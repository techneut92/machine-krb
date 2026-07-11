//! machine-krb-service — keep the AD machine-account Kerberos ticket fresh.
//!
//! Thin service wrapper around the [`machine_krb`] library. Designed to run as
//! a root systemd oneshot on a timer (`systemd/` in this repo), so the machine
//! ticket that FAST armoring / compound authentication needs is always warm —
//! no sudo prompt, no freshly-minted-ticket settle race when a consumer (an
//! RDP client, an LDAP bind, any GSSAPI service) reaches for it.
//!
//! Settings come from built-in defaults, overlaid by an optional YAML config
//! (`/etc/machine-krb/config.yaml`), overlaid by CLI flags — see [`config`].

mod config;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use machine_krb::{ArmorCache, Freshness, MachineIdentity, Tools};

use config::{DEFAULT_CONFIG_PATH, Settings};

/// EX_TEMPFAIL — a transient failure (off VPN / KDC unreachable). The systemd
/// timer will retry; `SuccessExitStatus=75` keeps the unit out of "failed".
const EXIT_TRANSIENT: u8 = 75;
/// EX_CONFIG — a permanent failure (not joined / credential revoked / bad
/// config). An operator has to fix something.
const EXIT_PERMANENT: u8 = 78;

#[derive(Parser)]
#[command(name = "machine-krb-service", version, about, long_about = None)]
struct Cli {
    /// Config file (YAML); a missing file just means built-in defaults
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Override: machine keytab
    #[arg(long, global = true)]
    keytab: Option<PathBuf>,
    /// Override: armor ticket cache
    #[arg(long, global = true)]
    ccache: Option<PathBuf>,
    /// Override: group allowed to read the cache
    #[arg(long, global = true)]
    group: Option<String>,
    /// Override: realm to use on a host joined to more than one
    #[arg(long, global = true)]
    realm: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Renew the ticket, or mint a new one from the keytab (root).
    /// This is the systemd-timer entrypoint.
    Run {
        /// Leave ownership/permissions alone (cache stays root-only)
        #[arg(long)]
        no_chown: bool,
    },
    /// Show the ticket's state.
    Status {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Check whether this device is (properly) AD-joined.
    CheckJoin {
        /// Also prove the machine credential against the KDC (root)
        #[arg(long)]
        deep: bool,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let config_path = cli.config.unwrap_or_else(|| DEFAULT_CONFIG_PATH.into());
    let mut settings = match Settings::load(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::from(EXIT_PERMANENT);
        }
    };
    settings.apply_overrides(cli.keytab, cli.ccache, cli.group, cli.realm);

    let tools = Tools::default();
    match cli.cmd {
        Cmd::Run { no_chown } => cmd_run(&tools, &settings, no_chown),
        Cmd::Status { json } => cmd_status(&tools, &settings, json),
        Cmd::CheckJoin { deep, json } => cmd_check_join(&tools, &settings, deep, json),
    }
}

/// Discover the machine identity, honoring the configured realm.
fn discover(tools: &Tools, settings: &Settings) -> machine_krb::Result<MachineIdentity> {
    match &settings.realm {
        Some(r) => MachineIdentity::discover_in_realm(tools, &settings.keytab, r),
        None => MachineIdentity::discover(tools, &settings.keytab),
    }
}

/// sd-daemon journal priority prefix — systemd parses a leading `<N>` on
/// stderr lines into the journal PRIORITY field, so monitoring can key off
/// err/warning-level entries even while `SuccessExitStatus=75` keeps the unit
/// green. Suppressed on a TTY (interactive runs shouldn't see the markers).
fn prio(level: &'static str) -> &'static str {
    if std::io::stderr().is_terminal() {
        ""
    } else {
        level
    }
}

/// Consecutive-transient-failure counter, kept next to the cache (tmpfs, so
/// it naturally resets at boot). All I/O is best-effort: bookkeeping problems
/// must never take the service down, and the 0750 `root:<group>` directory
/// means nothing unprivileged can tamper with the file.
fn counter_path(settings: &Settings) -> Option<PathBuf> {
    settings
        .ccache
        .parent()
        .map(|d| d.join(".transient-failures"))
}

fn bump_transient_counter(settings: &Settings) -> u32 {
    let Some(path) = counter_path(settings) else {
        return 1;
    };
    let n = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
        .unwrap_or(0)
        .saturating_add(1);
    let _ = std::fs::write(&path, n.to_string());
    n
}

fn clear_transient_counter(settings: &Settings) {
    if let Some(path) = counter_path(settings) {
        let _ = std::fs::remove_file(path);
    }
}

/// Print a `run` failure and map it to an exit code. Permanent errors exit 78
/// immediately. Transient errors exit 75 (the timer retries) — but only up to
/// `escalate_after` consecutive runs: past that the failure is reported as
/// permanent, so a real outage can't hide behind "transient" forever.
fn fail(settings: &Settings, context: &str, err: &machine_krb::Error) -> ExitCode {
    if !err.is_transient() {
        eprintln!("{}error: {context}: {err}", prio("<3>"));
        return ExitCode::from(EXIT_PERMANENT);
    }
    let n = bump_transient_counter(settings);
    if settings.escalate_after > 0 && n >= settings.escalate_after {
        eprintln!(
            "{}error: {context}: {err} — {n} consecutive transient failures; escalating to a \
             permanent failure so the outage is visible (check connectivity, or run \
             `check-join --deep` as root)",
            prio("<3>")
        );
        return ExitCode::from(EXIT_PERMANENT);
    }
    eprintln!(
        "{}error (transient, {n} consecutive): {context}: {err}",
        prio("<4>")
    );
    ExitCode::from(EXIT_TRANSIENT)
}

fn cmd_run(tools: &Tools, settings: &Settings, no_chown: bool) -> ExitCode {
    let id = match discover(tools, settings) {
        Ok(id) => id,
        Err(e) => return fail(settings, "cannot determine machine identity", &e),
    };

    // Resolve the group and (re)assert ownership of the cache directory. Doing
    // this every run means switching `group:` in the config + restarting the
    // service migrates the directory (and, below, the cache) to the new group.
    let gid = if no_chown {
        None
    } else {
        match machine_krb::lookup_gid(tools, &settings.group) {
            Ok(g) => Some(g),
            Err(e) => return fail(settings, &format!("group '{}'", settings.group), &e),
        }
    };
    if let Some(dir) = settings.ccache.parent() {
        if let Err(e) = machine_krb::prepare_dir(dir, gid) {
            return fail(settings, &format!("preparing {}", dir.display()), &e);
        }
    }

    let cache = ArmorCache::new(&settings.ccache);

    // A reboot or an over-eager tmpfiles/systemd pass may have reset the
    // cache's ownership. If a cache already exists (possibly still valid),
    // restore group access BEFORE the network round-trip — so consumers
    // aren't locked out of a good ticket while we refresh, or while we sit
    // in transient failures off-VPN.
    if let Some(gid) = gid {
        if std::fs::symlink_metadata(&settings.ccache).is_ok() {
            if let Err(e) = cache.set_access(gid) {
                return fail(settings, "restoring cache access", &e);
            }
        }
    }

    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match cache.ensure(tools, &id) {
            Ok(freshness) => {
                if let Some(gid) = gid {
                    if let Err(e) = cache.set_access(gid) {
                        return fail(settings, "restricting cache access", &e);
                    }
                }
                report_success(tools, &id, &cache, freshness);
                clear_transient_counter(settings);
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                if e.is_transient() && attempt < settings.attempts {
                    eprintln!(
                        "{}attempt {attempt}/{} failed (transient): {e} — retrying in {}s",
                        prio("<4>"),
                        settings.attempts,
                        settings.backoff.as_secs()
                    );
                    std::thread::sleep(settings.backoff);
                    continue;
                }
                return fail(settings, "could not refresh the machine ticket", &e);
            }
        }
    }
}

fn report_success(tools: &Tools, id: &MachineIdentity, cache: &ArmorCache, how: Freshness) {
    match how {
        Freshness::Renewed => println!("renewed: {} ({})", id.principal, cache.cache_name()),
        Freshness::Minted => println!(
            "minted: {} ({}) — a fresh machine ticket can take a few seconds \
             to settle for compound auth",
            id.principal,
            cache.cache_name()
        ),
    }
    if let Ok(text) = cache.klist_text(tools) {
        for line in text
            .lines()
            .filter(|l| l.contains("Default principal") || l.contains("krbtgt/"))
        {
            println!("  {}", line.trim());
        }
    }
}

fn cmd_status(tools: &Tools, settings: &Settings, json: bool) -> ExitCode {
    let cache = ArmorCache::new(&settings.ccache);
    let valid = cache.is_valid(tools);
    let text = cache.klist_text(tools).ok();
    let principal = text.as_deref().and_then(parse_default_principal);
    if json {
        let doc = serde_json::json!({
            "ccache": cache.path(),
            "valid": valid,
            "principal": principal,
            "klist": text,
        });
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(EXIT_PERMANENT);
            }
        }
    } else {
        println!("cache:  {}", cache.cache_name());
        println!("valid:  {}", if valid { "yes" } else { "no" });
        match text {
            Some(t) => print!("{t}"),
            None => println!("(no readable cache)"),
        }
    }
    if valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_check_join(tools: &Tools, settings: &Settings, deep: bool, json: bool) -> ExitCode {
    let status = machine_krb::check_join(tools, &settings.keytab, settings.realm.as_deref(), deep);
    if json {
        match serde_json::to_string_pretty(&status) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(EXIT_PERMANENT);
            }
        }
    } else {
        println!(
            "configured realm(s): {}",
            if status.configured_realms.is_empty() {
                "none — device is not AD-joined".to_string()
            } else {
                status.configured_realms.join(", ")
            }
        );
        match (&status.keytab_principal, &status.keytab_error) {
            (Some(p), _) => println!("machine principal:   {p}"),
            (None, Some(e)) => println!("machine principal:   unavailable — {e}"),
            (None, None) => println!("machine principal:   unavailable"),
        }
        match status.credential_valid {
            Some(true) => {
                println!(
                    "credential check:    OK — machine credential authenticated against the KDC"
                )
            }
            Some(false) => println!(
                "credential check:    FAILED — {}",
                status.credential_error.as_deref().unwrap_or("unknown")
            ),
            None => println!("credential check:    not run (use --deep, as root)"),
        }
        if let Some(s) = &status.sssd_status {
            println!(
                "sssd:                {}",
                s.replace('\n', "\n                     ")
            );
        }
        let verdict = if status.is_properly_joined() {
            "properly joined (credential proven)"
        } else if deep && status.credential_valid == Some(false) {
            "BROKEN join — configured, but the machine credential does not work"
        } else if status.is_configured() {
            "configured (run --deep as root to prove the credential)"
        } else {
            "not joined"
        };
        println!("verdict:             {verdict}");
    }
    let ok = if deep {
        status.is_properly_joined()
    } else {
        status.is_configured()
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Pull `Default principal: X` out of raw `klist` output.
fn parse_default_principal(klist: &str) -> Option<String> {
    klist
        .lines()
        .find_map(|l| l.trim().strip_prefix("Default principal:"))
        .map(|p| p.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_parses() {
        let text = "Ticket cache: FILE:/run/machine-krb/armor.ccache\n\
                    Default principal: WORKSTATION1$@EXAMPLE.COM\n";
        assert_eq!(
            parse_default_principal(text).as_deref(),
            Some("WORKSTATION1$@EXAMPLE.COM")
        );
        assert_eq!(parse_default_principal(""), None);
    }

    #[test]
    fn transient_counter_round_trip() {
        let dir = std::env::temp_dir().join(format!("mks-counter-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let settings = Settings {
            ccache: dir.join("armor.ccache"),
            ..Settings::default()
        };

        assert_eq!(bump_transient_counter(&settings), 1);
        assert_eq!(bump_transient_counter(&settings), 2);
        assert_eq!(bump_transient_counter(&settings), 3);
        clear_transient_counter(&settings);
        assert_eq!(bump_transient_counter(&settings), 1); // reset after success

        // corrupt counter degrades to a fresh count, never a panic
        std::fs::write(counter_path(&settings).unwrap(), "garbage").unwrap();
        assert_eq!(bump_transient_counter(&settings), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
