use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Hard cap on any single spawned tool. Observed in the field: on a half-up
/// network (VPN tunnel dead but its DNS still configured) kinit resolves the
/// KDCs and then hangs in its own per-KDC retry cycle for minutes — long
/// enough to blow through the systemd unit's start timeout and get SIGTERM'd,
/// which bypasses the transient/permanent exit-code contract entirely. A
/// killed-after-30s kinit instead surfaces as a *transient* error and follows
/// the normal retry/escalation path.
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// Absolute paths to the system Kerberos / AD tooling.
///
/// The defaults are absolute **on purpose**: resolving these through `PATH`
/// is how you end up running Homebrew's `kinit`, which lacks the PKINIT
/// plugin and behaves subtly differently from the system MIT krb5. Every
/// field can be overridden for non-standard layouts.
#[derive(Debug, Clone)]
pub struct Tools {
    pub kinit: PathBuf,
    pub klist: PathBuf,
    pub kdestroy: PathBuf,
    pub realm: PathBuf,
    pub sssctl: PathBuf,
    pub getent: PathBuf,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            kinit: "/usr/bin/kinit".into(),
            klist: "/usr/bin/klist".into(),
            kdestroy: "/usr/bin/kdestroy".into(),
            realm: "/usr/bin/realm".into(),
            sssctl: "/usr/bin/sssctl".into(),
            getent: "/usr/bin/getent".into(),
        }
    }
}

/// Kerberos environment variables that could redirect the spawned tools to a
/// different config, keytab, or cache than the ones passed explicitly. The
/// shipped systemd unit starts env-clean anyway, but this crate is meant for
/// reuse in arbitrary root contexts — so scrub them always.
const SCRUBBED_ENV: &[&str] = &[
    "KRB5_CONFIG",
    "KRB5CCNAME",
    "KRB5_KTNAME",
    "KRB5_CLIENT_KTNAME",
    "KRB5_TRACE",
    "KRB5RCACHEDIR",
    "KRB5RCACHETYPE",
];

/// Run `program` and capture its output; error if it cannot be spawned or if
/// it exceeds [`CHILD_TIMEOUT`] (killed, reported as [`Error::Timeout`]).
pub(crate) fn run<I, S>(program: &Path, args: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_with_timeout(program, args, CHILD_TIMEOUT)
}

fn run_with_timeout<I, S>(program: &Path, args: I, timeout: Duration) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let name = || program.display().to_string();
    // LC_ALL=C so output parsing is locale-independent (klist prints
    // localized dates and headers otherwise).
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
    let mut child = cmd.spawn().map_err(|source| Error::Spawn {
        program: name(),
        source,
    })?;

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait(); // reap — no zombies
                return Err(Error::Timeout {
                    program: name(),
                    seconds: timeout.as_secs(),
                });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Spawn {
                    program: name(),
                    source,
                });
            }
        }
    };

    // Post-exit pipe drain is safe here: these tools emit far less than the
    // kernel pipe buffer (64 KiB), so they can never block on a full pipe.
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_end(&mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_end(&mut stderr);
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Run `program`; return stdout on success, a `CommandFailed` error otherwise.
pub(crate) fn run_ok<I, S>(program: &Path, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let out = run(program, args)?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(Error::CommandFailed {
            program: program.display().to_string(),
            status: out
                .status
                .code()
                .map_or_else(|| "killed by signal".to_string(), |c| format!("exit {c}")),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        })
    }
}

/// Run `program`; true iff it exited 0. Spawn failures count as false.
pub(crate) fn succeeds<I, S>(program: &Path, args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run(program, args)
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hung_child_is_killed_and_reported() {
        let started = Instant::now();
        let err = run_with_timeout(
            Path::new("/usr/bin/sleep"),
            ["30"],
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Timeout { .. }), "{err}");
        // killed promptly, not after the child's own 30s
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn fast_child_completes_with_output() {
        let out = run_with_timeout(
            Path::new("/usr/bin/echo"),
            ["hello"],
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
    }
}
