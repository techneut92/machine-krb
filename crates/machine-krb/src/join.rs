use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::ccache::ArmorCache;
use crate::error::Result;
use crate::exec::{self, Tools};
use crate::identity::MachineIdentity;

/// Layered answer to "is this device properly joined to AD?".
///
/// Layers 1–3 each prove strictly more than the previous:
/// 1. `configured_realms` — realmd/SSSD *say* we're joined (`realm list`).
/// 2. `keytab_principal` — a machine credential exists (`klist -k`, root).
/// 3. `credential_valid` — the credential actually **works**: `kinit -k`
///    against a throwaway cache succeeded. This is the same proof
///    `adcli testjoin` performs, and it is the strongest client-side check
///    there is — an AD-side disabled/deleted computer object shows up here
///    as a failure, not before.
///
/// `sssd_status` is an *orthogonal, advisory* signal — SSSD's own
/// online/offline view. "Offline" usually just means the network/VPN is
/// down and neither proves nor disproves the join; "Online" implies the
/// machine credential currently works (SSSD binds LDAP with it).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct JoinStatus {
    pub configured_realms: Vec<String>,
    pub keytab_principal: Option<String>,
    /// Why layer 2 could not be checked (typically: not root).
    pub keytab_error: Option<String>,
    /// `Some(true|false)` only when a deep check ran.
    pub credential_valid: Option<bool>,
    pub credential_error: Option<String>,
    /// Raw `sssctl domain-status` output, when it ran successfully.
    pub sssd_status: Option<String>,
}

impl JoinStatus {
    /// realmd/SSSD configuration claims a join.
    pub fn is_configured(&self) -> bool {
        !self.configured_realms.is_empty()
    }

    /// The strongest verdict this report can support:
    /// deep-checked and the machine credential authenticated successfully.
    pub fn is_properly_joined(&self) -> bool {
        self.credential_valid == Some(true)
    }
}

/// Gather the join report. Never fails as a whole — each layer degrades into
/// its `*_error` field so callers always get a full picture.
///
/// `deep` performs the real credential test (`kinit -k` into a private
/// throwaway cache). It needs root (keytab) and a reachable KDC.
///
/// `realm` selects which machine principal to check on a multi-realm host
/// (case-insensitive); `None` uses the first principal in the keytab.
pub fn check(tools: &Tools, keytab: &Path, realm: Option<&str>, deep: bool) -> JoinStatus {
    let mut status = JoinStatus::default();

    // 1. configured?
    if let Ok(out) = exec::run_ok(&tools.realm, ["list", "--name-only"]) {
        status.configured_realms = out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
    }

    // 2. machine credential present?
    let discovered = match realm {
        Some(r) => MachineIdentity::discover_in_realm(tools, keytab, r),
        None => MachineIdentity::discover(tools, keytab),
    };
    let identity = match discovered {
        Ok(id) => {
            status.keytab_principal = Some(id.principal.clone());
            Some(id)
        }
        Err(e) => {
            status.keytab_error = Some(e.to_string());
            None
        }
    };

    // 3. credential actually valid? (deep — authenticates against the KDC)
    if deep {
        match identity {
            Some(ref id) => match verify_credential(tools, id) {
                Ok(()) => status.credential_valid = Some(true),
                Err(e) => {
                    status.credential_valid = Some(false);
                    status.credential_error = Some(e.to_string());
                }
            },
            None => {
                status.credential_error =
                    Some("skipped: machine credential not readable".to_string());
            }
        }
    }

    // 4. SSSD's own view (root only; silently absent otherwise).
    if let Some(realm) = status.configured_realms.first() {
        if let Ok(out) = exec::run_ok(&tools.sssctl, ["domain-status", "--", realm]) {
            let trimmed = out.trim();
            if !trimmed.is_empty() {
                status.sssd_status = Some(trimmed.to_string());
            }
        }
    }

    status
}

/// Prove the machine credential works: `kinit -k` into a private throwaway
/// cache, then destroy it. Equivalent to `adcli testjoin`.
///
/// The cache lives in a freshly-created private (0700) directory rather than
/// a predictable bare path in `/tmp` — `mkdir` fails on a pre-existing entry
/// (including an attacker's symlink), so root never writes a ticket through a
/// path someone else planted.
pub fn verify_credential(tools: &Tools, identity: &MachineIdentity) -> Result<()> {
    let dir = private_scratch_dir()?;
    let cache = ArmorCache::new(dir.join("verify.ccache"));
    let outcome = cache.mint(tools, identity);
    cache.destroy(tools);
    let _ = std::fs::remove_dir_all(&dir);
    outcome
}

fn private_scratch_dir() -> Result<PathBuf> {
    // Fixed /tmp on purpose (not std::env::temp_dir): TMPDIR is inherited from
    // the caller and could point a root check-join at a directory whose owner
    // can rename/replace entries. /tmp is guaranteed sticky (1777), and the
    // 0700 mkdir below fails on any pre-existing entry — including a planted
    // symlink — so root never writes a ticket through a path it didn't create.
    let base = Path::new("/tmp");
    let pid = std::process::id();
    for attempt in 0u32.. {
        let dir = base.join(format!("machine-krb-verify-{pid}-{attempt}"));
        match DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!("u32 attempt space exhausted");
}
