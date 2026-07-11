use std::io;
use std::path::PathBuf;

/// Errors produced by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The program could not be spawned at all (missing binary, permissions…).
    #[error("failed to run {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },

    /// The program ran but exited non-zero.
    #[error("{program} failed ({status}): {stderr}")]
    CommandFailed {
        program: String,
        status: String,
        stderr: String,
    },

    /// The program hung past the per-command cap and was killed. Typical
    /// cause: a half-up network where the KDC resolves but packets go
    /// nowhere, so kinit sits in its own retry cycle indefinitely.
    #[error("{program} timed out after {seconds}s and was killed")]
    Timeout { program: String, seconds: u64 },

    /// The keytab holds no `NAME$@REALM` (machine sAMAccountName) entry.
    #[error("no machine principal (NAME$@REALM) found in keytab {}", keytab.display())]
    NoMachinePrincipal { keytab: PathBuf },

    /// The keytab has machine principals, but none in the requested realm.
    #[error("no machine principal for realm {realm} in keytab {}", keytab.display())]
    NoMachinePrincipalForRealm { realm: String, keytab: PathBuf },

    /// The keytab exists but cannot be read — machine keytabs are root-only.
    /// (The io::Error is the source, not embedded here, so error chains
    /// don't print it twice.)
    #[error(
        "keytab {} is not readable \
         (machine keytabs are root-only — run as root, e.g. via the systemd service)",
        keytab.display()
    )]
    KeytabUnreadable {
        keytab: PathBuf,
        #[source]
        source: io::Error,
    },

    /// The keytab does not exist at all — most likely not AD-joined.
    #[error(
        "keytab {} not found — is this machine AD-joined? (realm join <domain>)",
        keytab.display()
    )]
    KeytabMissing { keytab: PathBuf },

    /// The group to share the ticket cache with does not exist.
    #[error("group '{0}' not found — create it (`groupadd -r {0}`) or pass a different group")]
    GroupNotFound(String),

    /// Renew and mint both ran, yet the cache still fails `klist -s`.
    #[error("ticket cache {} is still invalid after renew/mint", .0.display())]
    CacheStillInvalid(PathBuf),

    /// Refusing to take ownership of a shared system directory.
    #[error(
        "refusing to manage {}: not a dedicated absolute directory (shared system path, \
         relative, or contains '..')",
        .0.display()
    )]
    RefusingSharedDir(PathBuf),

    /// Refusing to operate through a symlink.
    #[error("refusing to operate on symlink {}", .0.display())]
    RefusingSymlink(PathBuf),

    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Whether retrying shortly might succeed (a network / KDC hiccup) versus a
    /// permanent setup or join problem that needs an operator to fix.
    ///
    /// Setup errors (missing/unreadable keytab, no matching principal, missing
    /// group, refused path, missing tool) are permanent. A `kinit`/`klist`
    /// failure is classified from the KDC's message: a stale/disabled/deleted
    /// machine account is permanent; unreachable-KDC / clock-skew / network is
    /// transient. Unknown states default to transient — a retry is cheap.
    pub fn is_transient(&self) -> bool {
        match self {
            Error::KeytabMissing { .. }
            | Error::KeytabUnreadable { .. }
            | Error::NoMachinePrincipal { .. }
            | Error::NoMachinePrincipalForRealm { .. }
            | Error::GroupNotFound(_)
            | Error::RefusingSharedDir(_)
            | Error::RefusingSymlink(_)
            | Error::Spawn { .. } => false,
            Error::CommandFailed { stderr, .. } => krb_error_is_transient(stderr),
            // A hung tool is a network condition (half-up VPN), not a setup
            // problem — retry once connectivity settles.
            Error::Timeout { .. } => true,
            Error::CacheStillInvalid(_) => true,
            // A permission / read-only-filesystem failure won't heal on retry
            // (SELinux denial, wrong mount, sandbox misconfiguration); other
            // io errors get the benefit of the doubt. (EROFS via raw errno —
            // ErrorKind::ReadOnlyFilesystem is still unstable.)
            Error::Io(e) => {
                e.kind() != io::ErrorKind::PermissionDenied && e.raw_os_error() != Some(libc::EROFS)
            }
        }
    }
}

/// Does this krb5 CLI error text describe a *transient* condition (retry may
/// help) rather than a permanent auth/database failure?
///
/// NOTE this is deliberately a *blocklist of known-permanent markers*: an
/// unknown error retries (cheap, hourly). The service layer adds an
/// escalation valve on top — N consecutive transient failures get reported
/// as permanent — so anything this list misses still surfaces eventually.
fn krb_error_is_transient(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    // Permanent: the machine account is stale, disabled, expired, or gone, or
    // the keytab no longer matches the KDC — a keytab refresh / re-join is
    // required, retrying won't help. (Matched against LC_ALL=C output.)
    const PERMANENT: &[&str] = &[
        "preauthentication failed",
        "client not found",
        "credentials have been revoked",
        "not found in kerberos database",
        "decrypt integrity check failed",
        "keytab entry not found",
        "no key table entry found",
        "entry in database has expired",  // KRB5KDC_ERR_NAME_EXP
        "no support for encryption type", // KRB5KDC_ERR_ETYPE_NOSUPP (stale keytab etypes)
        "client not yet valid",           // KRB5KDC_ERR_CLIENT_NOTYET
    ];
    // "KDC policy rejects request" is intentionally NOT here: it can be
    // time-based (logon hours) and therefore transient.
    !PERMANENT.iter().any(|m| s.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_setup_errors_as_permanent() {
        assert!(
            !Error::KeytabMissing {
                keytab: "/x".into()
            }
            .is_transient()
        );
        assert!(
            !Error::NoMachinePrincipalForRealm {
                realm: "R".into(),
                keytab: "/x".into()
            }
            .is_transient()
        );
        assert!(!Error::GroupNotFound("g".into()).is_transient());
    }

    fn kinit_err(stderr: &str) -> Error {
        Error::CommandFailed {
            program: "kinit".into(),
            status: "exit 1".into(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn classifies_kdc_errors() {
        for permanent in [
            "kinit: Client's credentials have been revoked while getting initial credentials",
            "kinit: Client's entry in database has expired while getting initial credentials",
            "kinit: KDC has no support for encryption type while getting initial credentials",
            "kinit: Client not yet valid - try again later while getting initial credentials",
            "kinit: Preauthentication failed while getting initial credentials",
        ] {
            assert!(!kinit_err(permanent).is_transient(), "{permanent}");
        }
        for transient in [
            "kinit: Cannot contact any KDC for realm 'EXAMPLE.COM'",
            "kinit: KDC policy rejects request while getting initial credentials", // may be logon hours
            "kinit: Clock skew too great while getting initial credentials",
        ] {
            assert!(kinit_err(transient).is_transient(), "{transient}");
        }
    }

    #[test]
    fn classifies_io_by_kind() {
        let denied = Error::Io(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(!denied.is_transient());
        let rofs = Error::Io(io::Error::from_raw_os_error(libc::EROFS));
        assert!(!rofs.is_transient());
        let other = Error::Io(io::Error::from(io::ErrorKind::Interrupted));
        assert!(other.is_transient());
    }
}
