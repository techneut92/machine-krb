use std::fs::{self, DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};
use crate::exec::{self, Tools};
use crate::identity::MachineIdentity;

/// How `ensure` obtained a valid ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Freshness {
    /// Existing ticket renewed in place (`kinit -R`) — same established
    /// ticket, no fresh authentication against the KDC.
    Renewed,
    /// Brand-new ticket minted from the keytab (`kinit -k`). Note: a fresh
    /// machine ticket can take a few seconds to "settle" before the KDC
    /// honours it as FAST armor for compound authentication.
    Minted,
}

/// A `FILE:` credential cache holding the machine (armor) ticket.
#[derive(Debug, Clone)]
pub struct ArmorCache {
    path: PathBuf,
}

impl ArmorCache {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The `FILE:<path>` form kinit/klist/kdestroy expect.
    pub fn cache_name(&self) -> String {
        format!("FILE:{}", self.path.display())
    }

    /// Does the cache exist and hold a non-expired ticket? (`klist -s`)
    pub fn is_valid(&self, tools: &Tools) -> bool {
        exec::succeeds(&tools.klist, ["-s", &self.cache_name()])
    }

    /// Renew the existing ticket in place (`kinit -R`).
    ///
    /// No keytab and no fresh authentication needed. Renewal only works while
    /// the current ticket is still **unexpired** (AD machine tickets live
    /// ~10 h); the ~7-day renewable lifetime is the outer bound reachable via
    /// *repeated pre-expiry renewals*, not a grace period after expiry — an
    /// expired ticket always needs [`Self::mint`]. Use [`Self::ensure`] to get
    /// the fallback automatically.
    ///
    /// The expected principal is passed explicitly, so a cache that somehow
    /// holds a *different* principal fails here ("Matching credential not
    /// found") instead of being silently renewed as the wrong identity.
    pub fn renew(&self, tools: &Tools, identity: &MachineIdentity) -> Result<()> {
        // "--" ends option parsing so the positional principal can never be
        // misparsed as a flag (defense-in-depth; principals are validated too).
        exec::run_ok(
            &tools.kinit,
            ["-R", "-c", &self.cache_name(), "--", &identity.principal],
        )
        .map(drop)
    }

    /// Mint a brand-new ticket from the machine keytab (`kinit -k`).
    /// Needs read access to the keytab — root, in practice.
    pub fn mint(&self, tools: &Tools, identity: &MachineIdentity) -> Result<()> {
        exec::run_ok(
            &tools.kinit,
            [
                "-k".as_ref(),
                "-t".as_ref(),
                identity.keytab.as_os_str(),
                "-c".as_ref(),
                self.cache_name().as_ref(),
                "--".as_ref(), // end of options — see renew()
                identity.principal.as_ref(),
            ],
        )
        .map(drop)
    }

    /// Make sure the cache holds a valid ticket **for this identity**: renew
    /// if possible (cheapest, keeps the same established ticket), mint from
    /// the keytab otherwise. The result is verified with `klist -s` before
    /// returning. A cache holding a foreign principal fails the renew and is
    /// overwritten by the mint — the cache self-heals.
    pub fn ensure(&self, tools: &Tools, identity: &MachineIdentity) -> Result<Freshness> {
        if self.renew(tools, identity).is_ok() && self.is_valid(tools) {
            return Ok(Freshness::Renewed);
        }
        self.mint(tools, identity)?;
        if self.is_valid(tools) {
            Ok(Freshness::Minted)
        } else {
            Err(Error::CacheStillInvalid(self.path.clone()))
        }
    }

    /// Restrict the cache to `root:<gid>` 0640 so group members (and only
    /// they) can use the armor ticket. kinit re-creates the file 0600 on
    /// every renew/mint, so call this after `ensure`.
    ///
    /// Only the group is changed (owner stays whoever kinit ran as), so this
    /// works under a minimal capability set (`CAP_CHOWN`). Race-free against
    /// symlink swaps: the file is opened with `O_NOFOLLOW` and the ownership/
    /// mode changes are applied through the file descriptor (`fchown`/
    /// `fchmod`), so there is no check-to-use window on the path.
    pub fn set_access(&self, gid: u32) -> Result<()> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|e| {
                // O_NOFOLLOW on a symlink -> ELOOP (ErrorKind::FilesystemLoop
                // is still unstable, so match the raw errno).
                if e.raw_os_error() == Some(libc::ELOOP) {
                    Error::RefusingSymlink(self.path.clone())
                } else {
                    e.into()
                }
            })?;
        std::os::unix::fs::fchown(&file, None, Some(gid))?;
        file.set_permissions(Permissions::from_mode(0o640))?;
        Ok(())
    }

    /// Raw `klist` text for status display (LC_ALL=C, so stable format).
    pub fn klist_text(&self, tools: &Tools) -> Result<String> {
        exec::run_ok(&tools.klist, [self.cache_name()])
    }

    /// Destroy the cache (best effort; missing cache is fine).
    pub fn destroy(&self, tools: &Tools) {
        let _ = exec::run(&tools.kdestroy, ["-c", &self.cache_name()]);
        let _ = fs::remove_file(&self.path);
    }
}

/// Create `dir` (if needed) 0750 so group members can reach the ticket cache
/// inside; with `Some(gid)`, hand the directory to that group. This must only
/// ever manage a **dedicated** directory like `/run/machine-krb`, so it refuses:
/// relative paths, paths containing `..`, a symlink where the directory
/// should be, and (post-canonicalization) well-known shared directories.
pub fn prepare_dir(dir: &Path, gid: Option<u32>) -> Result<()> {
    if !dir.is_absolute()
        || dir.components().any(|c| c == Component::ParentDir)
        || is_shared_dir(dir)
    {
        return Err(Error::RefusingSharedDir(dir.to_path_buf()));
    }
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(Error::RefusingSymlink(dir.to_path_buf()));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new().recursive(true).mode(0o750).create(dir)?;
        }
        Err(e) => return Err(e.into()),
    }
    // Canonicalize (resolves intermediate symlinks like /var/run or, on
    // ostree, /usr/local) before deciding whether this is a shared dir.
    let real = fs::canonicalize(dir)?;
    if is_shared_dir(&real) {
        return Err(Error::RefusingSharedDir(dir.to_path_buf()));
    }
    if let Some(gid) = gid {
        std::os::unix::fs::chown(&real, None, Some(gid))?;
    }
    fs::set_permissions(&real, Permissions::from_mode(0o750))?;
    Ok(())
}

/// Directories that must never have their ownership/mode taken over.
fn is_shared_dir(canonical: &Path) -> bool {
    const SHARED: &[&str] = &[
        "/",
        "/run",
        "/var/run",
        "/run/user",
        "/tmp",
        "/var/tmp",
        "/var",
        "/etc",
        "/home",
        "/root",
        "/usr",
        "/usr/local",
        "/usr/local/bin",
        "/var/usrlocal",
        "/var/lib",
        "/opt",
        "/srv",
        "/boot",
        "/dev",
        "/dev/shm",
    ];
    // Anything that shallow (e.g. /run, /var/lib) is by definition not a
    // dedicated leaf dir; the explicit list catches the named ones.
    SHARED.iter().any(|s| Path::new(s) == canonical)
}

/// Resolve a group name to its gid via `getent group` (covers local files
/// and SSSD/NSS-provided groups alike).
pub fn lookup_gid(tools: &Tools, group: &str) -> Result<u32> {
    // "--" so a group name starting with '-' can't be misparsed as a flag.
    let line = exec::run(&tools.getent, ["--", "group", group])?;
    if !line.status.success() {
        return Err(Error::GroupNotFound(group.to_string()));
    }
    parse_getent_gid(&String::from_utf8_lossy(&line.stdout))
        .ok_or_else(|| Error::GroupNotFound(group.to_string()))
}

/// Parse the gid out of a `getent group` line: `name:x:GID:members`.
pub(crate) fn parse_getent_gid(line: &str) -> Option<u32> {
    line.trim().split(':').nth(2)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getent_gid_parses() {
        assert_eq!(parse_getent_gid("machine-krb:x:973:dylan\n"), Some(973));
        assert_eq!(parse_getent_gid("wheel:x:10:"), Some(10));
        assert_eq!(parse_getent_gid(""), None);
        assert_eq!(parse_getent_gid("garbage"), None);
        assert_eq!(parse_getent_gid("a:b"), None);
    }

    #[test]
    fn prepare_dir_refuses_shared_dirs() {
        for d in ["/run", "/tmp", "/", "/var", "/etc", "/usr/local"] {
            assert!(matches!(
                prepare_dir(Path::new(d), None),
                Err(Error::RefusingSharedDir(_))
            ));
        }
    }

    #[test]
    fn prepare_dir_refuses_dotdot_and_relative() {
        for d in [
            "/run/machine-krb/..",
            "/run/../run",
            "run/machine-krb",
            "../x",
        ] {
            assert!(matches!(
                prepare_dir(Path::new(d), None),
                Err(Error::RefusingSharedDir(_))
            ));
        }
    }

    #[test]
    fn shared_dir_list_hits_canonical_forms() {
        for d in ["/var/usrlocal", "/run/user", "/var/lib", "/opt"] {
            assert!(is_shared_dir(Path::new(d)));
        }
        assert!(!is_shared_dir(Path::new("/run/machine-krb")));
    }

    #[test]
    fn cache_name_is_file_prefixed() {
        let c = ArmorCache::new("/run/machine-krb/armor.ccache");
        assert_eq!(c.cache_name(), "FILE:/run/machine-krb/armor.ccache");
    }
}
