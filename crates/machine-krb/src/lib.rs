//! Active Directory machine-account Kerberos plumbing for Linux clients.
//!
//! This crate keeps a **machine-account Kerberos ticket** fresh on an
//! AD-joined Linux device and answers "is this device *properly* joined?".
//! The motivating case is **compound authentication** (a.k.a. FAST armoring):
//! some KDC policies only issue a service ticket when the request is armored
//! with the *device's* machine ticket — so a client (an RDP session, a GSSAPI
//! LDAP bind, …) needs that machine ticket sitting in a cache, always valid.
//!
//! It deliberately shells out to the system MIT krb5 tools (absolute paths —
//! see [`Tools`]) instead of reimplementing Kerberos: the system `kinit`
//! already handles PKINIT, FAST and the distro's crypto policy correctly.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use machine_krb::{ArmorCache, MachineIdentity, Tools};
//!
//! let tools = Tools::default();
//! let id = MachineIdentity::discover(&tools, "/etc/krb5.keytab")?;
//! let gid = machine_krb::lookup_gid(&tools, "machine-krb")?;
//! machine_krb::prepare_dir(Path::new("/run/machine-krb"), Some(gid))?; // root:machine-krb 0750
//! let cache = ArmorCache::new("/run/machine-krb/armor.ccache");
//! let how = cache.ensure(&tools, &id)?; // Renewed (cheap) or Minted (keytab)
//! cache.set_access(gid)?;               // root:machine-krb 0640
//! println!("{}: {how:?}", id.principal);
//! # Ok::<(), machine_krb::Error>(())
//! ```
//!
//! Practically everything here needs root: minting and deep join checks read
//! `/etc/krb5.keytab`, and even renewing rewrites the cache file — which under
//! the `root:<group>` 0640/0750 layout above only root can do. Group members
//! *consume* the armor ticket; they don't maintain it. Only reading a cache
//! ([`ArmorCache::is_valid`]/[`ArmorCache::klist_text`]) and the shallow join
//! check work unprivileged.

mod ccache;
mod error;
mod exec;
mod identity;
mod join;

pub use ccache::{ArmorCache, Freshness, lookup_gid, prepare_dir};
pub use error::{Error, Result};
pub use exec::Tools;
pub use identity::MachineIdentity;
pub use join::{JoinStatus, check as check_join, verify_credential};
