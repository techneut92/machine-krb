use std::fs::File;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::exec::{self, Tools};

/// The machine's AD identity, discovered from its keytab.
///
/// The keytab is the ground truth for what this device can authenticate as —
/// more reliable than deriving `HOSTNAME$` from the hostname, which drifts
/// (renames, >15-char truncation, case).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MachineIdentity {
    /// e.g. `WORKSTATION1$@EXAMPLE.COM`
    pub principal: String,
    /// e.g. `EXAMPLE.COM`
    pub realm: String,
    pub keytab: PathBuf,
}

impl MachineIdentity {
    /// Read the keytab and pick the first machine (`NAME$@REALM`) principal.
    ///
    /// Needs read access to the keytab — i.e. root for `/etc/krb5.keytab`.
    /// On a host joined to multiple realms, use [`Self::discover_in_realm`] to
    /// choose which one.
    pub fn discover(tools: &Tools, keytab: impl Into<PathBuf>) -> Result<Self> {
        Self::pick(tools, keytab, None)
    }

    /// Like [`Self::discover`], but pick the machine principal whose realm
    /// matches `realm` (case-insensitive) — for hosts joined to more than one
    /// AD realm. Errors with [`Error::NoMachinePrincipalForRealm`] if none match.
    pub fn discover_in_realm(
        tools: &Tools,
        keytab: impl Into<PathBuf>,
        realm: &str,
    ) -> Result<Self> {
        Self::pick(tools, keytab, Some(realm))
    }

    fn pick(tools: &Tools, keytab: impl Into<PathBuf>, want_realm: Option<&str>) -> Result<Self> {
        let keytab = keytab.into();
        // Pre-check readability for a friendlier error than klist's.
        if let Err(source) = File::open(&keytab) {
            return Err(if source.kind() == std::io::ErrorKind::NotFound {
                Error::KeytabMissing { keytab }
            } else {
                Error::KeytabUnreadable { keytab, source }
            });
        }
        // "--" so a keytab path starting with '-' can't be misparsed as a flag.
        let listing = exec::run_ok(
            &tools.klist,
            ["-k".as_ref(), "--".as_ref(), keytab.as_os_str()],
        )?;
        let principals = parse_machine_principals(&listing);
        let principal = select_principal(&principals, want_realm)
            .cloned()
            .ok_or_else(|| match want_realm {
                Some(realm) => Error::NoMachinePrincipalForRealm {
                    realm: realm.to_string(),
                    keytab: keytab.clone(),
                },
                None => Error::NoMachinePrincipal {
                    keytab: keytab.clone(),
                },
            })?;
        let realm = principal
            .split_once('@')
            .map(|(_, r)| r.to_string())
            .unwrap_or_default();
        Ok(Self {
            principal,
            realm,
            keytab,
        })
    }
}

/// Choose a machine principal: the one whose realm matches `want_realm`
/// (case-insensitive), or the first one when `want_realm` is `None`.
pub(crate) fn select_principal<'a>(
    principals: &'a [String],
    want_realm: Option<&str>,
) -> Option<&'a String> {
    match want_realm {
        Some(realm) => principals.iter().find(|p| {
            p.rsplit_once('@')
                .is_some_and(|(_, r)| r.eq_ignore_ascii_case(realm))
        }),
        None => principals.first(),
    }
}

/// Extract machine (`NAME$@REALM`) principals from `klist -k` output,
/// first-seen order, deduplicated (keytabs repeat principals per enctype/kvno).
///
/// Service principals (`host/…`, `RestrictedKrbHost/…`) are skipped — only the
/// sAMAccountName form can `kinit -k` into a TGT usable as FAST armor.
pub(crate) fn parse_machine_principals(klist_k: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in klist_k.lines() {
        let mut fields = line.split_whitespace();
        let (Some(kvno), Some(principal)) = (fields.next(), fields.next()) else {
            continue;
        };
        // Data rows start with a numeric KVNO; headers/rules don't.
        if kvno.is_empty() || !kvno.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Some((name, realm)) = principal.split_once('@') else {
            continue;
        };
        // Reject a leading '-' outright: such a "principal" would later sit in
        // argv positions where a tool could misparse it as a flag. No real AD
        // sAMAccountName starts with '-'.
        if name.ends_with('$')
            && !name.starts_with('-')
            && !name.contains('/')
            && !realm.is_empty()
            && !found.iter().any(|p| p == principal)
        {
            found.push(principal.to_string());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::parse_machine_principals;

    const KLIST_K: &str = "\
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   2 WORKSTATION1$@EXAMPLE.COM
   2 WORKSTATION1$@EXAMPLE.COM
   2 host/WORKSTATION1@EXAMPLE.COM
   2 host/workstation1.example.com@EXAMPLE.COM
   2 RestrictedKrbHost/WORKSTATION1@EXAMPLE.COM
";

    #[test]
    fn picks_machine_principal_only_once() {
        let got = parse_machine_principals(KLIST_K);
        assert_eq!(got, vec!["WORKSTATION1$@EXAMPLE.COM".to_string()]);
    }

    #[test]
    fn empty_and_garbage_input() {
        assert!(parse_machine_principals("").is_empty());
        assert!(parse_machine_principals("no keytab entries here\n----\n").is_empty());
        // header word in KVNO column must not match
        assert!(parse_machine_principals("KVNO X$@R\n").is_empty());
    }

    #[test]
    fn skips_service_principals_with_dollar_realm() {
        // pathological: service principal whose instance ends in $
        let got = parse_machine_principals("   3 host/weird$@REALM\n   3 GOOD$@REALM\n");
        assert_eq!(got, vec!["GOOD$@REALM".to_string()]);
    }

    #[test]
    fn rejects_leading_dash_principals() {
        // a name that could be misparsed as a flag downstream is refused
        let got = parse_machine_principals("   2 -x$@REALM\n   2 OK$@REALM\n");
        assert_eq!(got, vec!["OK$@REALM".to_string()]);
    }

    #[test]
    fn selects_principal_by_realm() {
        let ps = vec!["WS1$@REALM.A".to_string(), "WS1$@REALM.B".to_string()];
        // no realm -> first
        assert_eq!(super::select_principal(&ps, None), Some(&ps[0]));
        // realm match is case-insensitive
        assert_eq!(super::select_principal(&ps, Some("realm.b")), Some(&ps[1]));
        // no match -> None
        assert_eq!(super::select_principal(&ps, Some("REALM.C")), None);
        assert_eq!(super::select_principal(&[], None), None);
    }
}
