//! Configuration: built-in defaults, overlaid by an optional YAML file,
//! overlaid by CLI flags (flags win). The library stays config-agnostic — this
//! layering lives entirely in the service binary.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/machine-krb/config.yaml";

const DEFAULT_KEYTAB: &str = "/etc/krb5.keytab";
const DEFAULT_CCACHE: &str = "/run/machine-krb/armor.ccache";
const DEFAULT_GROUP: &str = "machine-krb";
const DEFAULT_ATTEMPTS: u32 = 3;
const DEFAULT_BACKOFF_SECS: u64 = 10;
/// Consecutive transient-failure runs before the service escalates to a
/// permanent (visible) failure. ~half a day at the hourly cadence.
const DEFAULT_ESCALATE_AFTER: u32 = 12;

// Clamps: the whole retry budget must stay well under the systemd unit's
// TimeoutStartSec (3 min) or a run gets SIGTERM'd instead of exiting 75/78.
const MAX_ATTEMPTS: u32 = 10;
const MAX_BACKOFF_SECS: u64 = 60;
const MAX_ESCALATE_AFTER: u32 = 1000;

/// What the YAML file may contain — every field optional so an omitted key
/// falls through to the built-in default.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    keytab: Option<PathBuf>,
    ccache: Option<PathBuf>,
    group: Option<String>,
    realm: Option<String>,
    retry: Option<RetryFile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetryFile {
    attempts: Option<u32>,
    backoff_seconds: Option<u64>,
    escalate_after: Option<u32>,
}

/// Fully-resolved effective settings used by every command.
#[derive(Debug, Clone)]
pub struct Settings {
    pub keytab: PathBuf,
    pub ccache: PathBuf,
    pub group: String,
    /// Which realm's machine principal to use; `None` = first in the keytab.
    pub realm: Option<String>,
    pub attempts: u32,
    pub backoff: Duration,
    /// After this many *consecutive* transient-failure runs, report the
    /// failure as permanent (exit 78 → failed unit) so an outage can't hide
    /// behind "transient" forever. `0` disables escalation.
    pub escalate_after: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            keytab: DEFAULT_KEYTAB.into(),
            ccache: DEFAULT_CCACHE.into(),
            group: DEFAULT_GROUP.into(),
            realm: None,
            attempts: DEFAULT_ATTEMPTS,
            backoff: Duration::from_secs(DEFAULT_BACKOFF_SECS),
            escalate_after: DEFAULT_ESCALATE_AFTER,
        }
    }
}

impl Settings {
    /// Defaults overlaid by the YAML file at `path`, if it exists. A missing
    /// file is fine (defaults stand); a present-but-broken file is an error.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut settings = Settings::default();
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let file: FileConfig = serde_yaml_ng::from_str(&text)
                    .with_context(|| format!("parsing config {}", path.display()))?;
                settings.overlay(file);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("reading config {}", path.display()));
            }
        }
        Ok(settings)
    }

    fn overlay(&mut self, file: FileConfig) {
        if let Some(v) = file.keytab {
            self.keytab = v;
        }
        if let Some(v) = file.ccache {
            self.ccache = v;
        }
        if let Some(v) = file.group {
            self.group = v;
        }
        // An empty `realm:` means "unset" (use the first principal).
        self.realm = file.realm.filter(|r| !r.trim().is_empty());
        if let Some(r) = file.retry {
            if let Some(a) = r.attempts {
                self.attempts = a.clamp(1, MAX_ATTEMPTS);
            }
            if let Some(b) = r.backoff_seconds {
                self.backoff = Duration::from_secs(b.min(MAX_BACKOFF_SECS));
            }
            if let Some(n) = r.escalate_after {
                self.escalate_after = n.min(MAX_ESCALATE_AFTER);
            }
        }
    }

    /// Apply CLI overrides (each `Some` wins over the file/default value).
    pub fn apply_overrides(
        &mut self,
        keytab: Option<PathBuf>,
        ccache: Option<PathBuf>,
        group: Option<String>,
        realm: Option<String>,
    ) {
        if let Some(v) = keytab {
            self.keytab = v;
        }
        if let Some(v) = ccache {
            self.ccache = v;
        }
        if let Some(v) = group {
            self.group = v;
        }
        if let Some(v) = realm {
            self.realm = Some(v).filter(|r| !r.trim().is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_yaml_keeps_defaults() {
        let mut s = Settings::default();
        s.overlay(serde_yaml_ng::from_str("{}").unwrap());
        assert_eq!(s.keytab, PathBuf::from(DEFAULT_KEYTAB));
        assert_eq!(s.group, DEFAULT_GROUP);
        assert_eq!(s.attempts, DEFAULT_ATTEMPTS);
        assert!(s.realm.is_none());
    }

    #[test]
    fn yaml_overlays_selected_fields() {
        let yaml = "group: admins\nrealm: EXAMPLE.COM\nretry:\n  attempts: 5\n";
        let mut s = Settings::default();
        s.overlay(serde_yaml_ng::from_str(yaml).unwrap());
        assert_eq!(s.group, "admins");
        assert_eq!(s.realm.as_deref(), Some("EXAMPLE.COM"));
        assert_eq!(s.attempts, 5);
        assert_eq!(s.backoff, Duration::from_secs(DEFAULT_BACKOFF_SECS)); // untouched
        assert_eq!(s.ccache, PathBuf::from(DEFAULT_CCACHE)); // untouched
    }

    #[test]
    fn empty_realm_is_treated_as_unset() {
        let mut s = Settings::default();
        s.overlay(serde_yaml_ng::from_str("realm: '   '").unwrap());
        assert!(s.realm.is_none());
    }

    #[test]
    fn retry_values_are_clamped() {
        let mut s = Settings::default();
        s.overlay(serde_yaml_ng::from_str("retry:\n  attempts: 0").unwrap());
        assert_eq!(s.attempts, 1);
        s.overlay(
            serde_yaml_ng::from_str(
                "retry:\n  attempts: 99\n  backoff_seconds: 86400\n  escalate_after: 999999",
            )
            .unwrap(),
        );
        assert_eq!(s.attempts, MAX_ATTEMPTS);
        assert_eq!(s.backoff, Duration::from_secs(MAX_BACKOFF_SECS));
        assert_eq!(s.escalate_after, MAX_ESCALATE_AFTER);
    }

    #[test]
    fn escalate_after_zero_disables() {
        let mut s = Settings::default();
        assert_eq!(s.escalate_after, DEFAULT_ESCALATE_AFTER);
        s.overlay(serde_yaml_ng::from_str("retry:\n  escalate_after: 0").unwrap());
        assert_eq!(s.escalate_after, 0);
    }

    #[test]
    fn cli_overrides_win() {
        let mut s = Settings::default();
        s.overlay(serde_yaml_ng::from_str("group: fromfile").unwrap());
        s.apply_overrides(None, None, Some("fromflag".into()), None);
        assert_eq!(s.group, "fromflag");
    }

    #[test]
    fn unknown_key_is_rejected() {
        assert!(serde_yaml_ng::from_str::<FileConfig>("bogus: 1").is_err());
    }
}
