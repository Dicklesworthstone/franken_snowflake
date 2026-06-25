//! Portable directory resolution for local connector state.
//!
//! The policy mirrors `ProjectDirs`-style platform defaults without adding a
//! dependency to the production graph: explicit path wins, then an environment
//! override, then the native config/cache/state location for the current OS.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const APP_DIR: &str = "franken_snowflake";

/// Local directory category resolved by the connector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortableDirKind {
    /// Profile and CLI configuration.
    Config,
    /// Local cache metadata.
    Cache,
    /// Durable proof/e2e artifacts.
    Artifacts,
}

impl PortableDirKind {
    /// Environment override for this directory.
    #[must_use]
    pub const fn env_var(self) -> &'static str {
        match self {
            Self::Config => "FSNOW_CONFIG_DIR",
            Self::Cache => "FSNOW_CACHE_DIR",
            Self::Artifacts => "FSNOW_ARTIFACTS_DIR",
        }
    }

    fn leaf(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Cache => "cache",
            Self::Artifacts => "artifacts",
        }
    }
}

/// Resolve a connector directory with explicit > env > platform-default precedence.
#[must_use]
pub fn resolve_project_dir(kind: PortableDirKind, explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Some(path) = env::var_os(kind.env_var()) {
        return PathBuf::from(path);
    }
    platform_default(kind)
}

/// Resolve the config directory.
#[must_use]
pub fn config_dir(explicit: Option<&Path>) -> PathBuf {
    resolve_project_dir(PortableDirKind::Config, explicit)
}

/// Resolve the cache directory.
#[must_use]
pub fn cache_dir(explicit: Option<&Path>) -> PathBuf {
    resolve_project_dir(PortableDirKind::Cache, explicit)
}

/// Resolve the artifacts directory.
#[must_use]
pub fn artifacts_dir(explicit: Option<&Path>) -> PathBuf {
    resolve_project_dir(PortableDirKind::Artifacts, explicit)
}

fn platform_default(kind: PortableDirKind) -> PathBuf {
    platform_default_with(kind, |name| env::var_os(name))
}

fn platform_default_with<F>(kind: PortableDirKind, mut env_get: F) -> PathBuf
where
    F: FnMut(&str) -> Option<OsString>,
{
    #[cfg(target_os = "windows")]
    {
        let base_var = match kind {
            PortableDirKind::Config => "APPDATA",
            PortableDirKind::Cache | PortableDirKind::Artifacts => "LOCALAPPDATA",
        };
        if let Some(base) = env_get(base_var) {
            return PathBuf::from(base)
                .join("FrankenSuite")
                .join(APP_DIR)
                .join(kind.leaf());
        }
        if let Some(home) = env_get("USERPROFILE") {
            return PathBuf::from(home)
                .join("AppData")
                .join(if matches!(kind, PortableDirKind::Config) {
                    "Roaming"
                } else {
                    "Local"
                })
                .join("FrankenSuite")
                .join(APP_DIR)
                .join(kind.leaf());
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = env_get("HOME") {
            let base = PathBuf::from(home).join("Library").join(match kind {
                PortableDirKind::Config | PortableDirKind::Artifacts => "Application Support",
                PortableDirKind::Cache => "Caches",
            });
            return base.join(APP_DIR).join(kind.leaf());
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let override_var = match kind {
            PortableDirKind::Config => "XDG_CONFIG_HOME",
            PortableDirKind::Cache => "XDG_CACHE_HOME",
            PortableDirKind::Artifacts => "XDG_STATE_HOME",
        };
        if let Some(base) = env_get(override_var) {
            return PathBuf::from(base).join(APP_DIR).join(kind.leaf());
        }
        if let Some(home) = env_get("HOME") {
            let base = PathBuf::from(home).join(match kind {
                PortableDirKind::Config => ".config",
                PortableDirKind::Cache => ".cache",
                PortableDirKind::Artifacts => ".local/state",
            });
            return base.join(APP_DIR).join(kind.leaf());
        }
    }

    env::temp_dir().join(APP_DIR).join(kind.leaf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fake_env(entries: &[(&str, &str)]) -> impl FnMut(&str) -> Option<OsString> {
        let map = entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), OsString::from(value)))
            .collect::<BTreeMap<_, _>>();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn explicit_path_has_highest_precedence() {
        let explicit = Path::new("/explicit/fsnow");
        assert_eq!(
            resolve_project_dir(PortableDirKind::Config, Some(explicit)),
            explicit
        );
    }

    #[test]
    fn directory_kinds_expose_stable_env_overrides() {
        assert_eq!(PortableDirKind::Config.env_var(), "FSNOW_CONFIG_DIR");
        assert_eq!(PortableDirKind::Cache.env_var(), "FSNOW_CACHE_DIR");
        assert_eq!(PortableDirKind::Artifacts.env_var(), "FSNOW_ARTIFACTS_DIR");
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_defaults_follow_xdg_then_home() {
        let xdg = platform_default_with(
            PortableDirKind::Artifacts,
            fake_env(&[("XDG_STATE_HOME", "/xdg/state"), ("HOME", "/home/alice")]),
        );
        assert_eq!(
            xdg,
            PathBuf::from("/xdg/state").join(APP_DIR).join("artifacts")
        );

        let home =
            platform_default_with(PortableDirKind::Cache, fake_env(&[("HOME", "/home/alice")]));
        assert_eq!(
            home,
            PathBuf::from("/home/alice")
                .join(".cache")
                .join(APP_DIR)
                .join("cache")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_defaults_follow_library_locations() {
        let config =
            platform_default_with(PortableDirKind::Config, fake_env(&[("HOME", "/Users/a")]));
        assert_eq!(
            config,
            PathBuf::from("/Users/a")
                .join("Library")
                .join("Application Support")
                .join(APP_DIR)
                .join("config")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_defaults_follow_appdata_locations() {
        let config = platform_default_with(
            PortableDirKind::Config,
            fake_env(&[("APPDATA", r"C:\Users\a\AppData\Roaming")]),
        );
        assert_eq!(
            config,
            PathBuf::from(r"C:\Users\a\AppData\Roaming")
                .join("FrankenSuite")
                .join(APP_DIR)
                .join("config")
        );
    }
}
