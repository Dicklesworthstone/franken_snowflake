//! Platform data-directory resolution for the local store.
//!
//! Precedence, per the plan's cross-platform rules: explicit env override >
//! platform default. Never a hard-coded Unix path.
//!
//! - `FRANKEN_SNOWFLAKE_DATA_DIR` (any platform) wins when set and non-empty.
//! - Linux/other Unix: `$XDG_DATA_HOME/franken-snowflake`, else
//!   `$HOME/.local/share/franken-snowflake`.
//! - macOS: `$HOME/Library/Application Support/franken-snowflake`.
//! - Windows: `%APPDATA%\franken-snowflake`.

use std::env;
use std::path::PathBuf;

/// Environment variable that overrides the data directory on every platform.
pub const DATA_DIR_ENV: &str = "FRANKEN_SNOWFLAKE_DATA_DIR";

/// Leaf directory name under the platform data root.
pub const DATA_DIR_LEAF: &str = "franken-snowflake";

/// Operating-system family used by the pure resolver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataDirOs {
    /// Linux and other Unix-likes (XDG rules).
    Unix,
    /// macOS (`Library/Application Support`).
    MacOs,
    /// Windows (`%APPDATA%`).
    Windows,
}

impl DataDirOs {
    /// The family this binary was compiled for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Unix
        }
    }
}

/// Inputs to the pure resolver, read from the process environment by
/// [`default_data_dir`] and supplied directly by tests (the workspace forbids
/// mutating the process environment in tests under edition 2024).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataDirEnv {
    /// `FRANKEN_SNOWFLAKE_DATA_DIR`.
    pub override_dir: Option<String>,
    /// `XDG_DATA_HOME`.
    pub xdg_data_home: Option<String>,
    /// `HOME`.
    pub home: Option<String>,
    /// `APPDATA`.
    pub appdata: Option<String>,
}

impl DataDirEnv {
    /// Snapshot the relevant process environment variables.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            override_dir: non_empty(env::var(DATA_DIR_ENV).ok()),
            xdg_data_home: non_empty(env::var("XDG_DATA_HOME").ok()),
            home: non_empty(env::var("HOME").ok()),
            appdata: non_empty(env::var("APPDATA").ok()),
        }
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

/// Pure resolution policy behind [`default_data_dir`].
#[must_use]
pub fn resolve_data_dir(env: &DataDirEnv, os: DataDirOs) -> Option<PathBuf> {
    if let Some(explicit) = &env.override_dir {
        return Some(PathBuf::from(explicit));
    }
    match os {
        DataDirOs::Windows => env
            .appdata
            .as_ref()
            .map(|appdata| PathBuf::from(appdata).join(DATA_DIR_LEAF)),
        DataDirOs::MacOs => env.home.as_ref().map(|home| {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join(DATA_DIR_LEAF)
        }),
        DataDirOs::Unix => env
            .xdg_data_home
            .as_ref()
            .map(|xdg| PathBuf::from(xdg).join(DATA_DIR_LEAF))
            .or_else(|| {
                env.home.as_ref().map(|home| {
                    PathBuf::from(home)
                        .join(".local")
                        .join("share")
                        .join(DATA_DIR_LEAF)
                })
            }),
    }
}

/// The data directory for this process, or `None` when no platform root can be
/// derived (no override, no HOME/APPDATA). Callers treat `None` as "local store
/// unavailable" and degrade with a warning rather than failing.
#[must_use]
pub fn default_data_dir() -> Option<PathBuf> {
    resolve_data_dir(&DataDirEnv::from_process(), DataDirOs::current())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins_on_every_platform() {
        let env = DataDirEnv {
            override_dir: Some("/tmp/explicit".to_owned()),
            xdg_data_home: Some("/xdg".to_owned()),
            home: Some("/home/u".to_owned()),
            appdata: Some("C:\\Users\\u\\AppData\\Roaming".to_owned()),
        };
        for os in [DataDirOs::Unix, DataDirOs::MacOs, DataDirOs::Windows] {
            assert_eq!(
                resolve_data_dir(&env, os),
                Some(PathBuf::from("/tmp/explicit"))
            );
        }
    }

    #[test]
    fn platform_defaults_follow_the_plan() {
        let env = DataDirEnv {
            override_dir: None,
            xdg_data_home: None,
            home: Some("/home/u".to_owned()),
            appdata: Some("C:\\AppData".to_owned()),
        };
        assert_eq!(
            resolve_data_dir(&env, DataDirOs::Unix),
            Some(PathBuf::from("/home/u/.local/share/franken-snowflake"))
        );
        assert_eq!(
            resolve_data_dir(&env, DataDirOs::MacOs),
            Some(PathBuf::from(
                "/home/u/Library/Application Support/franken-snowflake"
            ))
        );
        assert_eq!(
            resolve_data_dir(&env, DataDirOs::Windows),
            Some(PathBuf::from("C:\\AppData").join("franken-snowflake"))
        );

        let xdg = DataDirEnv {
            xdg_data_home: Some("/xdg".to_owned()),
            ..env
        };
        assert_eq!(
            resolve_data_dir(&xdg, DataDirOs::Unix),
            Some(PathBuf::from("/xdg/franken-snowflake"))
        );
    }

    #[test]
    fn no_root_means_none() {
        let env = DataDirEnv::default();
        assert_eq!(resolve_data_dir(&env, DataDirOs::Unix), None);
        assert_eq!(resolve_data_dir(&env, DataDirOs::Windows), None);
        let blank = DataDirEnv {
            override_dir: Some("   ".to_owned()),
            ..DataDirEnv::default()
        };
        // Blank overrides are treated as unset by `from_process`; the pure
        // resolver trusts its input, so pin that behavior at the boundary.
        assert_eq!(non_empty(blank.override_dir), None);
    }
}
