// SPDX-License-Identifier: AGPL-3.0-only
//! Deployment configuration and validation.

use std::{net::IpAddr, path::PathBuf};

use serde::Deserialize;
use thiserror::Error;

use crate::roles::resolve_roles;

/// Server configuration loaded from TOML and environment overrides.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Public listener and data-directory settings.
    pub server: ServerSettings,
    /// TLS and reverse-proxy settings.
    pub tls: TlsSettings,
    /// Roles to run in this process.
    pub roles: RoleSettings,
    /// Storage profile selected for the process.
    pub storage: StorageSettings,
}

impl Config {
    /// Load a TOML file, using Personal-profile defaults when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, the TOML is invalid, or an environment
    /// override cannot be parsed.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let mut config = if path.exists() {
            let source = std::fs::read_to_string(path)
                .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
            toml::from_str(&source).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source: Box::new(source),
            })?
        } else {
            Self::default()
        };
        config.apply_environment()?;
        Ok(config)
    }

    /// Apply documented `SPL_` environment overrides.
    ///
    /// The names use underscores to keep them usable in shells and process managers. Role lists
    /// are comma-separated; empty variables are treated as absent so a deployment cannot
    /// accidentally erase a working value with an empty environment entry.
    fn apply_environment(&mut self) -> Result<(), ConfigError> {
        if let Some(value) = env_value("SPL_SERVER_LISTEN_ADDR") {
            self.server.listen_addr = value;
        }
        if let Some(value) = env_value("SPL_SERVER_LISTEN_PORT") {
            self.server.listen_port = value.parse().map_err(|_| {
                ConfigError::Invalid("SPL_SERVER_LISTEN_PORT must be an integer port".into())
            })?;
        }
        if let Some(value) = env_value("SPL_SERVER_PUBLIC_HOST") {
            self.server.public_host = value;
        }
        if let Some(value) = env_value("SPL_SERVER_DATA_DIR") {
            self.server.data_dir = PathBuf::from(value);
        }
        if let Some(value) = env_value("SPL_TLS_MODE") {
            self.tls.mode = value.parse().map_err(|()| {
                ConfigError::Invalid("SPL_TLS_MODE must be plain, files, or acme".into())
            })?;
        }
        if let Some(value) = env_value("SPL_TLS_CERT_FILE") {
            self.tls.cert_file = Some(PathBuf::from(value));
        }
        if let Some(value) = env_value("SPL_TLS_KEY_FILE") {
            self.tls.key_file = Some(PathBuf::from(value));
        }
        if let Some(value) = env_value("SPL_TLS_ACME_EMAIL") {
            self.tls.acme_email = Some(value);
        }
        if let Some(value) = env_value("SPL_TLS_ACME_PRODUCTION") {
            self.tls.acme_production = value.parse().map_err(|_| {
                ConfigError::Invalid("SPL_TLS_ACME_PRODUCTION must be true or false".into())
            })?;
        }
        if let Some(value) = env_value("SPL_STORAGE_BACKEND") {
            self.storage.backend = value;
        }
        if let Some(value) = env_value("SPL_ROLES_NAMES") {
            self.roles.names = value
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect();
        }
        Ok(())
    }

    /// Validate all values that can be checked without contacting external services.
    ///
    /// # Errors
    ///
    /// Returns an error when a listener, role, TLS, or ACME value violates a local
    /// deployment invariant.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.listen_port == 0 {
            return Err(ConfigError::Invalid(
                "server.listen_port must be between 1 and 65535".into(),
            ));
        }
        if self.server.public_host.trim().is_empty() {
            return Err(ConfigError::Invalid("server.public_host must not be empty".into()));
        }
        if self.server.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("server.data_dir must not be empty".into()));
        }
        resolve_roles(&self.roles.names)
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        match self.tls.mode {
            TlsMode::Files => {
                if self.tls.cert_file.is_none() || self.tls.key_file.is_none() {
                    return Err(ConfigError::Invalid(
                        "tls.mode = files requires tls.cert_file and tls.key_file".into(),
                    ));
                }
            }
            TlsMode::Acme => {
                if self.tls.acme_email.as_deref().unwrap_or_default().trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "tls.mode = acme requires tls.acme_email".into(),
                    ));
                }
                if self.server.public_host.parse::<IpAddr>().is_ok()
                    || self.server.public_host.eq_ignore_ascii_case("localhost")
                    || self.server.public_host.ends_with(".localhost")
                {
                    return Err(ConfigError::Invalid(
                        "tls.mode = acme requires a DNS name in server.public_host".into(),
                    ));
                }
            }
            TlsMode::Plain => {}
        }
        Ok(())
    }

    /// Validate settings required by the selected roles, including the database backend.
    ///
    /// # Errors
    ///
    /// Returns an error if any selected role cannot run with the configured storage backend.
    pub fn validate_for_roles(&self, roles: &[crate::Role]) -> Result<(), ConfigError> {
        self.validate()?;
        if roles.iter().any(|role| role.requires_store()) && self.storage.backend != "sqlite" {
            return Err(ConfigError::Invalid(
                "storage.backend must be sqlite for api, worker, or edge; PostgreSQL support is not available yet".into(),
            ));
        }
        Ok(())
    }

    /// The address used by the public listener.
    #[must_use]
    pub fn listen_address(&self) -> String {
        format!("{}:{}", self.server.listen_addr, self.server.listen_port)
    }
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.trim().is_empty())
}

/// Public listener and local data settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerSettings {
    /// Address to bind. The default is local-only for a safe first run.
    pub listen_addr: String,
    /// Public port. `8443` avoids a privileged bind during development.
    pub listen_port: u16,
    /// Public DNS name used by setup links and ACME.
    pub public_host: String,
    /// Directory for deployment keys and generated first-run material.
    pub data_dir: PathBuf,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".into(),
            listen_port: 8443,
            public_host: "localhost".into(),
            data_dir: PathBuf::from("./data"),
        }
    }
}

/// TLS mode for the shared public listener.
#[derive(Debug, Clone, Copy, Deserialize, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Plain HTTP for a trusted TLS-terminating reverse proxy.
    Plain,
    /// Load a certificate and private key from files.
    #[default]
    Files,
    /// Obtain a certificate through TLS-ALPN-01 ACME.
    Acme,
}

/// TLS, ACME, and proxy configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsSettings {
    /// Selected TLS mode.
    pub mode: TlsMode,
    /// PEM certificate chain for `files` mode.
    pub cert_file: Option<PathBuf>,
    /// PEM private key for `files` mode.
    pub key_file: Option<PathBuf>,
    /// Contact address for ACME registration.
    pub acme_email: Option<String>,
    /// Whether ACME requests use the Let's Encrypt production directory.
    ///
    /// Set this to `false` when testing against the staging directory. Production is the
    /// default so a Personal deployment obtains a browser-trusted certificate without an
    /// additional setting.
    pub acme_production: bool,
    /// Proxies trusted to supply forwarded client metadata in `plain` mode.
    pub trusted_proxies: Vec<String>,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            mode: TlsMode::Plain,
            cert_file: None,
            key_file: None,
            acme_email: None,
            acme_production: true,
            trusted_proxies: Vec::new(),
        }
    }
}

impl std::str::FromStr for TlsMode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plain" => Ok(Self::Plain),
            "files" => Ok(Self::Files),
            "acme" => Ok(Self::Acme),
            _ => Err(()),
        }
    }
}

/// Role names configured for a process.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RoleSettings {
    /// Names accepted by [`crate::resolve_roles`].
    pub names: Vec<String>,
}

impl Default for RoleSettings {
    fn default() -> Self {
        Self { names: vec!["all".into()] }
    }
}

/// Storage profile selected by a deployment.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageSettings {
    /// `sqlite` is the Personal and Team default; PostgreSQL is reserved for V2.
    pub backend: String,
}

impl Default for StorageSettings {
    fn default() -> Self {
        Self { backend: "sqlite".into() }
    }
}

/// Configuration failures with actionable paths.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Configuration file read error.
    #[error("could not read {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    /// Configuration file parse error.
    #[error("could not parse {path}: {source}")]
    Parse { path: PathBuf, source: Box<toml::de::Error> },
    /// A value violates a deployment invariant.
    #[error("{0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_for_local_validation() {
        let config = Config::default();
        config.validate().expect("defaults are valid");
        assert_eq!(config.listen_address(), "127.0.0.1:8443");
    }

    #[test]
    fn acme_requires_a_contact_and_dns_name() {
        let mut config = Config::default();
        config.tls.mode = TlsMode::Acme;
        assert!(config.validate().is_err());
        config.tls.acme_email = Some("operator@example.com".into());
        assert!(config.validate().is_err());
        config.server.public_host = "scoplen.example.com".into();
        config.validate().expect("ACME values are now present");
    }

    #[test]
    fn certificate_file_mode_requires_both_files() {
        let mut config = Config::default();
        config.tls.mode = TlsMode::Files;
        let error = config.validate().expect_err("missing files must be rejected");
        assert!(error.to_string().contains("cert_file and tls.key_file"));
    }

    #[test]
    fn acme_production_defaults_to_lets_encrypt_production() {
        let config = Config::default();
        assert!(config.tls.acme_production);
    }

    #[test]
    fn unsupported_storage_backends_are_rejected() {
        let mut config = Config::default();
        config.storage.backend = "postgres".into();
        let error = config
            .validate_for_roles(&[crate::Role::Api])
            .expect_err("PostgreSQL is not implemented for the API");
        assert!(error.to_string().contains("storage.backend"));
        config.storage.backend = "unknown".into();
        assert!(config.validate_for_roles(&[crate::Role::Worker]).is_err());
        config
            .validate_for_roles(&[crate::Role::Ca, crate::Role::Gateway])
            .expect("database-free roles ignore storage backend");
    }
}
