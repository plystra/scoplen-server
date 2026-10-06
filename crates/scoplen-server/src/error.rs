// SPDX-License-Identifier: AGPL-3.0-only
//! Errors for the server process boundary.

use std::path::PathBuf;

use thiserror::Error;

/// Errors returned while loading, validating, or running a deployment.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Configuration could not be read or parsed.
    #[error("configuration error: {0}")]
    Config(#[from] crate::ConfigError),
    /// The data directory could not be initialized.
    #[error("could not initialize data directory {path}: {source}")]
    DataDirectory {
        /// Directory that failed to initialize.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// A generated deployment material file could not be written.
    #[error("could not write deployment material {path}: {source}")]
    Material {
        /// File that failed to write.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// A listener or request-serving task failed.
    #[error("runtime error: {0}")]
    Runtime(#[from] std::io::Error),
    /// TLS configuration could not be created.
    #[error("TLS error: {0}")]
    Tls(String),
    /// A task returned an unexpected error.
    #[error("role task failed: {0}")]
    Task(String),
}
\n