// SPDX-License-Identifier: AGPL-3.0-only
//! Server role parsing and normalization.

use std::{fmt, str::FromStr};

/// A role implemented by `spl-server`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    /// Public HTTP API, sync API, and notification sockets.
    Api,
    /// Background jobs.
    Worker,
    /// Certificate authority signer.
    Ca,
    /// Public edge gateway.
    Edge,
    /// Private network gateway.
    Gateway,
}

impl Role {
    /// Return the stable configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Worker => "worker",
            Self::Ca => "ca",
            Self::Edge => "edge",
            Self::Gateway => "gateway",
        }
    }
}

impl FromStr for Role {
    type Err = RoleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "api" => Ok(Self::Api),
            "worker" => Ok(Self::Worker),
            "ca" => Ok(Self::Ca),
            "edge" => Ok(Self::Edge),
            "gateway" => Ok(Self::Gateway),
            other => Err(RoleError(other.to_owned())),
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned for an unknown role.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RoleError(String);

impl fmt::Display for RoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown role {:?}; expected api, worker, ca, edge, or gateway", self.0)
    }
}

impl std::error::Error for RoleError {}

/// Resolve the configured role names. `all` expands to every server role.
///
/// # Errors
///
/// Returns an error when a name is not one of the supported roles.
pub fn resolve_roles(names: &[String]) -> Result<Vec<Role>, RoleError> {
    let names = if names.is_empty() { vec!["all".to_owned()] } else { names.to_vec() };
    let mut roles = Vec::new();
    for name in names {
        if name.eq_ignore_ascii_case("all") {
            roles.extend([Role::Api, Role::Worker, Role::Ca, Role::Edge, Role::Gateway]);
            continue;
        }
        let role = name.parse()?;
        if !roles.contains(&role) {
            roles.push(role);
        }
    }
    Ok(roles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_expands_in_stable_order() {
        assert_eq!(
            resolve_roles(&["all".to_owned()]).expect("all is valid"),
            vec![Role::Api, Role::Worker, Role::Ca, Role::Edge, Role::Gateway]
        );
    }

    #[test]
    fn unknown_role_is_actionable() {
        let error = resolve_roles(&["database".to_owned()]).expect_err("role must be rejected");
        assert!(error.to_string().contains("api, worker, ca, edge, or gateway"));
    }
}
