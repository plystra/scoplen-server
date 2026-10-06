// SPDX-License-Identifier: AGPL-3.0-only
//! SQLite and PostgreSQL storage boundary. Implemented in roadmap gate V2.

#![forbid(unsafe_code)]

/// Storage contract marker.
pub const COMPONENT: &str = "store";
