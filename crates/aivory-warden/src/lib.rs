//! Aivory Warden: the one binary that joins the crates.
//!
//! The binary runs in one of these modes:
//!
//! - the background daemon (`daemon`),
//! - the CLI verbs (they talk to the daemon over IPC),
//! - the MCP stdio server (`mcp`),
//! - the Edge native messaging host (first argument starts with `chrome-extension://`).

pub mod cli;
pub mod daemon;
pub mod desktop;
pub mod duration;
pub mod mcp_setup;
pub mod notify;
pub mod packaged;
pub mod paths;
pub mod service;
pub mod sinkspec;
pub mod store;

pub use paths::Paths;
