//! Aivory Warden MCP crate.
//!
//! - [`serve_stdio`] runs the stdio MCP server that agents start as `aivory-warden mcp`.
//! - [`proxy`] holds the HTTP proxy logic that the daemon runs to use a secret without
//!   revealing it.
//!
//! The server writes MCP frames to stdout and nothing else.

pub mod proxy;
mod server;

pub use server::{WardenMcp, serve_io, serve_stdio};
