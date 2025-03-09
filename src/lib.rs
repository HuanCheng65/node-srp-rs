#![deny(clippy::all)]

mod client;
mod params;
mod server;
mod srp_integer;

// Re-export all public types and functions
pub use client::{Client, ClientEphemeral, ClientSession};
pub use params::{srp_group_from_value, SrpGroup};
pub use server::{Server, ServerEphemeral, ServerSession};

// Re-export standalone functions for backward compatibility
pub use client::{
  derive_private_key, derive_session as derive_client_session, derive_verifier,
  generate_ephemeral as generate_client_ephemeral, generate_salt, verify_session,
};
pub use server::{
  derive_session as derive_server_session, generate_ephemeral as generate_server_ephemeral,
};
