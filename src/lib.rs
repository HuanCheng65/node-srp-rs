#![deny(clippy::all)]

mod client;
mod params;
mod server;
mod srp_integer;

use napi_derive::napi;

/// Client-side SRP implementation
#[napi(js_name = "Client")]
pub struct ClientModule {}

#[napi]
impl ClientModule {
  #[napi(constructor)]
  pub fn new() -> Self {
    Self {}
  }

  #[napi]
  pub fn generate_salt(&self) -> String {
    client::generate_salt()
  }

  #[napi]
  pub fn derive_private_key(&self, salt: String, username: String, password: String) -> String {
    client::derive_private_key(salt, username, password)
  }

  #[napi]
  pub fn derive_verifier(&self, private_key: String) -> String {
    client::derive_verifier(private_key)
  }

  #[napi]
  pub fn generate_ephemeral(&self) -> client::ClientEphemeral {
    client::generate_ephemeral()
  }

  #[napi]
  pub fn derive_session(
    &self,
    client_secret_ephemeral: String,
    server_public_ephemeral: String,
    salt: String,
    username: String,
    private_key: String,
    client_public_ephemeral: Option<String>,
  ) -> napi::Result<client::ClientSession> {
    client::derive_session(
      client_secret_ephemeral,
      server_public_ephemeral,
      salt,
      username,
      private_key,
      client_public_ephemeral,
    )
  }

  #[napi]
  pub fn verify_session(
    &self,
    client_public_ephemeral: String,
    client_session: client::ClientSession,
    server_session_proof: String,
  ) -> napi::Result<()> {
    client::verify_session(
      client_public_ephemeral,
      client_session,
      server_session_proof,
    )
  }
}

/// Server-side SRP implementation
#[napi(js_name = "Server")]
pub struct ServerModule {}

#[napi]
impl ServerModule {
  #[napi(constructor)]
  pub fn new() -> Self {
    Self {}
  }

  #[napi]
  pub fn generate_ephemeral(&self, verifier: String) -> server::ServerEphemeral {
    server::generate_ephemeral(verifier)
  }

  #[napi]
  pub fn derive_session(
    &self,
    server_secret_ephemeral: String,
    client_public_ephemeral: String,
    salt: String,
    username: String,
    verifier: String,
    client_session_proof: String,
  ) -> napi::Result<server::ServerSession> {
    server::derive_session(
      server_secret_ephemeral,
      client_public_ephemeral,
      salt,
      username,
      verifier,
      client_session_proof,
    )
  }
}
