use crate::params::{get_group_params, get_h_N_xor_h_g, H_str, SrpGroup, H, HASH_OUTPUT_BYTES};
use crate::srp_integer::SrpInteger;
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Generate a random salt for password hashing
#[napi]
pub fn generate_salt() -> String {
  // s    User's salt
  let s = SrpInteger::random_integer(HASH_OUTPUT_BYTES);
  s.to_hex()
}

/// Derive the private key from user credentials
#[napi]
pub fn derive_private_key(salt: String, username: String, password: String) -> Result<String> {
  // s    User's salt
  // I    Username
  // p    Cleartext Password
  let s = SrpInteger::from_hex(&salt).map_err(|e| Error::new(Status::InvalidArg, e))?;
  let I = username;
  let p = password;

  // x = H(s, H(I | ':' | p))
  let i_p = format!("{}:{}", I, p);
  let h_i_p = H_str(&i_p);
  let x = H(&[&s, &h_i_p]);

  Ok(x.to_hex())
}

/// Client's ephemeral key pair
#[napi]
pub struct ClientEphemeral {
  pub secret: String,
  pub public: String,
}

/// Client's session key and proof
#[napi(object)]
pub struct ClientSession {
  pub key: String,
  pub proof: String,
}

/// Client-side SRP implementation
#[napi]
pub struct Client {
  group: SrpGroup,
}

#[napi]
impl Client {
  /// Create a new Client instance with optional parameter group
  #[napi(constructor)]
  pub fn new(group: Option<SrpGroup>) -> Self {
    Client {
      group: group.unwrap_or_default(),
    }
  }

  /// Generate a random salt for password hashing
  #[napi]
  pub fn generate_salt(&self) -> String {
    generate_salt()
  }

  /// Derive the private key from user credentials
  #[napi]
  pub fn derive_private_key(
    &self,
    salt: String,
    username: String,
    password: String,
  ) -> Result<String> {
    derive_private_key(salt, username, password)
  }

  /// Derive the password verifier from the private key
  #[napi]
  pub fn derive_verifier(&self, private_key: String) -> Result<String> {
    // N    A large safe prime
    // g    A generator modulo N
    let (N, g, _) = get_group_params(self.group);

    // x    Private key (derived from password and salt)
    let x = SrpInteger::from_hex(&private_key).map_err(|e| Error::new(Status::InvalidArg, e))?;

    // v = g^x (password verifier)
    let v = g.mod_pow(&x, N);

    Ok(v.to_hex())
  }

  /// Generate client's ephemeral key pair
  #[napi]
  pub fn generate_ephemeral(&self) -> ClientEphemeral {
    // N    A large safe prime
    // g    A generator modulo N
    let (N, g, _) = get_group_params(self.group);

    // a    Secret ephemeral value
    let a = SrpInteger::random_integer(HASH_OUTPUT_BYTES);

    // A = g^a (public ephemeral value)
    let A = g.mod_pow(&a, N);

    ClientEphemeral {
      secret: a.to_hex(),
      public: A.to_hex(),
    }
  }

  /// Derive the session key and proof on the client side
  #[napi]
  pub fn derive_session(
    &self,
    client_secret_ephemeral: String,
    server_public_ephemeral: String,
    salt: String,
    username: String,
    private_key: String,
    client_public_ephemeral: Option<String>,
  ) -> Result<ClientSession> {
    // N    A large safe prime
    // g    A generator modulo N
    // k    Multiplier parameter (k = H(N, g))
    let (N, g, k) = get_group_params(self.group);

    // a    Secret ephemeral value
    let a = SrpInteger::from_hex(&client_secret_ephemeral)
      .map_err(|e| Error::new(Status::InvalidArg, e))?;

    // A    Public ephemeral value
    let A = match client_public_ephemeral {
      Some(A_str) => SrpInteger::from_hex(&A_str).map_err(|e| Error::new(Status::InvalidArg, e))?,
      None => g.mod_pow(&a, N),
    };

    // B    Server's public ephemeral value
    let B = SrpInteger::from_hex(&server_public_ephemeral)
      .map_err(|e| Error::new(Status::InvalidArg, e))?;

    // Validate that B % N != 0
    if B.is_zero() || B.modulo(N).is_zero() {
      return Err(Error::new(
        Status::InvalidArg,
        "Server's public ephemeral value is invalid".to_string(),
      ));
    }

    // u = H(A, B)
    let u = H(&[&A, &B]);

    // s    User's salt
    let s = SrpInteger::from_hex(&salt).map_err(|e| Error::new(Status::InvalidArg, e))?;

    // x    Private key
    let x = SrpInteger::from_hex(&private_key).map_err(|e| Error::new(Status::InvalidArg, e))?;

    // Compute session key
    // S = (B - k*(g^x))^(a + ux)
    let S = B.subtract_mult_pow(k, g, &x, &a, &u, N);
    let K = H(&[&S]);

    // I    Username
    let I = username;

    // Get hashed value of identity
    let I_hash = H_str(&I);

    // Use XOR of hash(N) and hash(g)
    let N_g_xor = get_h_N_xor_h_g(self.group);

    // Generate client's proof
    // M1 = H(H(N) XOR H(g), H(I), s, A, B, K)
    let M1 = H(&[N_g_xor, &I_hash, &s, &A, &B, &K]);

    Ok(ClientSession {
      key: K.to_hex(),
      proof: M1.to_hex(),
    })
  }

  /// Verify the server's session proof
  #[napi]
  pub fn verify_session(
    &self,
    client_public_ephemeral: String,
    client_session: ClientSession,
    server_session_proof: String,
  ) -> Result<()> {
    // A    Client's public ephemeral value
    let A = SrpInteger::from_hex(&client_public_ephemeral)
      .map_err(|e| Error::new(Status::InvalidArg, e))?;

    // M1    Client's proof
    let M1 =
      SrpInteger::from_hex(&client_session.proof).map_err(|e| Error::new(Status::InvalidArg, e))?;

    // K    Session key
    let K = hex::decode(&client_session.key)
      .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;

    // M2    Server's proof
    let M2 =
      SrpInteger::from_hex(&server_session_proof).map_err(|e| Error::new(Status::InvalidArg, e))?;

    // Verify that M2 = H(A, M1, K)
    let K_srp = SrpInteger::from_bytes(&K);
    let expected_M2 = H(&[&A, &M1, &K_srp]);

    if !expected_M2.equals(&M2) {
      return Err(Error::new(
        Status::GenericFailure,
        "Server's proof is invalid".to_string(),
      ));
    }

    Ok(())
  }
}

// Standalone functions for backward compatibility
/// Derive the password verifier from the private key
#[napi]
pub fn derive_verifier(private_key: String) -> Result<String> {
  // Default to 2048-bit group for backward compatibility
  let group = SrpGroup::default();
  let (N, g, _) = get_group_params(group);

  // x    Private key (derived from password and salt)
  let x = SrpInteger::from_hex(&private_key).map_err(|e| Error::new(Status::InvalidArg, e))?;

  // v = g^x (password verifier)
  let v = g.mod_pow(&x, N);

  Ok(v.to_hex())
}

/// Generate client's ephemeral key pair
#[napi(js_name = "generateClientEphemeral")]
pub fn generate_ephemeral() -> ClientEphemeral {
  // Default to 2048-bit group for backward compatibility
  let group = SrpGroup::default();
  let (N, g, _) = get_group_params(group);

  // a    Secret ephemeral value
  let a = SrpInteger::random_integer(HASH_OUTPUT_BYTES);

  // A = g^a (public ephemeral value)
  let A = g.mod_pow(&a, N);

  ClientEphemeral {
    secret: a.to_hex(),
    public: A.to_hex(),
  }
}

/// Derive the session key and proof on the client side
#[napi(js_name = "deriveClientSession")]
pub fn derive_session(
  client_secret_ephemeral: String,
  server_public_ephemeral: String,
  salt: String,
  username: String,
  private_key: String,
  client_public_ephemeral: Option<String>,
) -> Result<ClientSession> {
  // Create a default client and use its method
  Client::new(None).derive_session(
    client_secret_ephemeral,
    server_public_ephemeral,
    salt,
    username,
    private_key,
    client_public_ephemeral,
  )
}

/// Verify the server's session proof
#[napi]
pub fn verify_session(
  client_public_ephemeral: String,
  client_session: ClientSession,
  server_session_proof: String,
) -> Result<()> {
  // Create a default client and use its method
  Client::new(None).verify_session(
    client_public_ephemeral,
    client_session,
    server_session_proof,
  )
}
