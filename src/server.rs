use crate::params::{get_group_params, get_h_N_xor_h_g, H_str, SrpGroup, H, HASH_OUTPUT_BYTES};
use crate::srp_integer::SrpInteger;
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Server's ephemeral key pair
#[napi]
pub struct ServerEphemeral {
  pub secret: String,
  pub public: String,
}

/// Server's session key and proof
#[napi(object)]
pub struct ServerSession {
  pub key: String,
  pub proof: String,
}

/// Server-side SRP implementation
#[napi]
pub struct Server {
  group: SrpGroup,
}

#[napi]
impl Server {
  /// Create a new Server instance with optional parameter group
  #[napi(constructor)]
  pub fn new(group: Option<SrpGroup>) -> Self {
    Server {
      group: group.unwrap_or_default(),
    }
  }

  /// Generate server's ephemeral key pair
  #[napi]
  pub fn generate_ephemeral(&self, verifier: String) -> Result<ServerEphemeral> {
    // N    A large safe prime
    // g    A generator modulo N
    // k    Multiplier parameter (k = H(N, g))
    let (N, g, k) = get_group_params(self.group);

    // v    Password verifier
    let v = SrpInteger::from_hex(&verifier).map_err(|e| Error::new(Status::InvalidArg, e))?;

    // B = kv + g^b (b = random number)
    let b = SrpInteger::random_integer(HASH_OUTPUT_BYTES);
    let gb = g.mod_pow(&b, N);
    let kv = k.multiply(&v).modulo(N);
    let B = kv.add(&gb).modulo(N);

    Ok(ServerEphemeral {
      secret: b.to_hex(),
      public: B.to_hex(),
    })
  }

  /// Derive the session key and proof on the server side
  #[napi]
  pub fn derive_session(
    &self,
    server_secret_ephemeral: String,
    client_public_ephemeral: String,
    salt: String,
    username: String,
    verifier: String,
    client_session_proof: String,
  ) -> Result<ServerSession> {
    // N    A large safe prime
    // g    A generator modulo N
    let (N, g, k) = get_group_params(self.group);

    // b    Secret ephemeral value
    let b = SrpInteger::from_hex(&server_secret_ephemeral)
      .map_err(|e| Error::new(Status::InvalidArg, e))?;

    // A    Client's public ephemeral value
    let A = SrpInteger::from_hex(&client_public_ephemeral)
      .map_err(|e| Error::new(Status::InvalidArg, e))?;

    // s    User's salt
    let s = SrpInteger::from_hex(&salt).map_err(|e| Error::new(Status::InvalidArg, e))?;

    // v    Password verifier
    let v = SrpInteger::from_hex(&verifier).map_err(|e| Error::new(Status::InvalidArg, e))?;

    // I    Username
    let I = username;

    // M1   Client's proof of session key
    let M1 =
      SrpInteger::from_hex(&client_session_proof).map_err(|e| Error::new(Status::InvalidArg, e))?;

    // Safeguard against malicious A values (A % N should not be 0)
    if A.is_zero() || A.modulo(N).is_zero() {
      return Err(Error::new(
        Status::InvalidArg,
        "Client's public ephemeral value is invalid".to_string(),
      ));
    }

    // B = kv + g^b
    let B = g.add_mult_pow(k, &v, g, &b, N);
    // u = H(A, B)
    let u = H(&[&A, &B]);

    // S = (A * v^u) ^ b
    let vu = v.mod_pow(&u, N);
    let Avu = A.multiply(&vu).modulo(N);
    let S = Avu.mod_pow(&b, N);

    // K = H(S)
    let K = H(&[&S]);

    // Get hashed value of identity
    let I_hash = H_str(&I);

    // Get XOR of hash(N) and hash(g)
    let N_g_xor = get_h_N_xor_h_g(self.group);

    // Verify that M1 = H(H(N) XOR H(g), H(I), s, A, B, K)
    let expected_M1 = H(&[N_g_xor, &I_hash, &s, &A, &B, &K]);

    if !expected_M1.equals(&M1) {
      return Err(Error::new(
        Status::GenericFailure,
        "Client's proof is invalid".to_string(),
      ));
    }

    // Generate server's proof
    // M2 = H(A, M1, K)
    let M2 = H(&[&A, &M1, &K]);

    Ok(ServerSession {
      key: K.to_hex(),
      proof: M2.to_hex(),
    })
  }
}

// Standalone functions for backward compatibility
/// Generate server's ephemeral key pair
#[napi(js_name = "generateServerEphemeral")]
pub fn generate_ephemeral(verifier: String) -> Result<ServerEphemeral> {
  // Create a default server and use its method
  Server::new(None).generate_ephemeral(verifier)
}

/// Derive the session key and proof on the server side
#[napi(js_name = "deriveServerSession")]
pub fn derive_session(
  server_secret_ephemeral: String,
  client_public_ephemeral: String,
  salt: String,
  username: String,
  verifier: String,
  client_session_proof: String,
) -> Result<ServerSession> {
  // Create a default server and use its method
  Server::new(None).derive_session(
    server_secret_ephemeral,
    client_public_ephemeral,
    salt,
    username,
    verifier,
    client_session_proof,
  )
}
