use crate::params::{self, h_N_xor_h_g, H_str, H, HASH_OUTPUT_BYTES};
use crate::srp_integer::SrpInteger;
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Server's ephemeral key pair
#[napi]
pub struct ServerEphemeral {
  pub secret: String,
  pub public: String,
}

/// Generate server's ephemeral key pair
#[napi(js_name = "generateServerEphemeral")]
pub fn generate_ephemeral(verifier: String) -> ServerEphemeral {
  let N = &*params::N;
  let g = &*params::g;
  let k = &*params::k;

  // v    Password verifier
  let v = SrpInteger::from_hex(&verifier);

  // B = kv + g^b (b = random number)
  let b = SrpInteger::random_integer(HASH_OUTPUT_BYTES);
  let B = g.add_mult_pow(k, &v, g, &b, N);

  ServerEphemeral {
    secret: b.to_hex(),
    public: B.to_hex(),
  }
}

/// Server's session key and proof
#[napi]
pub struct ServerSession {
  pub key: String,
  pub proof: String,
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
  let N = &*params::N;
  let g = &*params::g;
  let k = &*params::k;

  let b = SrpInteger::from_hex(&server_secret_ephemeral);
  let A = SrpInteger::from_hex(&client_public_ephemeral);
  let s = SrpInteger::from_hex(&salt);
  let I = username;
  let v = SrpInteger::from_hex(&verifier);

  // B = kv + g^b
  let B = g.add_mult_pow(k, &v, g, &b, N);

  if A.mod_(N).equals(&SrpInteger::ZERO) {
    return Err(Error::new(
      Status::InvalidArg,
      "The client sent an invalid public ephemeral".to_string(),
    ));
  }

  // u = H(A, B)
  let u = params::H(&[&A, &B]);

  // S = (A * v^u) ^ b
  let vu = v.mod_pow(&u, N);
  let Avu = A.multiply(&vu);
  let S = Avu.mod_pow(&b, N);

  // K = H(S)
  let K = params::H(&[&S]);

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  let h_I = params::H_str(&I);

  // Use pre-computed h_N_xor_h_g
  let expected_M = params::H(&[&h_N_xor_h_g, &h_I, &s, &A, &B, &K]);

  let actual_M = SrpInteger::from_hex(&client_session_proof);

  if !actual_M.equals(&expected_M) {
    return Err(Error::new(
      Status::InvalidArg,
      "Client provided session proof is invalid".to_string(),
    ));
  }

  // P = H(A, M, K)
  let P = params::H(&[&A, &expected_M, &K]);

  Ok(ServerSession {
    key: K.to_hex(),
    proof: P.to_hex(),
  })
}
