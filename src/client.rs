use crate::params::{self, H_str, H, HASH_OUTPUT_BYTES};
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
pub fn derive_private_key(salt: String, username: String, password: String) -> String {
  // s    User's salt
  // I    Username
  // p    Cleartext Password
  let s = SrpInteger::from_hex(&salt);
  let I = username;
  let p = password;

  // x = H(s, H(I | ':' | p))
  let i_p = format!("{}:{}", I, p);
  let h_i_p = H_str(&i_p);
  let x = H(&[&s, &h_i_p]);

  x.to_hex()
}

/// Derive the password verifier from the private key
#[napi]
pub fn derive_verifier(private_key: String) -> String {
  // N    A large safe prime
  // g    A generator modulo N
  let N = &*params::N;
  let g = &*params::g;

  // x    Private key (derived from password and salt)
  let x = SrpInteger::from_hex(&private_key);

  // v = g^x (password verifier)
  let v = g.mod_pow(&x, N);

  v.to_hex()
}

/// Client's ephemeral key pair
#[napi]
pub struct ClientEphemeral {
  pub secret: String,
  pub public: String,
}

/// Generate client's ephemeral key pair
#[napi(js_name = "generateClientEphemeral")]
pub fn generate_ephemeral() -> ClientEphemeral {
  // N    A large safe prime
  // g    A generator modulo N
  let N = &*params::N;
  let g = &*params::g;

  // A = g^a (a = random number)
  let a = SrpInteger::random_integer(HASH_OUTPUT_BYTES);
  let A = g.mod_pow(&a, N);

  ClientEphemeral {
    secret: a.to_hex(),
    public: A.to_hex(),
  }
}

/// Client's session key and proof
#[napi(object)]
pub struct ClientSession {
  pub key: String,
  pub proof: String,
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
  let N = &*params::N;
  let g = &*params::g;
  let k = &*params::k;

  // 解析输入参数
  let a = SrpInteger::from_hex(&client_secret_ephemeral);
  let B = SrpInteger::from_hex(&server_public_ephemeral);
  let s = SrpInteger::from_hex(&salt);
  let I = username;
  let x = SrpInteger::from_hex(&private_key);

  // A = g^a
  let A = match client_public_ephemeral {
    Some(public) => SrpInteger::from_hex(&public),
    None => g.mod_pow(&a, N),
  };

  // B % N > 0
  if B.mod_(N).equals(&SrpInteger::ZERO) {
    return Err(Error::new(
      Status::InvalidArg,
      "The server sent an invalid public ephemeral".to_string(),
    ));
  }

  // u = H(A, B)
  let u = params::H(&[&A, &B]);

  // S = (B - kg^x) ^ (a + ux) mod N
  let gx = g.mod_pow(&x, N);
  let kgx = k.multiply(&gx);
  let B_minus_kgx = B.subtract(&kgx).mod_(N);
  let ux = u.multiply(&x);
  let a_plus_ux = a.add(&ux);
  let S = B_minus_kgx.mod_pow(&a_plus_ux, N);

  // K = H(S)
  let K = params::H(&[&S]);

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  // 精确匹配 JS 实现
  let h_N = params::H(&[N]);
  let h_g = params::H(&[g]);
  let h_N_xor_h_g = h_N.xor(&h_g);
  let h_I = params::H_str(&I);

  // 关键：所有参数**一次性**哈希，而不是嵌套哈希
  let M = params::H(&[&h_N_xor_h_g, &h_I, &s, &A, &B, &K]);

  Ok(ClientSession {
    key: K.to_hex(),
    proof: M.to_hex(),
  })
}

/// Verify the server's session proof
#[napi]
pub fn verify_session(
  client_public_ephemeral: String,
  client_session: ClientSession,
  server_session_proof: String,
) -> Result<()> {
  // Parse inputs
  let A = SrpInteger::from_hex(&client_public_ephemeral);
  let M = SrpInteger::from_hex(&client_session.proof);
  let K = SrpInteger::from_hex(&client_session.key);

  // Expected proof: H(A, M, K)
  let expected = H(&[&A, &M, &K]);
  let actual = SrpInteger::from_hex(&server_session_proof);

  if !actual.equals(&expected) {
    return Err(Error::new(
      Status::InvalidArg,
      "Server provided session proof is invalid".to_string(),
    ));
  }

  Ok(())
}
