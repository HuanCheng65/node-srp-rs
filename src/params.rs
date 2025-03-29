use crate::srp_integer::SrpInteger;
use lazy_static::lazy_static;
use napi::{Error, Result, Status};
use napi_derive::napi;
use sha2::{Digest, Sha256};

// RFC 5054 SRP parameter groups
// 1024-bit Group
const N_1024_HEX: &str = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3";
const G_1024_HEX: &str = "02";

// 1536-bit Group
const N_1536_HEX: &str = "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB";
const G_1536_HEX: &str = "02";

// 2048-bit Group (this is the original one used in the codebase)
const N_2048_HEX: &str = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
const G_2048_HEX: &str = "02";

// 3072-bit Group
const N_3072_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
const G_3072_HEX: &str = "05";

// 4096-bit Group
const N_4096_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";
const G_4096_HEX: &str = "05";

pub const HASH_OUTPUT_BYTES: usize = 32; // 256 / 8

/// Enum representing SRP parameter groups from RFC 5054
#[napi]
#[derive(Debug, PartialEq)]
pub enum SrpGroup {
  /// 1024-bit SRP group from RFC 5054
  RFC5054_1024,
  /// 1536-bit SRP group from RFC 5054
  RFC5054_1536,
  /// 2048-bit SRP group from RFC 5054
  RFC5054_2048,
  /// 3072-bit SRP group from RFC 5054
  RFC5054_3072,
  /// 4096-bit SRP group from RFC 5054
  RFC5054_4096,
}

// Default to the 2048-bit group for backward compatibility
impl Default for SrpGroup {
  fn default() -> Self {
    SrpGroup::RFC5054_2048
  }
}

/// Helper function to create SrpGroup from bit size
#[napi]
pub fn srp_group_from_value(value: u32) -> Result<SrpGroup> {
  match value {
    1024 => Ok(SrpGroup::RFC5054_1024),
    1536 => Ok(SrpGroup::RFC5054_1536),
    2048 => Ok(SrpGroup::RFC5054_2048),
    3072 => Ok(SrpGroup::RFC5054_3072),
    4096 => Ok(SrpGroup::RFC5054_4096),
    _ => Err(Error::new(
      Status::InvalidArg,
      format!("Invalid SRP group size: {}", value),
    )),
  }
}

// Static SRP parameters for all groups
lazy_static! {
  // Core parameters for the default 2048-bit group
  pub static ref N: SrpInteger = SrpInteger::from_hex(N_2048_HEX).unwrap();
  pub static ref g: SrpInteger = SrpInteger::from_hex(G_2048_HEX).unwrap();
  pub static ref k: SrpInteger = H(&[&N, &g]);

  // Pre-computed hash values for performance
  pub static ref h_N: SrpInteger = H(&[&N]);
  pub static ref h_g: SrpInteger = H(&[&g]);
  pub static ref h_N_xor_h_g: SrpInteger = h_N.xor(&h_g);

  // Parameters for all groups
  pub static ref N_1024: SrpInteger = SrpInteger::from_hex(N_1024_HEX).unwrap();
  pub static ref g_1024: SrpInteger = SrpInteger::from_hex(G_1024_HEX).unwrap();
  pub static ref k_1024: SrpInteger = H(&[&N_1024, &g_1024]);

  pub static ref N_1536: SrpInteger = SrpInteger::from_hex(N_1536_HEX).unwrap();
  pub static ref g_1536: SrpInteger = SrpInteger::from_hex(G_1536_HEX).unwrap();
  pub static ref k_1536: SrpInteger = H(&[&N_1536, &g_1536]);

  pub static ref N_2048: SrpInteger = SrpInteger::from_hex(N_2048_HEX).unwrap();
  pub static ref g_2048: SrpInteger = SrpInteger::from_hex(G_2048_HEX).unwrap();
  pub static ref k_2048: SrpInteger = H(&[&N_2048, &g_2048]);

  pub static ref N_3072: SrpInteger = SrpInteger::from_hex(N_3072_HEX).unwrap();
  pub static ref g_3072: SrpInteger = SrpInteger::from_hex(G_3072_HEX).unwrap();
  pub static ref k_3072: SrpInteger = H(&[&N_3072, &g_3072]);

  pub static ref N_4096: SrpInteger = SrpInteger::from_hex(N_4096_HEX).unwrap();
  pub static ref g_4096: SrpInteger = SrpInteger::from_hex(G_4096_HEX).unwrap();
  pub static ref k_4096: SrpInteger = H(&[&N_4096, &g_4096]);

  // Precomputed hash values for each group for performance
  pub static ref h_N_1024: SrpInteger = H(&[&N_1024]);
  pub static ref h_g_1024: SrpInteger = H(&[&g_1024]);
  pub static ref h_N_xor_h_g_1024: SrpInteger = h_N_1024.xor(&h_g_1024);

  pub static ref h_N_1536: SrpInteger = H(&[&N_1536]);
  pub static ref h_g_1536: SrpInteger = H(&[&g_1536]);
  pub static ref h_N_xor_h_g_1536: SrpInteger = h_N_1536.xor(&h_g_1536);

  pub static ref h_N_2048: SrpInteger = H(&[&N_2048]);
  pub static ref h_g_2048: SrpInteger = H(&[&g_2048]);
  pub static ref h_N_xor_h_g_2048: SrpInteger = h_N_2048.xor(&h_g_2048);

  pub static ref h_N_3072: SrpInteger = H(&[&N_3072]);
  pub static ref h_g_3072: SrpInteger = H(&[&g_3072]);
  pub static ref h_N_xor_h_g_3072: SrpInteger = h_N_3072.xor(&h_g_3072);

  pub static ref h_N_4096: SrpInteger = H(&[&N_4096]);
  pub static ref h_g_4096: SrpInteger = H(&[&g_4096]);
  pub static ref h_N_xor_h_g_4096: SrpInteger = h_N_4096.xor(&h_g_4096);
}

/// Function to get N, g, and k for a specific group
pub fn get_group_params(
  group: SrpGroup,
) -> (
  &'static SrpInteger,
  &'static SrpInteger,
  &'static SrpInteger,
) {
  match group {
    SrpGroup::RFC5054_1024 => (&N_1024, &g_1024, &k_1024),
    SrpGroup::RFC5054_1536 => (&N_1536, &g_1536, &k_1536),
    SrpGroup::RFC5054_2048 => (&N_2048, &g_2048, &k_2048),
    SrpGroup::RFC5054_3072 => (&N_3072, &g_3072, &k_3072),
    SrpGroup::RFC5054_4096 => (&N_4096, &g_4096, &k_4096),
  }
}

/// Function to get the precomputed h_N_xor_h_g value for a specific group
pub fn get_h_N_xor_h_g(group: SrpGroup) -> &'static SrpInteger {
  match group {
    SrpGroup::RFC5054_1024 => &h_N_xor_h_g_1024,
    SrpGroup::RFC5054_1536 => &h_N_xor_h_g_1536,
    SrpGroup::RFC5054_2048 => &h_N_xor_h_g_2048,
    SrpGroup::RFC5054_3072 => &h_N_xor_h_g_3072,
    SrpGroup::RFC5054_4096 => &h_N_xor_h_g_4096,
  }
}

/// Hash function for SRP protocol (SHA-256)
pub fn H(args: &[&SrpInteger]) -> SrpInteger {
  let mut hasher = Sha256::new();

  for arg in args {
    let hex = arg.to_hex();
    let bytes = hex::decode(&hex).unwrap();
    hasher.update(&bytes);
  }

  let result = hasher.finalize();
  let hex_result = hex::encode(result);

  SrpInteger::from_hex(&hex_result).unwrap()
}

// String hashing function
pub fn H_str(s: &str) -> SrpInteger {
  let mut hasher = Sha256::new();
  hasher.update(s.as_bytes());

  let result = hasher.finalize();
  let hex_result = hex::encode(result);

  SrpInteger::from_hex(&hex_result).unwrap()
}
