use crate::srp_integer::SrpInteger;
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

const N_HEX: &str = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
const G_HEX: &str = "02";
pub const HASH_OUTPUT_BYTES: usize = 32; // 256 / 8

lazy_static! {
  pub static ref N: SrpInteger = SrpInteger::from_hex(N_HEX);
  pub static ref g: SrpInteger = SrpInteger::from_hex(G_HEX);
  pub static ref k: SrpInteger = H(&[&N, &g]);
}

// 一次性哈希多个 SrpInteger，完全模拟 JS 实现
pub fn H(args: &[&SrpInteger]) -> SrpInteger {
  let mut hasher = Sha256::new();

  for arg in args {
    // 对 SrpInteger，用十六进制表示并转为二进制更新哈希器
    let hex = arg.to_hex();
    let bytes = hex::decode(&hex).unwrap();
    hasher.update(&bytes);
  }

  let result = hasher.finalize();
  let hex_result = hex::encode(result);

  SrpInteger::from_hex(&hex_result)
}

// 哈希一个字符串
pub fn H_str(s: &str) -> SrpInteger {
  let mut hasher = Sha256::new();
  hasher.update(s.as_bytes());

  let result = hasher.finalize();
  let hex_result = hex::encode(result);

  SrpInteger::from_hex(&hex_result)
}
