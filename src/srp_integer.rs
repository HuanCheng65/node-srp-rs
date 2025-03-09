use num_bigint::{BigInt, Sign};
use rand::thread_rng;
use rand::RngCore;
use std::fmt;

pub struct SrpInteger {
  value: BigInt,
  hex_length: Option<usize>,
}

impl SrpInteger {
  pub const ZERO: SrpInteger = SrpInteger {
    value: BigInt::ZERO,
    hex_length: None,
  };

  pub fn from_hex(hex: &str) -> Self {
    // 清理输入（与JS版本一致）
    let cleaned_hex = hex.trim().replace(" ", "").replace("\n", "");

    // 使用与JS相同的方式：0x前缀 + 十六进制字符串
    let value = match BigInt::parse_bytes(cleaned_hex.as_bytes(), 16) {
      Some(v) => v,
      None => panic!("Invalid hex string: {}", hex),
    };

    Self {
      value,
      hex_length: Some(cleaned_hex.len()),
    }
  }

  pub fn to_hex(&self) -> String {
    if self.hex_length.is_none() {
      panic!("This SrpInteger has no specified length");
    }

    let hex = self.value.to_str_radix(16).to_lowercase();

    // 确保和JS版本一样填充前导零
    if let Some(len) = self.hex_length {
      if hex.len() < len {
        return "0".repeat(len - hex.len()) + &hex;
      }
    }

    hex
  }

  pub fn random_integer(bytes: usize) -> Self {
    let mut rng = thread_rng();
    let mut buf = vec![0u8; bytes];
    rng.fill_bytes(&mut buf);

    // 转换为十六进制字符串
    let hex = hex::encode(&buf);
    Self::from_hex(&hex)
  }

  pub fn equals(&self, other: &Self) -> bool {
    self.value == other.value
  }

  pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
    let result = self.value.modpow(&exp.value, &modulus.value);

    Self {
      value: result,
      hex_length: modulus.hex_length, // 使用modulus的长度，与JS一致
    }
  }

  pub fn multiply(&self, other: &Self) -> Self {
    let result = &self.value * &other.value;

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  pub fn add(&self, other: &Self) -> Self {
    let result = &self.value + &other.value;

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  pub fn subtract(&self, other: &Self) -> Self {
    let result = &self.value - &other.value;

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  pub fn mod_(&self, modulus: &Self) -> Self {
    let mut result = &self.value % &modulus.value;

    // 确保结果为正，与JS一致
    if result < BigInt::from(0) {
      result += &modulus.value;
    }

    Self {
      value: result,
      hex_length: modulus.hex_length,
    }
  }

  pub fn xor(&self, other: &Self) -> Self {
    // 转为十六进制，确保长度匹配
    let a_hex = self.to_hex();
    let b_hex = other.to_hex();

    // 确保两者长度相同
    let a_bytes = hex::decode(&a_hex).unwrap();
    let b_bytes = hex::decode(&b_hex).unwrap();

    // 确保等长度（使用相同的填充逻辑）
    let max_len = std::cmp::max(a_bytes.len(), b_bytes.len());
    let mut a_padded = vec![0; max_len - a_bytes.len()];
    let mut b_padded = vec![0; max_len - b_bytes.len()];

    a_padded.extend_from_slice(&a_bytes);
    b_padded.extend_from_slice(&b_bytes);

    // 执行异或操作
    let xor_result: Vec<u8> = a_padded
      .iter()
      .zip(b_padded.iter())
      .map(|(a, b)| a ^ b)
      .collect();

    // 保持与JS一致的长度处理
    Self {
      value: BigInt::from_bytes_be(Sign::Plus, &xor_result),
      hex_length: self.hex_length,
    }
  }
}

impl fmt::Debug for SrpInteger {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let hex = self.value.to_str_radix(16);
    if hex.len() > 16 {
      write!(f, "<SrpInteger {}{}>", &hex[0..16], "...")
    } else {
      write!(f, "<SrpInteger {}>", hex)
    }
  }
}
