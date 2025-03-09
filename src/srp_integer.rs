#[cfg(not(any(target_os = "macos", target_env = "msvc")))]
use rug::{rand::RandState, Assign, Complete, Integer};

#[cfg(any(target_os = "macos", target_env = "msvc"))]
use {
  num_bigint::{BigInt, BigUint, Sign},
  num_traits::{One, Pow, Zero},
  rand::{thread_rng, RngCore},
  std::ops::Add,
};

use std::fmt;

pub struct SrpInteger {
  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  value: Integer,

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  value: BigInt,

  hex_length: Option<usize>,
}

impl SrpInteger {
  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub const ZERO: SrpInteger = SrpInteger {
    value: Integer::ZERO,
    hex_length: None,
  };

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  pub const ZERO: SrpInteger = SrpInteger {
    value: BigInt::ZERO,
    hex_length: None,
  };

  // Efficiently create from bytes
  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn from_bytes(bytes: &[u8]) -> Self {
    let value = Integer::from_digits(bytes, rug::integer::Order::Msf);
    Self {
      value,
      hex_length: Some(bytes.len() * 2), // Each byte corresponds to two hex characters
    }
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  pub fn from_bytes(bytes: &[u8]) -> Self {
    let value = BigUint::from_bytes_be(bytes).into();
    Self {
      value,
      hex_length: Some(bytes.len() * 2), // Each byte corresponds to two hex characters
    }
  }

  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn from_hex(hex: &str) -> Self {
    // Clean input
    let cleaned_hex = hex.trim().replace(" ", "").replace("\n", "");

    let value = Integer::parse_radix(&cleaned_hex, 16)
      .expect(&format!("Invalid hex string: {}", hex))
      .complete();

    Self {
      value,
      hex_length: Some(cleaned_hex.len()),
    }
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  pub fn from_hex(hex: &str) -> Self {
    // Clean input
    let cleaned_hex = hex.trim().replace(" ", "").replace("\n", "");

    let value = BigUint::parse_bytes(cleaned_hex.as_bytes(), 16)
      .expect(&format!("Invalid hex string: {}", hex))
      .into();

    Self {
      value,
      hex_length: Some(cleaned_hex.len()),
    }
  }

  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn to_hex(&self) -> String {
    if self.hex_length.is_none() {
      panic!("This SrpInteger has no specified length");
    }

    let hex = self.value.to_string_radix(16).to_lowercase();

    if let Some(len) = self.hex_length {
      if hex.len() < len {
        return "0".repeat(len - hex.len()) + &hex;
      }
    }

    hex
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
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

  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn random_integer(bytes: usize) -> Self {
    // Create a random state
    let mut rand = RandState::new();
    // Create random integer of specified size
    let mut value = Integer::new();
    value.assign(Integer::random_bits(bytes as u32 * 8, &mut rand));

    // Convert to hex and retain length information
    let hex = value.to_string_radix(16);
    let hex_len = hex.len();

    Self {
      value,
      hex_length: Some(hex_len),
    }
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]

  pub fn random_integer(bytes: usize) -> Self {
    let mut rng = thread_rng();
    let mut buf = vec![0u8; bytes];
    rng.fill_bytes(&mut buf);

    let hex = hex::encode(&buf);
    Self::from_hex(&hex)
  }

  pub fn equals(&self, other: &Self) -> bool {
    self.value == other.value
  }

  // Calculate (B - kg^x) ^ (a + ux)
  pub fn subtract_mult_pow(
    &self,
    k: &Self,
    g: &Self,
    x: &Self,
    a: &Self,
    u: &Self,
    modulus: &Self,
  ) -> Self {
    let gx = g.mod_pow(x, modulus);
    let kgx = k.multiply(&gx);
    let B_minus_kgx = self.subtract(&kgx);
    let ux = u.multiply(x);
    let a_plus_ux = a.add(&ux);
    B_minus_kgx.mod_pow(&a_plus_ux, modulus)
  }

  // Calculate kv + g^b
  pub fn add_mult_pow(&self, k: &Self, v: &Self, g: &Self, b: &Self, modulus: &Self) -> Self {
    let gb = g.mod_pow(b, modulus);
    let kv = k.multiply(v);
    kv.add(&gb).mod_(modulus)
  }

  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
    let result = self
      .value
      .clone()
      .pow_mod(&exp.value, &modulus.value)
      .expect("Modular exponentiation failed");

    Self {
      value: result,
      hex_length: modulus.hex_length,
    }
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
    let result = self.value.modpow(&exp.value, &modulus.value);

    Self {
      value: result,
      hex_length: modulus.hex_length,
    }
  }

  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn multiply(&self, other: &Self) -> Self {
    let result = (&self.value * &other.value).complete();

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  pub fn multiply(&self, other: &Self) -> Self {
    let result = &self.value * &other.value;

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn add(&self, other: &Self) -> Self {
    let result = (&self.value + &other.value).complete();

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  pub fn add(&self, other: &Self) -> Self {
    let result = &self.value + &other.value;

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn subtract(&self, other: &Self) -> Self {
    let result = (&self.value - &other.value).complete();

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  pub fn subtract(&self, other: &Self) -> Self {
    let result = &self.value - &other.value;

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn mod_(&self, modulus: &Self) -> Self {
    let mut result = self.value.clone();
    result %= &modulus.value;

    // Ensure result is positive
    if result < 0 {
      result += &modulus.value;
    }

    Self {
      value: result,
      hex_length: modulus.hex_length,
    }
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  pub fn mod_(&self, modulus: &Self) -> Self {
    let mut result = &self.value % &modulus.value;

    if result < BigInt::from(0) {
      result += &modulus.value;
    }

    Self {
      value: result,
      hex_length: modulus.hex_length,
    }
  }

  #[cfg(not(any(target_os = "macos", target_env = "msvc")))]
  pub fn xor(&self, other: &Self) -> Self {
    let result = (&self.value ^ &other.value).complete();

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  #[cfg(any(target_os = "macos", target_env = "msvc"))]
  pub fn xor(&self, other: &Self) -> Self {
    let a_hex = self.to_hex();
    let b_hex = other.to_hex();

    let a_bytes = hex::decode(&a_hex).unwrap();
    let b_bytes = hex::decode(&b_hex).unwrap();

    let max_len = std::cmp::max(a_bytes.len(), b_bytes.len());
    let mut a_padded = vec![0; max_len - a_bytes.len()];
    let mut b_padded = vec![0; max_len - b_bytes.len()];

    a_padded.extend_from_slice(&a_bytes);
    b_padded.extend_from_slice(&b_bytes);

    let xor_result: Vec<u8> = a_padded
      .iter()
      .zip(b_padded.iter())
      .map(|(a, b)| a ^ b)
      .collect();

    Self {
      value: BigInt::from_bytes_be(Sign::Plus, &xor_result),
      hex_length: self.hex_length,
    }
  }

  // Check if the integer is zero
  pub fn is_zero(&self) -> bool {
    self.equals(&Self::ZERO)
  }

  // Compute modulo
  pub fn modulo(&self, modulus: &Self) -> Self {
    self.mod_(modulus)
  }
}

#[cfg(not(any(target_os = "macos", target_env = "msvc")))]
impl fmt::Debug for SrpInteger {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let hex = self.value.to_string_radix(16);
    if hex.len() > 16 {
      write!(f, "<SrpInteger {}{}>", &hex[0..16], "...")
    } else {
      write!(f, "<SrpInteger {}>", hex)
    }
  }
}

#[cfg(any(target_os = "macos", target_env = "msvc"))]
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
