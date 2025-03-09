use rug::{rand::RandState, Assign, Complete, Integer};
use std::fmt;

pub struct SrpInteger {
  value: Integer,
  hex_length: Option<usize>,
}

impl SrpInteger {
  pub const ZERO: SrpInteger = SrpInteger {
    value: Integer::ZERO,
    hex_length: None,
  };

  // Efficiently create from bytes
  pub fn from_bytes(bytes: &[u8]) -> Self {
    let value = Integer::from_digits(bytes, rug::integer::Order::Msf);
    Self {
      value,
      hex_length: Some(bytes.len() * 2), // Each byte corresponds to two hex characters
    }
  }

  // Write binary representation directly to vector to avoid hex conversion
  pub fn write_binary_to_vec(&self, vec: &mut Vec<u8>) {
    vec.clear();

    // Calculate required bytes (enough to contain the integer)
    let req_size = (self.value.significant_bits() as usize + 7) / 8;

    // Ensure vector has sufficient capacity
    if vec.capacity() < req_size {
      vec.reserve(req_size + 64);
    }

    let bytes = self.value.to_digits::<u8>(rug::integer::Order::Msf);
    vec.extend_from_slice(&bytes);
  }

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
    let B_minus_kgx = self.subtract(&kgx).mod_(modulus);
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

  pub fn multiply(&self, other: &Self) -> Self {
    let result = (&self.value * &other.value).complete();

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  pub fn add(&self, other: &Self) -> Self {
    let result = (&self.value + &other.value).complete();

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

  pub fn subtract(&self, other: &Self) -> Self {
    let result = (&self.value - &other.value).complete();

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }

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

  pub fn xor(&self, other: &Self) -> Self {
    let result = (&self.value ^ &other.value).complete();

    Self {
      value: result,
      hex_length: self.hex_length.or(other.hex_length),
    }
  }
}

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
