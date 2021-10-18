//! This module contains the main CID type.
//!
//! If you are an application developer you likely won't use the `Cid` which is
//! generic over the digest size. Intead you would use the concrete top-level
//! `Cid` type.
//!
//! As a library author that works with CIDs that should support hashes of
//! anysize, you would import the `Cid` type from this module.
use core::{
  convert::TryFrom,
  fmt,
};

use alloc::{
  borrow,
  str,
  string::{
    String,
    ToString,
  },
  vec::Vec,
};

use bytecursor::ByteCursor;
use unsigned_varint::encode as varint_encode;

use multibase::{
  encode as base_encode,
  Base,
};
use sp_multihash::MultihashGeneric as Multihash;

use crate::{
  codec,
  codec::Codec,
  error::{
    Error,
    Result,
  },
  version::Version,
};

/// Representation of a CID.
///
/// The generic is about the allocated size of the multihash.
#[derive(PartialEq, Eq, Copy, Clone, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "scale-codec", derive(parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-codec", derive(parity_scale_codec::Encode))]
#[cfg_attr(feature = "serde-codec", derive(serde::Deserialize))]
#[cfg_attr(feature = "serde-codec", derive(serde::Serialize))]
pub struct Cid<const S: usize> {
  /// The version of CID.
  version: Version,
  /// The codec of CID.
  codec: Codec,
  /// The multihash of CID.
  hash: Multihash<S>,
}

impl<const S: usize> Cid<S> {
  /// Create a new CIDv0.
  pub fn new_v0(hash: Multihash<S>) -> Result<Self> {
    if hash.code() != codec::SHA2_256 {
      return Err(Error::InvalidCidV0Multihash);
    }
    Ok(Self { codec: codec::DAG_PB, version: Version::V0, hash })
  }

  /// Create a new CIDv1.
  pub fn new_v1(codec: Codec, hash: Multihash<S>) -> Self {
    Self { codec, version: Version::V1, hash }
  }

  /// Create a new CID.
  pub fn new(
    version: Version,
    codec: Codec,
    hash: Multihash<S>,
  ) -> Result<Self> {
    match version {
      Version::V0 => {
        if codec != codec::DAG_PB {
          return Err(Error::InvalidCidV0Codec);
        }
        Self::new_v0(hash)
      }
      Version::V1 => Ok(Self::new_v1(codec, hash)),
    }
  }

  /// Returns the cid version.
  pub fn version(&self) -> Version { self.version }

  /// Returns the cid codec.
  pub fn codec(&self) -> u64 { self.codec }

  /// Returns the cid multihash.
  pub fn hash(&self) -> &Multihash<S> { &self.hash }

  /// Reads the bytes from a byte stream.
  pub fn read_bytes(r: &mut ByteCursor) -> Result<Self> {
    let version = match crate::varint_read_u64(r) {
      Ok(v) => v,
      Err(e) => return Err(e),
    };
    let codec = match crate::varint_read_u64(r) {
      Ok(v) => v,
      Err(e) => return Err(e),
    };
    // CIDv0 has the fixed `0x12 0x20` prefix
    if [version, codec] == [0x12, 0x20] {
      let mut digest = [0u8; 32];
      match r.read_exact(&mut digest) {
        Ok(_) => (),
        Err(_) => return Err(Error::VarIntDecodeError),
      };
      let mh =
        Multihash::wrap(version, &digest).expect("Digest is always 32 bytes.");
      Self::new_v0(mh)
    }
    else {
      let version = match Version::try_from(version) {
        Ok(ver) => ver,
        Err(_) => return Err(Error::VarIntDecodeError),
      };
      let mh = match Multihash::read(r) {
        Ok(dig) => dig,
        Err(_) => return Err(Error::VarIntDecodeError),
      };
      Self::new(version, codec, mh)
    }
  }

  fn write_bytes_v1(&self, w: &mut ByteCursor) -> Result<()> {
    let mut version_buf = varint_encode::u64_buffer();
    let version = varint_encode::u64(self.version.into(), &mut version_buf);

    let mut codec_buf = varint_encode::u64_buffer();
    let codec = varint_encode::u64(self.codec, &mut codec_buf);

    match w.write_all(version) {
      Ok(_) => (),
      Err(_) => return Err(Error::InvalidCidVersion),
    };
    match w.write_all(codec) {
      Ok(_) => (),
      Err(_) => return Err(Error::InvalidCidV0Codec),
    };
    match self.hash.write(w) {
      Ok(_) => (),
      Err(_) => return Err(Error::VarIntDecodeError),
    };
    Ok(())
  }

  /// Writes the bytes to a byte stream.
  pub fn write_bytes(&self, w: &mut ByteCursor) -> Result<()> {
    match self.version {
      Version::V0 => match self.hash.write(w) {
        Ok(_) => (),
        Err(_) => return Err(Error::VarIntDecodeError),
      },
      Version::V1 => match self.write_bytes_v1(w) {
        Ok(_) => (),
        Err(_) => return Err(Error::VarIntDecodeError),
      },
    };
    Ok(())
  }

  /// Returns the encoded bytes of the `Cid`.
  pub fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = ByteCursor::new(Vec::new());
    self.write_bytes(&mut bytes).unwrap();
    bytes.into_inner()
  }

  fn to_string_v0(&self) -> String {
    Base::Base58Btc.encode(self.hash.to_bytes())
  }

  fn to_string_v1(&self) -> String {
    multibase::encode(Base::Base32Lower, self.to_bytes().as_slice())
  }

  /// Convert CID into a multibase encoded string
  ///
  /// # Example
  ///
  /// ```
  /// use multibase::Base;
  /// use sp_cid::{
  ///   codec,
  ///   Cid,
  /// };
  /// use sp_multihash::{
  ///   Code,
  ///   MultihashDigest,
  /// };
  ///
  /// let cid = Cid::new_v1(codec::RAW, Code::Sha2_256.digest(b"foo"));
  /// let encoded = cid.to_string_of_base(Base::Base64).unwrap();
  /// assert_eq!(encoded, "mAVUSICwmtGto/8aP+ZtFPB0wQTQTQi1wZIO/oPmKXohiZueu");
  /// ```
  pub fn to_string_of_base(&self, base: Base) -> Result<String> {
    match self.version {
      Version::V0 => {
        if base == Base::Base58Btc {
          Ok(self.to_string_v0())
        }
        else {
          Err(Error::InvalidCidV0Base)
        }
      }
      Version::V1 => Ok(base_encode(base, self.to_bytes())),
    }
  }
}
impl<const S: usize> Default for Cid<S> {
  fn default() -> Self {
    Self {
      codec: codec::IDENTITY,
      version: Version::V1,
      hash: Multihash::<S>::default(),
    }
  }
}

impl<const S: usize> fmt::Display for Cid<S> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let output = match self.version {
      Version::V0 => self.to_string_v0(),
      Version::V1 => self.to_string_v1(),
    };
    write!(f, "{}", output)
  }
}

impl<const S: usize> fmt::Debug for Cid<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if f.alternate() {
      f.debug_struct("Cid")
        .field("version", &self.version())
        .field("codec", &self.codec())
        .field("hash", self.hash())
        .finish()
    }
    else {
      let output = match self.version {
        Version::V0 => self.to_string_v0(),
        Version::V1 => self.to_string_v1(),
      };
      write!(f, "Cid({})", output)
    }
  }
}

impl<const S: usize> str::FromStr for Cid<S> {
  type Err = Error;

  fn from_str(cid_str: &str) -> Result<Self> { Self::try_from(cid_str) }
}

impl<const S: usize> TryFrom<String> for Cid<S> {
  type Error = Error;

  fn try_from(cid_str: String) -> Result<Self> {
    Self::try_from(cid_str.as_str())
  }
}

impl<const S: usize> TryFrom<&str> for Cid<S> {
  type Error = Error;

  fn try_from(cid_str: &str) -> Result<Self> {
    static IPFS_DELIMETER: &str = "/ipfs/";

    let hash = match cid_str.find(IPFS_DELIMETER) {
      Some(index) => &cid_str[index + IPFS_DELIMETER.len()..],
      _ => cid_str,
    };

    if hash.len() < 2 {
      return Err(Error::InputTooShort);
    }

    let decoded = if Version::is_v0_str(hash) {
      match Base::Base58Btc.decode(hash) {
        Ok(d) => d,
        Err(_) => return Err(Error::ParsingError),
      }
    }
    else {
      match multibase::decode(hash) {
        Ok((_, d)) => d,
        Err(_) => return Err(Error::VarIntDecodeError),
      }
    };

    Self::try_from(decoded)
  }
}

impl<const S: usize> TryFrom<Vec<u8>> for Cid<S> {
  type Error = Error;

  fn try_from(bytes: Vec<u8>) -> Result<Self> {
    Self::try_from(bytes.as_slice())
  }
}

impl<const S: usize> TryFrom<&[u8]> for Cid<S> {
  type Error = Error;

  fn try_from(bytes: &[u8]) -> Result<Self> {
    Self::read_bytes(&mut ByteCursor::new(bytes.to_vec()))
  }
}

impl<const S: usize> From<&Cid<S>> for Cid<S> {
  fn from(cid: &Cid<S>) -> Self { *cid }
}

impl<const S: usize> From<Cid<S>> for Vec<u8> {
  fn from(cid: Cid<S>) -> Self { cid.to_bytes() }
}

impl<const S: usize> From<Cid<S>> for String {
  fn from(cid: Cid<S>) -> Self { cid.to_string() }
}

impl<'a, const S: usize> From<Cid<S>> for borrow::Cow<'a, Cid<S>> {
  fn from(from: Cid<S>) -> Self { borrow::Cow::Owned(from) }
}

impl<'a, const S: usize> From<&'a Cid<S>> for borrow::Cow<'a, Cid<S>> {
  fn from(from: &'a Cid<S>) -> Self { borrow::Cow::Borrowed(from) }
}

#[cfg(test)]
mod tests {
  #[test]
  #[cfg(feature = "scale-codec")]
  fn test_cid_scale_codec() {
    use super::Cid;
    use parity_scale_codec::{
      Decode,
      Encode,
    };

    let cid = Cid::<64>::default();
    let bytes = cid.encode();
    let cid2 = Cid::decode(&mut &bytes[..]).unwrap();
    assert_eq!(cid, cid2);
  }

  #[test]
  #[cfg(feature = "serde-codec")]
  fn test_cid_serde() {
    use super::Cid;

    let cid = Cid::<64>::default();
    let bytes = serde_json::to_string(&cid).unwrap();
    let cid2 = serde_json::from_str(&bytes).unwrap();
    assert_eq!(cid, cid2);
  }

  #[test]
  #[cfg(feature = "std")]
  fn test_debug_instance() {
    use super::Cid;
    use std::str::FromStr;
    let cid = Cid::<64>::from_str(
      "bafyreibjo4xmgaevkgud7mbifn3dzp4v4lyaui4yvqp3f2bqwtxcjrdqg4",
    )
    .unwrap();
    // short debug
    assert_eq!(
      &format!("{:?}", cid),
      "Cid(bafyreibjo4xmgaevkgud7mbifn3dzp4v4lyaui4yvqp3f2bqwtxcjrdqg4)"
    );
    // verbose debug
    let mut txt = format!("{:#?}", cid);
    txt.retain(|c| !c.is_whitespace());
    assert_eq!(
      &txt,
      "Cid{version:V1,codec:113,hash:Multihash{code:18,size:32,digest:[41,119,\
       46,195,0,149,81,168,63,176,40,43,118,60,191,149,226,240,10,35,152,172,\
       31,178,232,48,180,238,36,196,112,55,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\
       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],},}"
    );
  }
}
