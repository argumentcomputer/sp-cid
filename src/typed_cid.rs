use crate::{
  cid::Cid,
  codec::Codec,
  version::{
    self,
    Version,
  },
};
use sp_multihash::MultihashGeneric as Multihash;

/// A statically typed content-identifier
pub struct TypedCid<const S: usize, const C: Codec> {
  hash: Multihash<S>,
}

impl<const S: usize, const C: Codec> TypedCid<S, C> {
  pub fn to_dynamic(&self) -> Cid<S> { Cid::new_v1(C, self.hash) }

  pub fn from_dynamic(cid: &Cid<S>) -> Option<Self> {
    if cid.version() == Version::V1 && C == cid.codec() {
      Some(Self { hash: *cid.hash() })
    }
    else {
      None
    }
  }
}
