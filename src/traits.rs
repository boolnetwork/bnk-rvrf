use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use sha3::{Digest as Digest2, Keccak256};

// trait
pub trait ScalarTrait:
    Add<Output = Self>
    + Mul<Output = Self>
    + Sub<Output = Self>
    + Neg<Output = Self>
    + MulAssign
    + AddAssign
    + Clone
    + Copy
    + PartialEq
    + Default
    + Debug
    + Sized
{
    type ScalarType;
    #[cfg(feature = "prove")]
    fn random_scalar() -> Self;
    fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self;
    fn get_self(&self) -> Self;
    fn one() -> Self;
    fn zero() -> Self;
    fn from_u64(n: u64) -> Self;
    fn bytes(&self) -> Vec<u8>;
}

// trait
pub trait PointTrait:
    Add<Output = Self>
    + Sub<Output = Self>
    + AddAssign
    + SubAssign
    + Clone
    + Copy
    + Default
    + PartialEq
    + Debug
    + Sized //+ Mul<dyn ScalarTrait>
{
    fn hash_to_point<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self;
    fn generator() -> Self;
    fn generator_2() -> Self;
    fn point_to_bytes(&self) -> Vec<u8>;
    // fn default() -> Self;
}

/// Trait of a replaceable hash algorithm.
pub trait Hash {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8>;
}

/// Implements Keccak256 as a Hash instance.
#[derive(Default, Debug, Clone)]
pub struct ZKeccak256 {}

impl Hash for ZKeccak256 {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8> {
        let mut hash_algorithm = Keccak256::default();
        hash_algorithm.input(input);
        hash_algorithm.result().to_vec()
    }
}

lazy_static! {
    /// Shared hash algorithm reference for quick implementation replacement.
    /// Other code should use this reference, and not directly use a specific implementation.
    pub static ref HASH: ZKeccak256 = ZKeccak256::default();
}
