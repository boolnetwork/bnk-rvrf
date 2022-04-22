use p256::Scalar;
use p256::{AffinePoint, FieldBytes};
use rand_core::OsRng;

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub};
use p256::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::Field;
use p256::ProjectivePoint;

use alloc::vec::Vec;
// #[macro_use]
// extern crate lazy_static;

pub fn algorithms_trait_prove<T:ScalarTrait + Copy, K: PointTrait + Copy + Mul<T> >(input:T, input2:T, input3:K ,input4:K)
{
    let mut data = T::random_scalar();
    data += input;
    let _ = input + input2;
    let _ = input - input2;
    let _ = input * input2;
    let _ = input3 - input4;
    input3 * input2;
}

pub fn algorithms_type_prove(input:ScalarSelfDefined, input2:ScalarSelfDefined, input3:PointSelfDefined ,input4:PointSelfDefined){
    let mut data = ScalarSelfDefined::random_scalar();
    data += input;
    let _ = input + input2;
    let _ = input - input2;
    let _ = input * input2;
    let _ = input3 - input4;
    input3 * input2;
    input2 * input3;
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ScalarSelfDefined {
    pub data: Scalar,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PointSelfDefined {
    pub data: AffinePoint,
}

// trait
pub trait ScalarTrait:
    Add<Output = Self> + Mul<Output = Self> + Sub<Output = Self> + MulAssign + AddAssign + Clone + Copy + PartialEq + Sized
{
    type ScalarType;
    fn random_scalar() -> Self;
    fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self;
    fn get_self(&self) -> Self;
    fn one() -> Self;
    fn zero() -> Self;
    fn from_u64(n:u64) -> Self;
}

// trait
pub trait PointTrait:
Add<Output = Self> + Sub<Output = Self> + AddAssign + Clone + Copy + PartialEq + Sized //+ Mul<dyn ScalarTrait>
{
    fn hash_to_point<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self;
    fn generator() -> Self;
    fn generator_2() -> Self;
    fn point_to_bytes(&self) -> Vec<u8>;
}

impl MulAssign<ScalarSelfDefined> for ScalarSelfDefined{
    fn mul_assign(&mut self, rhs: ScalarSelfDefined) {
        *self = ScalarSelfDefined {
            data: (&self.data).mul(&rhs.data),
        };
    }
}

impl AddAssign<ScalarSelfDefined> for ScalarSelfDefined{
    fn add_assign(&mut self, rhs: ScalarSelfDefined) {
        *self = ScalarSelfDefined {
            data: (&self.data).add(&rhs.data),
        };
    }
}

impl Mul<ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn mul(self, other: ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: (&self.data).mul(&other.data),
        }
    }
}

impl<'o> Mul<&'o ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn mul(self, other: &'o ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: (&self.data).mul(&other.data),
        }
    }
}

impl Add<ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn add(self, other: ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: (&self.data).add(&other.data),
        }
    }
}

impl Sub<ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn sub(self, other: ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined{
            data:(&self.data).sub(&other.data)
        }
    }
}

impl<'o> Sub<&'o ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn sub(self, other: &'o ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined{
            data:(&self.data).sub(&other.data)
        }
    }
}

impl ScalarTrait for ScalarSelfDefined {
    type ScalarType = Scalar;

    fn random_scalar() -> Self {
        let mut csprng = OsRng;
        ScalarSelfDefined {
            data: Scalar::random(&mut csprng),
        }
    }

    fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        let mut array = [0; 32];
        array.clone_from_slice(&HASH.hash(input));
        let mut bytes = FieldBytes::default();
        bytes.copy_from_slice(&array);
        ScalarSelfDefined {
            data: Scalar::from_bytes_reduced(&bytes),
        }
    }

    fn get_self(&self) -> Self{
        self.clone()
    }

    fn one() -> Self {
        ScalarSelfDefined{
            data: Scalar::one()
        }
    }

    fn zero() -> Self {
        ScalarSelfDefined{
            data: Scalar::zero()
        }
    }

    fn from_u64(n: u64) -> Self {
        ScalarSelfDefined{
            data: Scalar::from(n)
        }
    }
}

// ============

impl Mul<ScalarSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, scalar: ScalarSelfDefined) -> PointSelfDefined {
        let point = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(self.data)).unwrap(),
        );
        let scalar = scalar.data;
        PointSelfDefined {
            data: (point * scalar).to_affine(),
        }
    }
}

impl Mul<&ScalarSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, scalar: &ScalarSelfDefined) -> PointSelfDefined {
        let point = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(self.data)).unwrap(),
        );
        let scalar = scalar.data;
        PointSelfDefined {
            data: (point * scalar).to_affine(),
        }
    }
}

impl Mul<PointSelfDefined> for ScalarSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, point: PointSelfDefined) -> PointSelfDefined {
        let point = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(point.data)).unwrap(),
        );
        let scalar = self.data;
        PointSelfDefined {
            data: (point * scalar).to_affine(),
        }
    }
}

impl Mul<&PointSelfDefined> for ScalarSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, point: &PointSelfDefined) -> PointSelfDefined {
        let point = ProjectivePoint::from(
        AffinePoint::from_encoded_point(&EncodedPoint::from(point.data)).unwrap(),
    );
        let scalar = self.data;
        PointSelfDefined {
            data: (point * scalar).to_affine(),
        }
    }
}

// ==============

impl AddAssign<PointSelfDefined> for PointSelfDefined{
    fn add_assign(&mut self, rhs: PointSelfDefined) {
        let point1 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(self.data)).unwrap(),
        );
        let point2 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(rhs.data)).unwrap(),
        );
        *self = PointSelfDefined {
            data: (point1 + point2).to_affine(),
        };
    }
}

impl Add<PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn add(self, other: PointSelfDefined) -> PointSelfDefined {
        let point1 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(self.data)).unwrap(),
        );
        let point2 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(other.data)).unwrap(),
        );
        PointSelfDefined {
            data: (point1 + point2).to_affine(),
        }
    }
}

impl Sub<PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn sub(self, other: PointSelfDefined) -> PointSelfDefined {
        let point1 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(self.data)).unwrap(),
        );
        let point2 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(other.data)).unwrap(),
        );
        PointSelfDefined {
            data: (point1 - point2).to_affine(),
        }
    }
}

impl<'o> Sub<&'o PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn sub(self, other: &'o PointSelfDefined) -> PointSelfDefined {
        let point1 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(self.data)).unwrap(),
        );
        let point2 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(other.data)).unwrap(),
        );
        PointSelfDefined {
            data: (point1 - point2).to_affine(),
        }
    }
}

impl PointTrait for PointSelfDefined {
    //type PointType = Self;

    fn hash_to_point<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        PointSelfDefined {
            data: AffinePoint::default(),
        }
    }

    fn generator() -> PointSelfDefined {
        PointSelfDefined {
            data: AffinePoint::generator()
        }
    }

    fn generator_2() -> Self {
        PointSelfDefined {
            data: AffinePoint::generator()
        }
    }

    fn point_to_bytes(&self) -> Vec<u8> {
        self.data.to_encoded_point(true).as_ref().to_vec()
    }
}


// ======================
#[test]
fn trait_type_test() {
    algorithms_trait_prove(ScalarSelfDefined::random_scalar(),
                     ScalarSelfDefined::random_scalar(),
                     PointSelfDefined::generator(),
                     PointSelfDefined::generator()
    );
    algorithms_type_prove(ScalarSelfDefined::random_scalar(),
                           ScalarSelfDefined::random_scalar(),
                           PointSelfDefined::generator(),
                           PointSelfDefined::generator());
}

#[test]
fn cal_test() {
    let a: ScalarSelfDefined = ScalarTrait::random_scalar();
    let b: ScalarSelfDefined = ScalarTrait::random_scalar();
    let c1 = a.data.mul(&b.get_self().data);
    let c2 = a * b;
    assert_eq!(c1, c2.data);
}

use sha3::{Digest as Digest2, Keccak256};
use sha2::digest::Output;

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
