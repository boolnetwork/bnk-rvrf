use k256::Scalar;
use k256::{AffinePoint, FieldBytes};
#[cfg(feature = "std-rand")]
//use rand_core::OsRng;
use rand::rngs::OsRng;

use crate::traits::{Hash, PointTrait, ScalarTrait, HASH};
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use k256::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::Field;
use k256::ProjectivePoint;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScalarSelfDefined {
    pub data: Scalar,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PointSelfDefined {
    pub data: AffinePoint,
}

impl MulAssign<ScalarSelfDefined> for ScalarSelfDefined {
    fn mul_assign(&mut self, rhs: ScalarSelfDefined) {
        *self = ScalarSelfDefined {
            data: self.data * rhs.data,
        };
    }
}

impl AddAssign<ScalarSelfDefined> for ScalarSelfDefined {
    fn add_assign(&mut self, rhs: ScalarSelfDefined) {
        *self = ScalarSelfDefined {
            data: self.data + rhs.data,
        };
    }
}

impl Mul<ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn mul(self, other: ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data * other.data,
        }
    }
}

impl<'o> Mul<&'o ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn mul(self, other: &'o ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data * other.data,
        }
    }
}

impl Add<ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn add(self, other: ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data + other.data,
        }
    }
}

impl Sub<ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn sub(self, other: ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data - other.data,
        }
    }
}

impl<'o> Sub<&'o ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn sub(self, other: &'o ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data - other.data,
        }
    }
}

impl Neg for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn neg(self) -> ScalarSelfDefined {
        ScalarSelfDefined { data: -self.data }
    }
}

impl ScalarTrait for ScalarSelfDefined {
    type ScalarType = Scalar;

    #[cfg(feature = "std-prove")]
    fn random_scalar() -> Self {
        let mut csprng = OsRng;
        ScalarSelfDefined {
            data: Scalar::random(&mut csprng),
        }
    }

    #[cfg(feature = "sgx-prove")]
    fn random_scalar() -> Self {
        use rand_sgx::{OsRng, RngCore};
        let mut csprng = OsRng;
        let mut scalar_bytes = [0u8; 32];
        csprng.fill_bytes(&mut scalar_bytes);
        let mut bytes = FieldBytes::default();
        bytes.copy_from_slice(&scalar_bytes);
        let res = Scalar::from_repr(bytes).unwrap();
        ScalarSelfDefined { data: res }
    }

    fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        let mut array = [0; 32];
        array.clone_from_slice(&HASH.hash(input));
        let mut bytes = FieldBytes::default();
        bytes.copy_from_slice(&array);
        let res = Scalar::from_repr(bytes).unwrap();
        ScalarSelfDefined { data: res }
    }

    fn get_self(&self) -> Self {
        *self
    }

    fn one() -> Self {
        ScalarSelfDefined {
            data: Scalar::one(),
        }
    }

    fn zero() -> Self {
        ScalarSelfDefined {
            data: Scalar::zero(),
        }
    }

    fn from_u64(n: u64) -> Self {
        ScalarSelfDefined {
            data: Scalar::from(n),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.data.to_bytes().as_slice().to_vec()
    }
}

// ============

impl Mul<ScalarSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, scalar: ScalarSelfDefined) -> PointSelfDefined {
        let point = ProjectivePoint::from(self.data);
        let scalar = scalar.data;
        PointSelfDefined {
            data: (point * scalar).to_affine(),
        }
    }
}

impl Mul<&ScalarSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, scalar: &ScalarSelfDefined) -> PointSelfDefined {
        let point = ProjectivePoint::from(self.data);
        let scalar = scalar.data;
        PointSelfDefined {
            data: (point * scalar).to_affine(),
        }
    }
}

impl Mul<PointSelfDefined> for ScalarSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, point: PointSelfDefined) -> PointSelfDefined {
        let point = ProjectivePoint::from(point.data);
        let scalar = self.data;
        PointSelfDefined {
            data: (point * scalar).to_affine(),
        }
    }
}

impl Mul<&PointSelfDefined> for ScalarSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, point: &PointSelfDefined) -> PointSelfDefined {
        let point = ProjectivePoint::from(point.data);
        let scalar = self.data;
        PointSelfDefined {
            data: (point * scalar).to_affine(),
        }
    }
}

// ==============

impl AddAssign<PointSelfDefined> for PointSelfDefined {
    fn add_assign(&mut self, rhs: PointSelfDefined) {
        *self = PointSelfDefined {
            data: (ProjectivePoint::from(self.data) + rhs.data).to_affine(),
        };
    }
}

impl Add<PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn add(self, other: PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: (ProjectivePoint::from(self.data) + other.data).to_affine(),
        }
    }
}

impl Sub<PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn sub(self, other: PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: (ProjectivePoint::from(self.data) - other.data).to_affine(),
        }
    }
}

impl<'o> Sub<&'o PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn sub(self, other: &'o PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: (ProjectivePoint::from(self.data) - other.data).to_affine(),
        }
    }
}

impl SubAssign for PointSelfDefined {
    fn sub_assign(&mut self, other: PointSelfDefined) {
        *self = PointSelfDefined {
            data: (ProjectivePoint::from(self.data) - other.data).to_affine(),
        };
    }
}

impl PointTrait for PointSelfDefined {
    //type PointType = Self;

    fn hash_to_point<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        let mut array = [0; 32];
        array.clone_from_slice(&HASH.hash(input));
        let mut bytes = FieldBytes::default();
        bytes.copy_from_slice(array.as_ref());
        let scalar = Scalar::from_bytes_reduced(&bytes);
        PointSelfDefined {
            data: (ProjectivePoint::from(AffinePoint::generator()) * scalar).to_affine(), //TODO::hash
        }
    }

    fn generator() -> PointSelfDefined {
        PointSelfDefined {
            data: AffinePoint::generator(),
        }
    }

    fn generator_2() -> Self {
        PointSelfDefined { data: *BASE_POINT2 }
    }

    fn point_to_bytes(&self) -> Vec<u8> {
        self.data.to_encoded_point(true).as_ref().to_vec()
    }
}

// ======================

const BASE_POINT2_X: [u8; 32] = [
    0x08, 0xd1, 0x32, 0x21, 0xe3, 0xa7, 0x32, 0x6a, 0x34, 0xdd, 0x45, 0x21, 0x4b, 0xa8, 0x01, 0x16,
    0xdd, 0x14, 0x2e, 0x4b, 0x5f, 0xf3, 0xce, 0x66, 0xa8, 0xdc, 0x7b, 0xfa, 0x03, 0x78, 0xb7, 0x95,
];

const BASE_POINT2_Y: [u8; 32] = [
    0x5d, 0x41, 0xac, 0x14, 0x77, 0x61, 0x4b, 0x5c, 0x08, 0x48, 0xd5, 0x0d, 0xbd, 0x56, 0x5e, 0xa2,
    0x80, 0x7b, 0xcb, 0xa1, 0xdf, 0x0d, 0xf0, 0x7a, 0x82, 0x17, 0xe9, 0xf7, 0xf7, 0xc2, 0xbe, 0x88,
];

use k256::Secp256k1;
// use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::ff::PrimeField;

lazy_static::lazy_static! {
    static ref BASE_POINT2_ENCODED: EncodedPoint<Secp256k1> = {
        let mut g = [0u8; 65];
        g[0] = 0x04;
        g[1..33].copy_from_slice(&BASE_POINT2_X);
        g[33..].copy_from_slice(&BASE_POINT2_Y);
        let res:EncodedPoint<Secp256k1> = EncodedPoint::<Secp256k1>::from_bytes(g).unwrap();
        res
    };

    static ref BASE_POINT2: AffinePoint = AffinePoint::from_encoded_point(&BASE_POINT2_ENCODED).unwrap();
}

#[test]
fn scalar_test() {
    let a: ScalarSelfDefined = ScalarTrait::random_scalar();
    let b: ScalarSelfDefined = ScalarTrait::random_scalar();

    let c1 = a.data * b.data;
    let c2 = a * b;
    assert_eq!(c1, c2.data);

    let c1 = a.data + b.data;
    let c2 = a + b;
    assert_eq!(c1, c2.data);

    let c1 = a.data - b.data;
    let c2 = a - b;
    assert_eq!(c1, c2.data);

    let c1 = -b.data;
    let c2 = -b;
    assert_eq!(c1, c2.data);
}

#[test]
fn point_test() {
    let g = PointSelfDefined::generator();

    let a: ScalarSelfDefined = ScalarTrait::random_scalar();
    let a_p: PointSelfDefined = a * g;
    let b: ScalarSelfDefined = ScalarTrait::random_scalar();
    let b_p: PointSelfDefined = b * g;
    let c: ScalarSelfDefined = ScalarTrait::random_scalar();
    let c_p: PointSelfDefined = c * g;

    let add = a + b + c;
    let c1 = add * g;
    let c2 = a_p + b_p + c_p;
    assert_eq!(c1, c2);
}

#[test]
fn point_zero_test() {
    let g = PointSelfDefined::generator();
    let inf_p = PointSelfDefined::default();

    assert_eq!(inf_p, inf_p + inf_p);

    let a: ScalarSelfDefined = ScalarTrait::zero();
    let a_p: PointSelfDefined = a * g;
    let b: ScalarSelfDefined = ScalarTrait::random_scalar();
    let b_p: PointSelfDefined = b * g;
    let c: ScalarSelfDefined = ScalarTrait::random_scalar();
    let c_p: PointSelfDefined = c * g;

    assert_eq!(a_p, inf_p);

    let add = a + b - c;

    let c1 = a * (add * g) * b;
    let c2 = a * (a_p + b_p - c_p) * b;
    assert_eq!(c1, c2);
}
