use p256::{Scalar, NonZeroScalar};
use p256::{AffinePoint, FieldBytes};
use rand_core::OsRng;

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, Neg, SubAssign};
use p256::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::Field;
use p256::ProjectivePoint;
use crate::traits::{ScalarTrait, PointTrait, HASH, Hash};

use alloc::vec::Vec;
use core::convert::TryFrom;

pub fn algorithms_trait_prove<T: ScalarTrait + Copy, K: PointTrait + Copy + Mul<T>>(
    input: T,
    input2: T,
    input3: K,
    input4: K,
) {
    let mut data = T::random_scalar();
    data += input;
    let _ = input + input2;
    let _ = input - input2;
    let _ = input * input2;
    let _ = input3 - input4;
    input3 * input2;
}

pub fn algorithms_type_prove(
    input: ScalarSelfDefined,
    input2: ScalarSelfDefined,
    input3: PointSelfDefined,
    input4: PointSelfDefined,
) {
    let mut data = ScalarSelfDefined::random_scalar();
    data += input;
    let _ = input + input2;
    let _ = input - input2;
    let _ = input * input2;
    let _ = input3 - input4;
    input3 * input2;
    input2 * input3;
}

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
            data: (&self.data).mul(&rhs.data),
        };
    }
}

impl AddAssign<ScalarSelfDefined> for ScalarSelfDefined {
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
        ScalarSelfDefined {
            data: (&self.data).sub(&other.data),
        }
    }
}

impl<'o> Sub<&'o ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn sub(self, other: &'o ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: (&self.data).sub(&other.data),
        }
    }
}

impl Neg for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn neg(self) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: (Self::zero().data).sub(&self.data),
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

    fn get_self(&self) -> Self {
        self.clone()
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
        PointSelfDefined {
            data: AffinePoint::default(),
        }
    }

    fn generator() -> PointSelfDefined {
        PointSelfDefined {
            data: AffinePoint::generator(),
        }
    }

    fn generator_2() -> Self {
        PointSelfDefined {
            data: AffinePoint::generator(),
        }
    }

    fn point_to_bytes(&self) -> Vec<u8> {
        self.data.to_encoded_point(true).as_ref().to_vec()
    }

    // fn default() -> Self {
    //     PointSelfDefined{
    //         data:AffinePoint::generator()
    //     }
    // }
}

// ======================
#[test]
fn trait_type_test() {
    algorithms_trait_prove(
        ScalarSelfDefined::random_scalar(),
        ScalarSelfDefined::random_scalar(),
        PointSelfDefined::generator(),
        PointSelfDefined::generator(),
    );
    algorithms_type_prove(
        ScalarSelfDefined::random_scalar(),
        ScalarSelfDefined::random_scalar(),
        PointSelfDefined::generator(),
        PointSelfDefined::generator(),
    );
}

#[test]
fn cal_test() {
    let a: ScalarSelfDefined = ScalarTrait::random_scalar();
    let b: ScalarSelfDefined = ScalarTrait::random_scalar();
    let c1 = a.data.mul(&b.get_self().data);
    let c2 = a * b;
    assert_eq!(c1, c2.data);

    let a: ScalarSelfDefined = ScalarTrait::random_scalar();
    let b: ScalarSelfDefined = ScalarTrait::random_scalar();
    let c1 = a.data.add(&b.get_self().data);
    let c2 = a + b;
    assert_eq!(c1, c2.data);

    let a: ScalarSelfDefined = ScalarTrait::random_scalar();
    let a_p: PointSelfDefined = a * PointSelfDefined::generator();
    let b: ScalarSelfDefined = ScalarTrait::random_scalar();
    let b_p: PointSelfDefined = b * PointSelfDefined::generator();

    let add = a + b;
    let c1 = add * PointSelfDefined::generator();
    let c2 = a_p + b_p;
    assert_eq!(c1, c2);
}