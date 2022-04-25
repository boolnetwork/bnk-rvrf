use crate::traits::{Hash, PointTrait, ScalarTrait, HASH};
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use rand_core::OsRng;

use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use sha3::Sha3_512;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScalarSelfDefined {
    pub data: Scalar,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PointSelfDefined {
    pub data: RistrettoPoint,
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

    fn random_scalar() -> Self {
        let mut csprng = OsRng;
        ScalarSelfDefined {
            data: Scalar::random(&mut csprng),
        }
    }

    fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        let mut array = [0; 32];
        array.clone_from_slice(&HASH.hash(input));
        ScalarSelfDefined {
            data: Scalar::from_bytes_mod_order(array),
        }
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
        self.data.as_bytes().to_vec()
    }
}

// ============

impl Mul<ScalarSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, scalar: ScalarSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data * scalar.data,
        }
    }
}

impl Mul<&ScalarSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, scalar: &ScalarSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data * scalar.data,
        }
    }
}

impl Mul<PointSelfDefined> for ScalarSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, point: PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data * point.data,
        }
    }
}

impl Mul<&PointSelfDefined> for ScalarSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, point: &PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data * point.data,
        }
    }
}

// ==============

impl AddAssign<PointSelfDefined> for PointSelfDefined {
    fn add_assign(&mut self, rhs: PointSelfDefined) {
        *self = PointSelfDefined {
            data: self.data + rhs.data,
        };
    }
}

impl Add<PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn add(self, other: PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data + other.data,
        }
    }
}

impl Sub<PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn sub(self, other: PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data - other.data,
        }
    }
}

impl<'o> Sub<&'o PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn sub(self, other: &'o PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data - other.data,
        }
    }
}

impl SubAssign for PointSelfDefined {
    fn sub_assign(&mut self, other: PointSelfDefined) {
        *self = PointSelfDefined {
            data: self.data - other.data,
        };
    }
}

impl PointTrait for PointSelfDefined {
    fn hash_to_point<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        PointSelfDefined {
            data: RistrettoPoint::hash_from_bytes::<Sha3_512>(input.as_ref()),
        }
    }

    fn generator() -> PointSelfDefined {
        PointSelfDefined {
            data: RISTRETTO_BASEPOINT_POINT,
        }
    }

    fn generator_2() -> Self {
        PointSelfDefined {
            data: RistrettoPoint::hash_from_bytes::<Sha3_512>(
                RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            ),
        }
    }

    fn point_to_bytes(&self) -> Vec<u8> {
        self.data.compress().to_bytes().to_vec()
    }
}
