use crate::util::Com;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};
#[cfg(feature = "prove")]
use zk_utils_test::get_random_scalar;
use zk_utils_test::{hash_to_scalar, point_to_bytes, BASEPOINT_G1, BASEPOINT_G2};

use alloc::vec::Vec;

use crate::traits::{ScalarTrait, PointTrait, ScalarSelfDefined, PointSelfDefined};
use core::ops::Mul;
use core::marker::PhantomData;

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct CRS<S:ScalarTrait,P:PointTrait> {
    pub c: P,
    pub ph: PhantomData<S>,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Prover<S:ScalarTrait,P:PointTrait> {
    pub crs: CRS<S, P>,
    pub m: S,
    pub r: S,
}

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct Proof<S:ScalarTrait,P:PointTrait> {
    pub ca: P,
    pub cb: P,
    pub f: S,
    pub za: S,
    pub zb: S,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Verifier<S:ScalarTrait,P:PointTrait> {
    pub crs: CRS<S,P>,
}
#[cfg(feature = "prove")]
impl <S:ScalarTrait + Mul<P, Output = P> , P: PointTrait + Mul<S, Output = P>>CRS<S,P> {
    pub fn new(m: S, r: S) -> Self {
        Self {
            c: Com::<S,P>::commit_scalar_2(m, r).comm.point,
            ph: Default::default()
        }
    }
}
#[cfg(feature = "prove")]
impl <S:ScalarTrait + Mul<P, Output = P> , P: PointTrait + Mul<S, Output = P>>Prover<S, P> {
    pub fn new(m: S) -> Prover<S, P> {
        let r = S::random_scalar();
        Prover {
            crs: CRS::new(m, r),
            m,
            r: r,
        }
    }

    pub fn proof_with_a(self) -> (Proof<S, P>, S) {
        let m = self.m.clone();
        let r = self.r.clone();
        let a = S::random_scalar();
        let s = S::random_scalar();
        let t = S::random_scalar();

        let ca = Com::<S,P>::commit_scalar_2(a, s);
        let cb = Com::<S,P>::commit_scalar_2(a * m, t);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut P::generator().point_to_bytes());
        hash_vec.append(&mut P::generator_2().point_to_bytes());
        hash_vec.append(&mut ca.comm.point.point_to_bytes());
        hash_vec.append(&mut cb.comm.point.point_to_bytes());

        let x = S::hash_to_scalar(&hash_vec);
        let f = m * x + a;
        (
            Proof {
                ca: ca.comm.point,
                cb: cb.comm.point,
                f: f,
                za: r * x + s,
                zb: r * (x - f) + t,
            },
            a,
        )
    }

    #[allow(dead_code)]
    pub fn proof(self) -> Proof<S, P> {
        let m = self.m.clone();
        let r = self.r.clone();
        let a = S::random_scalar();
        let s = S::random_scalar();
        let t = S::random_scalar();

        let ca = Com::<S,P>::commit_scalar_2(a, s);
        let cb = Com::<S,P>::commit_scalar_2(a * m, t);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut P::generator().point_to_bytes());
        hash_vec.append(&mut P::generator_2().point_to_bytes());
        hash_vec.append(&mut ca.comm.point.point_to_bytes());
        hash_vec.append(&mut cb.comm.point.point_to_bytes());

        let x = S::hash_to_scalar(&hash_vec);
        let f = m * x + a;
        Proof {
            ca: ca.comm.point,
            cb: cb.comm.point,
            f: f,
            za: r * x + s,
            zb: r * (x - f) + t,
        }
    }
}

impl <S:ScalarTrait + Mul<P, Output = P> , P: PointTrait + Mul<S, Output = P>>Verifier<S,P> {
    pub fn new(crs: CRS<S, P>) -> Verifier<S,P> {
        Self { crs }
    }

    pub fn verify(self, proof: Proof<S, P>) -> bool {
        let Proof { ca, cb, f, za, zb } = proof;
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut P::generator().point_to_bytes());
        hash_vec.append(&mut P::generator_2().point_to_bytes());
        hash_vec.append(&mut ca.point_to_bytes());
        hash_vec.append(&mut cb.point_to_bytes());

        let x = S::hash_to_scalar(&hash_vec);
        let c = self.crs.c.clone();

        let left_1 = c * x + ca;
        let right_1 = Com::<S,P>::commit_scalar_2(f, za).comm.point;

        let left_2 = c * (x - f) + cb;
        let right_2 = Com::<S,P>::commit_scalar_2(S::zero(), zb).comm.point;

        if left_1 == right_1 && left_2 == right_2 {
            return true;
        } else {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Index;
    use p256::AffinePoint;
    use p256::elliptic_curve::sec1::EncodedPoint;

    #[test]
    fn zero_or_one_raw_test() {
        // proof
        let m:ScalarSelfDefined = ScalarTrait::one();
        let r:ScalarSelfDefined = ScalarTrait::random_scalar();
        let a:ScalarSelfDefined = ScalarTrait::random_scalar();
        let s:ScalarSelfDefined = ScalarTrait::random_scalar();
        let t:ScalarSelfDefined = ScalarTrait::random_scalar();

        let c = Com::<ScalarSelfDefined,PointSelfDefined>::commit_scalar_2(m, r).comm.point;
        let ca = Com::<ScalarSelfDefined,PointSelfDefined>::commit_scalar_2(a, s);
        let cb = Com::<ScalarSelfDefined,PointSelfDefined>::commit_scalar_2(a * m, t);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut PointSelfDefined::generator().point_to_bytes());
        hash_vec.append(&mut PointSelfDefined::generator_2().point_to_bytes());
        hash_vec.append(&mut ca.comm.point.point_to_bytes());
        hash_vec.append(&mut cb.comm.point.point_to_bytes());

        let x:ScalarSelfDefined = ScalarTrait::hash_to_scalar(&hash_vec);

        let f = m * x + a;
        let ca = ca.comm.point;
        let cb = cb.comm.point;
        let f = f;
        let za = r * x + s;
        let zb = r * (x - f) + t;

        // verify
        let left_1 = c * x + ca;
        let right_1 = Com::<ScalarSelfDefined,PointSelfDefined>::commit_scalar_2(f, za).comm.point;

        let left_2 = c * (x - f) + cb;
        let right_2 = Com::<ScalarSelfDefined,PointSelfDefined>::commit_scalar_2(ScalarSelfDefined::zero(), zb).comm.point;
        //  let right_2 = Com::<ScalarSelfDefined,PointSelfDefined>::commit_scalar_3(ScalarSelfDefined::zero(), zb).comm.point;

        assert_eq!(left_1, right_1);
        assert_eq!(left_2, right_2);
    }

    #[test]
    fn zero_test(){
        use p256::ProjectivePoint;
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        let a: ScalarSelfDefined = ScalarTrait::zero();
        let b: PointSelfDefined = PointTrait::generator_2();
        let aa = &EncodedPoint::from((a * b).data);
        let bb = AffinePoint::from_encoded_point(aa).unwrap();
        let cc = ProjectivePoint::from(bb);
    }


    #[test]
    fn zero_or_one_test() {
        let m:ScalarSelfDefined = ScalarTrait::zero();
        let p = Prover::<ScalarSelfDefined,PointSelfDefined>::new(m);

        let proof = p.proof();

        let v = Verifier::new(p.crs);
        let res = v.verify(proof);
        assert_eq!(res, true);
    }
}
