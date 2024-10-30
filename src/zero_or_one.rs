// This file is part of BoolNetwork.

// Copyright (C) BoolNetwork (HK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(clippy::many_single_char_names)]

use crate::traits::{PointTrait, ScalarTrait};
use crate::util::Com;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Mul;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct CRS<S: ScalarTrait, P: PointTrait> {
    pub c: P,
    pub ph: PhantomData<S>,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Prover<S: ScalarTrait, P: PointTrait> {
    pub crs: CRS<S, P>,
    pub m: S,
    pub r: S,
}

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct Proof<S: ScalarTrait, P: PointTrait> {
    pub ca: P,
    pub cb: P,
    pub f: S,
    pub za: S,
    pub zb: S,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Verifier<S: ScalarTrait, P: PointTrait> {
    pub crs: CRS<S, P>,
}
#[cfg(feature = "prove")]
impl<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>> CRS<S, P> {
    pub fn new(m: S, r: S) -> Self {
        Self {
            c: Com::<S, P>::commit_scalar_with(m, r).comm.point,
            ph: Default::default(),
        }
    }
}

#[cfg(feature = "prove")]
impl<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>> Prover<S, P> {
    pub fn new(m: S) -> Prover<S, P> {
        let r = S::random_scalar();
        Prover {
            crs: CRS::new(m, r),
            m,
            r,
        }
    }

    pub fn proof_with_a(self) -> (Proof<S, P>, S) {
        let m = self.m;
        let r = self.r;
        let a = S::random_scalar();
        let s = S::random_scalar();
        let t = S::random_scalar();

        let ca = Com::<S, P>::commit_scalar_with(a, s);
        let cb = Com::<S, P>::commit_scalar_with(a * m, t);

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
                f,
                za: r * x + s,
                zb: r * (x - f) + t,
            },
            a,
        )
    }

    #[allow(dead_code)]
    pub fn proof(self) -> Proof<S, P> {
        let m = self.m;
        let r = self.r;
        let a = S::random_scalar();
        let s = S::random_scalar();
        let t = S::random_scalar();

        let ca = Com::<S, P>::commit_scalar_with(a, s);
        let cb = Com::<S, P>::commit_scalar_with(a * m, t);

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
            f,
            za: r * x + s,
            zb: r * (x - f) + t,
        }
    }
}

impl<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>> Verifier<S, P> {
    pub fn new(crs: CRS<S, P>) -> Verifier<S, P> {
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
        let c = self.crs.c;

        let left_1 = c * x + ca;
        let right_1 = Com::<S, P>::commit_scalar_with(f, za).comm.point;

        let left_2 = c * (x - f) + cb;
        let right_2 = Com::<S, P>::commit_scalar_with(S::zero(), zb).comm.point;

        left_1 == right_1 && left_2 == right_2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::{PointType, ScalarType};

    #[cfg(feature = "pk256")]
    use p256::elliptic_curve::sec1::EncodedPoint;
    #[cfg(feature = "pk256")]
    use p256::AffinePoint;

    #[test]
    fn zero_or_one_raw_test() {
        // proof
        let m: ScalarType = ScalarTrait::one();
        let r: ScalarType = ScalarTrait::random_scalar();
        let a: ScalarType = ScalarTrait::random_scalar();
        let s: ScalarType = ScalarTrait::random_scalar();
        let t: ScalarType = ScalarTrait::random_scalar();

        let c = Com::<ScalarType, PointType>::commit_scalar_with(m, r)
            .comm
            .point;
        let ca = Com::<ScalarType, PointType>::commit_scalar_with(a, s);
        let cb = Com::<ScalarType, PointType>::commit_scalar_with(a * m, t);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut PointType::generator().point_to_bytes());
        hash_vec.append(&mut PointType::generator_2().point_to_bytes());
        hash_vec.append(&mut ca.comm.point.point_to_bytes());
        hash_vec.append(&mut cb.comm.point.point_to_bytes());

        let x: ScalarType = ScalarTrait::hash_to_scalar(&hash_vec);

        let f = m * x + a;
        let ca = ca.comm.point;
        let cb = cb.comm.point;
        let f = f;
        let za = r * x + s;
        let zb = r * (x - f) + t;

        // verify
        let left_1 = c * x + ca;
        let right_1 = Com::<ScalarType, PointType>::commit_scalar_with(f, za)
            .comm
            .point;

        let left_2 = c * (x - f) + cb;
        let right_2 = Com::<ScalarType, PointType>::commit_scalar_with(ScalarType::zero(), zb)
            .comm
            .point;
        //  let right_2 = Com::<ScalarType,PointType>::commit_scalar_3(ScalarType::zero(), zb).comm.point;

        assert_eq!(left_1, right_1);
        assert_eq!(left_2, right_2);
    }

    // #[cfg(feature = "pk256")]
    // #[ignore]
    // #[test]
    // fn zero_test() {
    //     use p256::elliptic_curve::sec1::FromEncodedPoint;
    //     use p256::ProjectivePoint;
    //
    //     let a: ScalarType = ScalarTrait::zero();
    //     let b: PointType = PointTrait::generator_2();
    //     let aa = &EncodedPoint::from((a * b).data);
    //     let bb = AffinePoint::from_encoded_point(aa).unwrap();
    //     let _cc = ProjectivePoint::from(bb);
    // }

    #[cfg(feature = "pk256")]
    #[test]
    fn zero_or_one_p256_test() {
        let m: ScalarType = ScalarTrait::zero();
        let p = Prover::<ScalarType, PointType>::new(m);

        let proof = p.proof();

        let v = Verifier::new(p.crs);
        let res = v.verify(proof);
        assert_eq!(res, true);
    }

    #[test]
    fn zero_or_one_ed25519_test() {
        use crate::ed25519::{PointType, ScalarType};
        let m: ScalarType = ScalarTrait::zero();
        let p = Prover::<ScalarType, PointType>::new(m);

        let proof = p.proof();

        let v = Verifier::new(p.crs);
        let res = v.verify(proof);
        assert_eq!(res, true);
    }

    #[cfg(feature = "pk256")]
    #[test]
    fn zero_or_one_secp256k1_test() {
        use crate::secp256k1::{PointType, ScalarType};
        let m: ScalarType = ScalarTrait::zero();
        let p = Prover::<ScalarType, PointType>::new(m);

        let proof = p.proof();

        let v = Verifier::new(p.crs);
        let res = v.verify(proof);
        assert_eq!(res, true);
    }
}
