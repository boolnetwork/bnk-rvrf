#![allow(clippy::many_single_char_names)]
use crate::traits::{PointTrait, ScalarTrait};
use crate::util::Com;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Mul;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Default)]
pub struct CRS<S: ScalarTrait, P: PointTrait> {
    pub c: P,
    pub ph: PhantomData<S>,
}

pub fn prf_h_2<S: ScalarTrait, P: PointTrait>(input: S) -> P {
    P::hash_to_point(&input.bytes())
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PRFProver<S: ScalarTrait, P: PointTrait> {
    pub ph: PhantomData<S>,
    pub ph2: PhantomData<P>,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PRFVerifier<S: ScalarTrait, P: PointTrait> {
    pub ph: PhantomData<S>,
    pub ph2: PhantomData<P>,
}
impl<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>> PRFVerifier<S, P> {
    pub fn verify(proof: PRFPoof<S, P>, _x: S, r: S) -> bool {
        let PRFPoof {
            m1,
            m2,
            y1,
            y2,
            c,
            v,
        } = proof;
        let u = Self::prf_h_2(r);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut P::point_to_bytes(&m1));
        hash_vec.append(&mut P::point_to_bytes(&m2));
        let x = S::hash_to_scalar(&hash_vec);

        let g_y1_h_y2 = Com::<S, P>::commit_scalar_2(y1, y2).comm.point;
        let m1_c_x = m1 + c * x;
        assert_eq!(g_y1_h_y2, m1_c_x);
        let u_y1 = u * y1;
        let m2_v_c = m2 + v * x; //todo() v?
        assert_eq!(u_y1, m2_v_c);
        true
    }

    pub fn verify_with_hash(proof: PRFPoof<S, P>, _x: S, r: S, hash: S) -> bool {
        let PRFPoof {
            m1,
            m2,
            y1,
            y2,
            c,
            v,
        } = proof;
        let u = Self::prf_h_2(r);
        let x = hash;

        let g_y1_h_y2 = Com::<S, P>::commit_scalar_2(y1, y2).comm.point;
        let m1_c_x = m1 + c * x;
        assert_eq!(g_y1_h_y2, m1_c_x);
        let u_y1 = u * y1;
        let m2_v_c = m2 + v * x; //todo() v?
        assert_eq!(u_y1, m2_v_c);
        true
    }

    pub fn prf_h_2(input: S) -> P {
        P::hash_to_point(&input.bytes())
    }
}
#[cfg(feature = "prove")]
impl<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>> PRFProver<S, P> {
    pub fn prove(sk: S, r: S, _x: S, t: S, c: P) -> PRFPoof<S, P> {
        let u = Self::prf_h_2(r);

        let s_pie = S::random_scalar();
        let t_pie = S::random_scalar();

        let m1 = Com::commit_scalar_2(s_pie, t_pie).comm.point;
        let m2 = s_pie * u;

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut P::point_to_bytes(&m1));
        hash_vec.append(&mut P::point_to_bytes(&m2));
        let x = S::hash_to_scalar(&hash_vec);

        let y1 = s_pie + sk * x;
        let y2 = t_pie + t * x;

        let v = sk * u;
        PRFPoof {
            m1,
            m2,
            y1,
            y2,
            c,
            v,
        }
    }

    pub fn prove_step_one(_sk: S, r: S) -> (P, P, P, S, S, Vec<Vec<u8>>) {
        let u = Self::prf_h_2(r);

        let s_pie = S::random_scalar();
        let t_pie = S::random_scalar();

        let m1 = Com::commit_scalar_2(s_pie, t_pie).comm.point;
        let m2 = s_pie * u;

        let mut hash_vec: Vec<Vec<u8>> = Vec::new();
        hash_vec.push(P::point_to_bytes(&m1));
        hash_vec.push(P::point_to_bytes(&m2));

        (u, m1, m2, s_pie, t_pie, hash_vec)
    }

    pub fn prove_step_two(
        sk: S,
        t: S,
        c: P,
        s_pie: S,
        t_pie: S,
        u: P,
        m1: P,
        m2: P,
        hash: S,
    ) -> PRFPoof<S, P> {
        let x = hash;

        let y1 = s_pie + sk * x;
        let y2 = t_pie + t * x;

        let v = sk * u;
        PRFPoof {
            m1,
            m2,
            y1,
            y2,
            c,
            v,
        }
    }

    pub fn prf_h_2(input: S) -> P {
        P::hash_to_point(&input.bytes())
    }
}
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct PRFPoof<S: ScalarTrait, P: PointTrait> {
    pub m1: P,
    pub m2: P,
    pub y1: S,
    pub y2: S,
    pub c: P,
    pub v: P,
}

impl<S: ScalarTrait, P: PointTrait> PRFPoof<S, P> {
    pub fn get_v(self) -> P {
        self.v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ed25519::{PointSelfDefined, ScalarSelfDefined};
    #[test]
    fn p_test() {
        let sk = ScalarSelfDefined::random_scalar();
        let r = ScalarSelfDefined::random_scalar();
        let x = ScalarSelfDefined::random_scalar();
        let u = prf_h_2::<ScalarSelfDefined, PointSelfDefined>(r);

        let t = ScalarSelfDefined::random_scalar();

        let s_pie = ScalarSelfDefined::random_scalar();
        let t_pie = ScalarSelfDefined::random_scalar();

        let _m1 = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(s_pie, t_pie)
            .comm
            .point;
        let _m2 = s_pie * u;
        let _y1 = s_pie + sk * x;
        let _y2 = t_pie + t * x;
        let c = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(sk, t)
            .comm
            .point;

        let proof = PRFProver::prove(sk, r, x, t, c);
        let result = PRFVerifier::verify(proof, x, r);
        assert_eq!(result, true);
    }

    #[test]
    fn prf_test() {
        let sk = ScalarSelfDefined::random_scalar();
        let r = ScalarSelfDefined::random_scalar();
        let x = ScalarSelfDefined::random_scalar();
        let u = prf_h_2::<ScalarSelfDefined, PointSelfDefined>(r);

        let t = ScalarSelfDefined::random_scalar();

        let s_pie = ScalarSelfDefined::random_scalar();
        let t_pie = ScalarSelfDefined::random_scalar();

        let m1 = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(s_pie, t_pie)
            .comm
            .point;
        let m2 = s_pie * u;
        let y1 = s_pie + sk * x;
        let y2 = t_pie + t * x;

        let v = sk * u; // todo()
        let c = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(sk, t)
            .comm
            .point;

        let g_y1_h_y2 = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(y1, y2)
            .comm
            .point;
        let m1_c_x = m1 + c * x;
        assert_eq!(g_y1_h_y2, m1_c_x);
        let u_y1 = u * y1;
        let m2_v_c = m2 + v * x;
        assert_eq!(u_y1, m2_v_c);
    }

    #[test]
    fn curve25519_sk_pk_ed25519_test() {
        use crate::ed25519::ScalarSelfDefined;

        use ed25519_dalek::{Keypair, PublicKey, SecretKey};
        use ed25519_dalek::{Signer, Verifier};

        let sk = ScalarSelfDefined::random_scalar();

        let sk = SecretKey::from_bytes(&sk.bytes()).unwrap();
        let pk: PublicKey = (&sk).into();

        let key_pair = Keypair {
            secret: sk,
            public: pk,
        };

        let message: &[u8] = b"This is a test of the tsunami alert system.";
        let signature = key_pair.sign(message);
        // TODO fix
        assert!(key_pair.verify(message, &signature).is_ok());
    }
}
