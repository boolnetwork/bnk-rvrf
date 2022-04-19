use crate::util::{fix_len_binary, number_to_binary};
use crate::util::{generate_sks, hash_x, kronecker_delta, x_pow_n, Com, Commitment, Secret};
use crate::zero_or_one::{
    Proof as ZOProof, Prover as ZOProver, Verifier as ZOVerifier, CRS as ZOCRS,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use polynomials::*;
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use std::ops::Index;
use zk_utils_test::{
    bytes_to_scalar, get_random_scalar, hash_to_scalar, point_to_bytes, scalar_to_bytes,
    BASEPOINT_G1, BASEPOINT_G2,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct CRS {
    pub c: RistrettoPoint,
}

pub fn prf_h_2(input: Scalar) -> RistrettoPoint {
    *BASEPOINT_G1 * input
}

pub fn prf_h(input: Scalar) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha3_512>(input.as_bytes())
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PRFProver {}

#[derive(Copy, Clone, Debug, Default)]
pub struct PRFVerifier {}
impl PRFVerifier {
    pub fn verify(proof: PRFPoof, _x: Scalar, r: Scalar) -> bool {
        let PRFPoof {
            m1,
            m2,
            y1,
            y2,
            c,
            v,
        } = proof;
        let u = prf_h(r);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&m1));
        hash_vec.append(&mut point_to_bytes(&m2));
        let x = hash_to_scalar(&hash_vec);

        let g_y1_h_y2 = Com::commit_scalar_2(y1, y2).comm.point;
        let m1_c_x = m1 + c * x;
        assert_eq!(g_y1_h_y2, m1_c_x);
        let u_y1 = u * y1;
        let m2_v_c = m2 + v * x; //todo() v?
        assert_eq!(u_y1, m2_v_c);
        true
    }

    pub fn verify_with_hash(proof: PRFPoof, _x: Scalar, r: Scalar, hash: Scalar) -> bool {
        let PRFPoof {
            m1,
            m2,
            y1,
            y2,
            c,
            v,
        } = proof;
        let u = prf_h(r);
        let x = hash;

        let g_y1_h_y2 = Com::commit_scalar_2(y1, y2).comm.point;
        let m1_c_x = m1 + c * x;
        assert_eq!(g_y1_h_y2, m1_c_x);
        let u_y1 = u * y1;
        let m2_v_c = m2 + v * x; //todo() v?
        assert_eq!(u_y1, m2_v_c);
        true
    }
}

impl PRFProver {
    pub fn prove(sk: Scalar, r: Scalar, _x: Scalar, t: Scalar, c: RistrettoPoint) -> PRFPoof {
        let u = prf_h(r);

        let s_pie = get_random_scalar();
        let t_pie = get_random_scalar();

        let m1 = Com::commit_scalar_2(s_pie, t_pie).comm.point;
        let m2 = s_pie * u;

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&m1));
        hash_vec.append(&mut point_to_bytes(&m2));
        let x = hash_to_scalar(&hash_vec);

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

    pub fn prove_step_one(
        sk: Scalar,
        r: Scalar,
    ) -> (
        RistrettoPoint,
        RistrettoPoint,
        RistrettoPoint,
        Scalar,
        Scalar,
        Vec<Vec<u8>>,
    ) {
        let u = prf_h(r);

        let s_pie = get_random_scalar();
        let t_pie = get_random_scalar();

        let m1 = Com::commit_scalar_2(s_pie, t_pie).comm.point;
        let m2 = s_pie * u;

        let mut hash_vec: Vec<Vec<u8>> = Vec::new();
        hash_vec.push(point_to_bytes(&m1));
        hash_vec.push(point_to_bytes(&m2));

        (u, m1, m2, s_pie, t_pie, hash_vec)
    }

    pub fn prove_step_two(
        sk: Scalar,
        t: Scalar,
        c: RistrettoPoint,
        s_pie: Scalar,
        t_pie: Scalar,
        u: RistrettoPoint,
        m1: RistrettoPoint,
        m2: RistrettoPoint,
        hash: Scalar,
    ) -> PRFPoof {
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
}
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct PRFPoof {
    pub m1: RistrettoPoint,
    pub m2: RistrettoPoint,
    pub y1: Scalar,
    pub y2: Scalar,
    pub c: RistrettoPoint,
    pub v: RistrettoPoint,
}

impl PRFPoof {
    pub fn get_v(self) -> RistrettoPoint {
        self.v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zero_or_one::Verifier;
    use std::ops::Index;

    #[test]
    fn p_test() {
        let sk = get_random_scalar();
        let r = get_random_scalar();
        let x = get_random_scalar();
        let u = prf_h(r);

        let t = get_random_scalar();

        let s_pie = get_random_scalar();
        let t_pie = get_random_scalar();

        let m1 = Com::commit_scalar_2(s_pie, t_pie).comm.point;
        let m2 = s_pie * u;
        let y1 = s_pie + sk * x;
        let y2 = t_pie + t * x;
        let c = Com::commit_scalar_2(sk, t).comm.point;

        let proof = PRFProver::prove(sk, r, x, t, c);
        let result = PRFVerifier::verify(proof, x, r);
        assert_eq!(result, true);
    }

    #[test]
    fn prf_test() {
        let sk = get_random_scalar();
        let r = get_random_scalar();
        let x = get_random_scalar();
        let u = prf_h(r);

        let t = get_random_scalar();

        let s_pie = get_random_scalar();
        let t_pie = get_random_scalar();

        let m1 = Com::commit_scalar_2(s_pie, t_pie).comm.point;
        let m2 = s_pie * u;
        let y1 = s_pie + sk * x;
        let y2 = t_pie + t * x;

        let v = sk * u; // todo()
        let c = Com::commit_scalar_2(sk, t).comm.point;

        let g_y1_h_y2 = Com::commit_scalar_2(y1, y2).comm.point;
        let m1_c_x = m1 + c * x;
        assert_eq!(g_y1_h_y2, m1_c_x);
        let u_y1 = u * y1;
        let m2_v_c = m2 + v * x;
        assert_eq!(u_y1, m2_v_c);
    }

    #[test]
    fn curve25519_sk_pk_ed25519_test() {
        use ed25519_dalek::Keypair;
        use ed25519_dalek::Signature;
        use ed25519_dalek::{Signer, Verifier};

        let sk = get_random_scalar();
        let pk = RistrettoPoint::multiscalar_mul([sk], &[*BASEPOINT_G1]).compress();

        let mut pair:[u8; 64] = [0u8; 64];
        pair[0..32].copy_from_slice(sk.as_bytes());
        pair[32..].copy_from_slice(pk.as_bytes());
        let key_pair = Keypair::from_bytes(&pair).unwrap();
        let message: &[u8] = b"This is a test of the tsunami alert system.";
        let signature = key_pair.sign(message);
        // TODO fix
        assert!(key_pair.verify(message, &signature).is_ok());
    }
}
