use crate::util::{fix_len_binary, number_to_binary};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use polynomials::*;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_scalar, get_random_scalar, hash_to_scalar, point_to_bytes, scalar_to_bytes,
    BASEPOINT_G1, BASEPOINT_G2,
};
use crate::util::{Com, Secret, Commitment, generate_sks, kronecker_delta, hash_x, x_pow_n};
use crate::zero_or_one::{Prover as ZOProver, CRS as ZOCRS, Proof as ZOProof, Verifier as ZOVerifier};
use std::ops::Index;


#[derive(Copy, Clone, Debug, Default)]
pub struct CRS {
    pub c: RistrettoPoint,
}

pub fn prf_h(input:Scalar) -> RistrettoPoint{
    *BASEPOINT_G1 * input
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PRFProver{
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PRFVerifier{
}
impl PRFVerifier {
    pub fn verify(proof:PRFPoof, _x:Scalar, r:Scalar) -> bool{
        let PRFPoof{m1, m2, y1, y2, c,v} = proof;
        let u = prf_h(r);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&m1));
        hash_vec.append(&mut point_to_bytes(&m2));
        let x = hash_to_scalar(&hash_vec);

        let g_y1_h_y2 = Com::commit_scalar_2(y1,y2).comm.point;
        let m1_c_x = m1 + c * x;
        assert_eq!(g_y1_h_y2,m1_c_x);
        let u_y1 = u * y1;
        let m2_v_c = m2 + v*x;  //todo() v?
        assert_eq!(u_y1,m2_v_c);
        true
    }
}
impl PRFProver {
    pub fn proof(sk:Scalar, r:Scalar, _x:Scalar, t:Scalar, c:RistrettoPoint) -> PRFPoof{
        let u = prf_h(r);

        let s_pie = get_random_scalar();
        let t_pie = get_random_scalar();

        let m1 = Com::commit_scalar_2(s_pie,t_pie).comm.point;
        let m2 = s_pie * u;

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&m1));
        hash_vec.append(&mut point_to_bytes(&m2));
        let x = hash_to_scalar(&hash_vec);

        let y1 = s_pie + sk * x;
        let y2 = t_pie + t * x;

        let v = sk * u;
        PRFPoof{
            m1,
            m2,
            y1,
            y2,
            c,
            v
        }
    }
}
#[derive(Copy, Clone, Debug, Default)]
pub struct PRFPoof{
    pub m1: RistrettoPoint,
    pub m2: RistrettoPoint,
    pub y1: Scalar,
    pub y2: Scalar,
    pub c: RistrettoPoint,
    pub v: RistrettoPoint
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Index;
    use crate::zero_or_one::Verifier;

    #[test]
    fn p_test() {
        let sk = get_random_scalar();
        let r = get_random_scalar();
        let x =get_random_scalar();
        let u = prf_h(r);

        let t = get_random_scalar();

        let s_pie = get_random_scalar();
        let t_pie = get_random_scalar();

        let m1 = Com::commit_scalar_2(s_pie,t_pie).comm.point;
        let m2 = s_pie * u;
        let y1 = s_pie + sk * x;
        let y2 = t_pie + t * x;
        let c = Com::commit_scalar_2(sk,t).comm.point;

        let proof = PRFProver::proof(sk,r,x,t,c);
        let result = PRFVerifier::verify(proof, x, r);
        assert_eq!(result,true);
    }

    #[test]
    fn prf_test() {
        let sk = get_random_scalar();
        let r = get_random_scalar();
        let x =get_random_scalar();
        let u = prf_h(r);

        let t = get_random_scalar();

        let s_pie = get_random_scalar();
        let t_pie = get_random_scalar();

        let m1 = Com::commit_scalar_2(s_pie,t_pie).comm.point;
        let m2 = s_pie * u;
        let y1 = s_pie + sk * x;
        let y2 = t_pie + t * x;

        let v = sk * u; // todo()
        let c = Com::commit_scalar_2(sk,t).comm.point;

        let g_y1_h_y2 = Com::commit_scalar_2(y1,y2).comm.point;
        let m1_c_x = m1 + c * x;
        assert_eq!(g_y1_h_y2,m1_c_x);
        let u_y1 = u * y1;
        let m2_v_c = m2 + v*x;
        assert_eq!(u_y1,m2_v_c);
    }
}