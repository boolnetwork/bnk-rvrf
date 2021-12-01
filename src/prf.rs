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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Index;

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

        let v = sk * u;
        let c = Com::commit_scalar_2(sk,t).comm.point;

        let g_y1_h_y2 = Com::commit_scalar_2(y1,y2).comm.point;
        let m1_c_x = m1 + c * x;
        assert_eq!(g_y1_h_y2,m1_c_x);
        let u_y1 = u * y1;
        let m2_v_c = m2 + v*x;
        assert_eq!(u_y1,m2_v_c);
    }
}