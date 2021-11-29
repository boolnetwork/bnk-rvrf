use crate::util::{fix_len_binary, number_to_binary};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use polynomials::*;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_scalar, get_random_scalar, hash_to_scalar, point_to_bytes, scalar_to_bytes,
    BASEPOINT_G1, BASEPOINT_G2,
};
use crate::util::{Com, Secret, Commitment, generate_sks, kronecker_delta};

#[derive(Clone, Debug, Default)]
pub struct Statement {
    pub pk_vec: Vec<RistrettoPoint>,
}

impl Statement{
    pub fn new(amount:u64,r:Scalar) -> Self{
        let sks= generate_sks(amount);
        let pk_vec: Vec<RistrettoPoint> = sks
            .into_iter()
            .map(|sk| Com::commit_scalar_2(sk,r).comm.point )
            .collect();

        Self{
            pk_vec,
        }
    }
}