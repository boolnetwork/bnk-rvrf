use crate::util::{fix_len_binary, number_to_binary};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use polynomials::*;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_scalar, get_random_scalar, hash_to_scalar, point_to_bytes, scalar_to_bytes,
    BASEPOINT_G1, BASEPOINT_G2,
};
use crate::util::{Com, Secret, Commitment, generate_sks, kronecker_delta};

use crate::one_out_of_many::*;

#[derive(Clone, Debug, Default)]
pub struct VRFStatement {
    pub pk_vec: Vec<RistrettoPoint>,
}

impl VRFStatement{
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Index;

    #[test]
    fn vrf_test() {

    }

    #[test]
    fn ooom_test() {
        let l = 6;
        let witness = Witness::new(l);
        let r = witness.r;
        let amount = 8;
        let statment = Statement::new(amount,l,r);
        let crs = CRS::new(get_random_scalar(),r);

        let prover = Prover::new(witness,statment.clone(),crs);
        let proof = prover.prove();

        let verifier = Verifier::new(statment,crs);
        let result = verifier.verify(proof);
        assert_eq!(result,true);
    }
}