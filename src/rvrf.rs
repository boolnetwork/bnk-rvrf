use crate::one_out_of_many::*;
use crate::prf::{PRFPoof, PRFProver, PRFVerifier};
use crate::util::{fix_len_binary, number_to_binary};
use crate::util::{generate_pk, generate_sks, kronecker_delta, Com, Commitment, Secret};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use polynomials::*;
use zk_utils_test::{
    bytes_to_scalar, get_random_scalar, hash_to_scalar, point_to_bytes, scalar_to_bytes,
    BASEPOINT_G1, BASEPOINT_G2,
};

#[derive(Clone, Debug, Default)]
pub struct VRFStatement {
    pub pk_vec: Vec<RistrettoPoint>,
}

impl VRFStatement {
    pub fn new(amount: u64, r: Scalar) -> Self {
        let sks = generate_sks(amount);
        let pk_vec: Vec<RistrettoPoint> = sks
            .into_iter()
            .map(|sk| Com::commit_scalar_2(sk, r).comm.point)
            .collect();

        Self { pk_vec }
    }
}

pub fn generate_pks(amount: u64) -> Vec<RistrettoPoint> {
    let sks = generate_sks(amount);
    let pk_vec: Vec<RistrettoPoint> = sks.into_iter().map(|sk| generate_pk(sk)).collect();
    pk_vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Index;
    use std::time::{Duration, Instant};
    use serde_json;

    #[test]
    fn rvrf_bench_test() {
        for amount in 1..50{
            let mut total_prove = Duration::new(0, 0);
            let mut total_verify = Duration::new(0, 0);
            let samples = 10;
            for i in 0..samples{
                let l = 0;
                let witness = Witness::new(l);
                let r = witness.r;

                // 构造 输入参数
                let sks = generate_sks(amount);
                let pk_vec: Vec<RistrettoPoint> =
                    sks.clone().into_iter().map(|sk| generate_pk(sk)).collect();
                let sk_witness = sks[l as usize];
                let c = Com::commit_scalar_2(sk_witness, -r).comm.point;
                let pks: Vec<RistrettoPoint> = pk_vec.clone().into_iter().map(|each| each - c).collect();
                let statment: Statement = pks.into();
                //

                let crs = CRS::new(get_random_scalar(), r);
                let rr = get_random_scalar();

                let start = Instant::now();
                let prover = Prover::new(witness, statment.clone(), crs);
                let proof = prover.prove(vec![]); //todo!()
                let proof_prf = PRFProver::proof(sk_witness, rr, get_random_scalar(), -r, c);
                total_prove += start.elapsed();
                let len1 = serde_json::to_string(&proof).unwrap().len();
                let len2 = serde_json::to_string(&proof_prf).unwrap().len();
                println!("size:{:?}",len1+len2);

                let start = Instant::now();
                let verifier = Verifier::new(statment, crs);
                let result = verifier.verify(proof, vec![]);
                let proof_prf_result = PRFVerifier::verify(proof_prf, get_random_scalar(), rr);
                total_verify += start.elapsed();

                assert_eq!(result, true);
                assert_eq!(proof_prf_result, true);
            }
            let total_prove_avg = total_prove / samples;
            let total_verify_avg = total_verify / samples;
            println!("amount:{:?},prove:{:?},verify:{:?}",amount,total_prove_avg,total_verify_avg);

        }
    }

    #[test]
    fn rvrf_test() {
        let l = 6;
        let witness = Witness::new(l);
        let r = witness.r;
        let amount = 15;

        // 构造 输入参数
        let sks = generate_sks(amount);
        let pk_vec: Vec<RistrettoPoint> =
            sks.clone().into_iter().map(|sk| generate_pk(sk)).collect();
        let sk_witness = sks[l as usize];
        let c = Com::commit_scalar_2(sk_witness, -r).comm.point;
        let pks: Vec<RistrettoPoint> = pk_vec.clone().into_iter().map(|each| each - c).collect();
        let statment: Statement = pks.into();
        //

        let crs = CRS::new(get_random_scalar(), r);
        let rr = get_random_scalar();

        let prover = Prover::new(witness, statment.clone(), crs);
        let proof = prover.prove(vec![]); //todo!()
        let proof_prf = PRFProver::proof(sk_witness, rr, get_random_scalar(), -r, c);

        let verifier = Verifier::new(statment, crs);
        let result = verifier.verify(proof, vec![]);
        let proof_prf_result = PRFVerifier::verify(proof_prf, get_random_scalar(), rr);

        assert_eq!(result, true);
        assert_eq!(proof_prf_result, true);
    }

    #[test]
    fn ooom_test() {
        let l = 6;
        let witness = Witness::new(l);
        let r = witness.r;
        let amount = 8;
        let statment = Statement::new(amount, l, r);
        let crs = CRS::new(get_random_scalar(), r);

        let prover = Prover::new(witness, statment.clone(), crs);
        let proof = prover.prove(vec![]);

        let verifier = Verifier::new(statment, crs);
        let result = verifier.verify(proof, vec![]);
        assert_eq!(result, true);
    }
}
