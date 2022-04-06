use crate::one_out_of_many::*;
use crate::prf::{PRFPoof, PRFProver, PRFVerifier};
use crate::util::{fix_len_binary, number_to_binary};
use crate::util::{generate_pk, generate_sks, kronecker_delta, Com, Commitment, Secret};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use polynomials::*;
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RVRFProof {
    pub m1: RistrettoPoint,
    pub m2: RistrettoPoint,
    pub proof: Proof,
    pub proof_prf: PRFPoof,
    pub c: RistrettoPoint
}

pub fn rvrf_prove(
    witness: Witness,
    statment: Statement,
    rr: Scalar,
    r: Scalar,
    c: RistrettoPoint,
    sk: Scalar,
) -> RVRFProof {
    let crs = CRS::new(get_random_scalar(), get_random_scalar());
    let sk_witness = sk;
    let (u, m1, m2, s_pie, t_pie, hash_vec) = PRFProver::prove_step_one(sk_witness, rr);
    let prover = Prover::new(witness, statment.clone(), crs);
    let (proof, hash) = prover.prove_return_hash(hash_vec.clone());
    let proof_prf = PRFProver::prove_step_two(sk_witness, -r, c, s_pie, t_pie, u, m1, m2, hash);
    RVRFProof {
        m1,
        m2,
        proof,
        proof_prf,
        c
    }
}

pub fn rvrf_verify(rvrfproof: RVRFProof, statment: Statement, rr: Scalar) -> bool {
    let RVRFProof {
        m1,
        m2,
        proof,
        proof_prf,
        c
    } = rvrfproof;
    let crs = CRS::new(get_random_scalar(), get_random_scalar());

    let mut hash_vec: Vec<Vec<u8>> = Vec::new();
    hash_vec.push(point_to_bytes(&m1));
    hash_vec.push(point_to_bytes(&m2));
    let verifier = Verifier::new(statment, crs);
    let (result, hash) = verifier.verify_return_hash(proof, hash_vec);
    let proof_prf_result = PRFVerifier::verify_with_hash(proof_prf, Scalar::one(), rr, hash);

    if result == true && proof_prf_result == true {
        return true;
    }
    false
}
use std::time::{Duration, Instant};

/// public_keys链上公钥s  secret_key自己的私钥 rand链上随机数 index链上公钥中自己公钥的位置
pub fn rvrf_prove_simple(public_keys:Vec<RistrettoPoint>,secret_key:Scalar,rand:Scalar, index:u64) -> RVRFProof{
    let l = index;
    let witness = Witness::new(l);
    let r = witness.r;
    let c = Com::commit_scalar_2(secret_key, -r).comm.point;

    let pks: Vec<RistrettoPoint> = public_keys.clone().into_iter().map(|each| each - c).collect();
    let statment: Statement = pks.into();


    let rvrfproof =
        rvrf_prove(witness, statment.clone(), rand, r, c, secret_key);
    rvrfproof
}

/// rvrfproof证明  public_keys链上公钥s  rand链上随机数
pub fn rvrf_verify_simple(rvrfproof:RVRFProof, public_keys:Vec<RistrettoPoint>, rand:Scalar) -> bool{
    let c = rvrfproof.c;
    let pks: Vec<RistrettoPoint> = public_keys.clone().into_iter().map(|each| each - c).collect();
    let statment: Statement = pks.into();

    let res = rvrf_verify(rvrfproof, statment, rand);
    res
}

pub fn rvrf_test_wasm() -> bool {
    let l = 6;
    let a = Scalar::zero();
    let b = Scalar::one();
    let c = a + b;
    let d = generate_pk(c);

    get_random_scalar();
    rvrf_full_test_wasm()
    //Scalar::one();
}

pub fn rvrf_full_test_wasm() -> bool {
    let l = 6;
    let witness = Witness::new(l);
    let r = witness.r;
    let amount = 15;

    // 构造 输入参数
    let sks = generate_sks(amount);
    let pk_vec: Vec<RistrettoPoint> = sks.clone().into_iter().map(|sk| generate_pk(sk)).collect();
    let sk_witness = sks[l as usize];
    let c = Com::commit_scalar_2(sk_witness, -r).comm.point;
    let pks: Vec<RistrettoPoint> = pk_vec.clone().into_iter().map(|each| each - c).collect();
    let statment: Statement = pks.into();
    //

    let crs = CRS::new(get_random_scalar(), r);
    let rr = get_random_scalar();

    let rvrfproof = rvrf_prove(witness, statment.clone(), rr, r, c, sks[l as usize]);
    rvrf_verify(rvrfproof, statment, rr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::ops::Index;
    use std::time::{Duration, Instant};

    #[test]
    fn rvrf_bench_simple_test() {
        for amount in 1..5 {
            let mut total_prove = Duration::new(0, 0);
            let mut total_verify = Duration::new(0, 0);
            let mut total_size = 0usize;
            let samples = 10;
            for i in 0..samples {

                // 链上的那一组公钥中自己的公钥的index
                let l = 0;
                let witness = Witness::new(l);
                let r = witness.r;

                // 构造 输入参数
                // 一组 私钥 sks  （模拟每个人的私钥）
                let sks = generate_sks(amount);
                // 生成对应的 sks 的公钥集合 pk_vec  （链上获取）
                let pk_vec: Vec<RistrettoPoint> =
                    sks.clone().into_iter().map(|sk| generate_pk(sk)).collect();
                // sks中，自己拥有的index的位置的 sk_witness  （自己的参数）
                let sk_witness = sks[l as usize];

                // 链上获取 就是 r 用来计算 prf
                let rr = get_random_scalar();


                let start = Instant::now();
                let rvrfproof =
                    rvrf_prove_simple(pk_vec.clone(), sk_witness, rr, l);
                total_prove += start.elapsed();
                let len1 = serde_json::to_string(&rvrfproof).unwrap().len();
                total_size += len1;

                let start = Instant::now();
                let res = rvrf_verify_simple(rvrfproof, pk_vec, rr);
                total_verify += start.elapsed();
                assert_eq!(res, true);

            }
            let total_prove_avg = total_prove / samples;
            let total_verify_avg = total_verify / samples;
            let total_size_avg = total_size / samples as usize;
            println!(
                "amount:{:?},prove:{:?},verify:{:?},size:{:?}",
                amount, total_prove_avg, total_verify_avg, total_size_avg
            );
        }
    }

    #[test]
    fn rvrf_bench_test() {
        for amount in 1..5 {
            let mut total_prove = Duration::new(0, 0);
            let mut total_verify = Duration::new(0, 0);
            let mut total_size = 0usize;
            let samples = 10;
            for i in 0..samples {

                // 链上的那一组公钥中自己的公钥的index
                let l = 0;
                let witness = Witness::new(l);
                let r = witness.r;

                // 构造 输入参数

                // 一组 私钥 sks  （模拟每个人的私钥）
                let sks = generate_sks(amount);
                // 生成对应的 sks 的公钥集合 pk_vec  （链上获取）
                let pk_vec: Vec<RistrettoPoint> =
                    sks.clone().into_iter().map(|sk| generate_pk(sk)).collect();
                // sks中，自己拥有的index的位置的 sk_witness  （自己的参数）
                let sk_witness = sks[l as usize];

                // 现场生成，后面需要
                let c = Com::commit_scalar_2(sk_witness, -r).comm.point;

                // 此处用链上的 pk_vec 生成 statement ，后面需要
                let pks: Vec<RistrettoPoint> =
                    pk_vec.clone().into_iter().map(|each| each - c).collect();
                let statment: Statement = pks.into();
                //

                // 链上获取 就是 r 用来计算 prf
                let rr = get_random_scalar();

                let start = Instant::now();
                let rvrfproof =
                    rvrf_prove(witness, statment.clone(), rr, r, c, sks[l as usize]);
                total_prove += start.elapsed();
                let len1 = serde_json::to_string(&rvrfproof).unwrap().len();
                total_size += len1;

                let start = Instant::now();
                let res = rvrf_verify(rvrfproof, statment, rr);
                total_verify += start.elapsed();
                assert_eq!(res, true);
            }
            let total_prove_avg = total_prove / samples;
            let total_verify_avg = total_verify / samples;
            let total_size_avg = total_size / samples as usize;
            println!(
                "amount:{:?},prove:{:?},verify:{:?},size:{:?}",
                amount, total_prove_avg, total_verify_avg, total_size_avg
            );
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
        let proof_prf = PRFProver::prove(sk_witness, rr, get_random_scalar(), -r, c);

        let verifier = Verifier::new(statment, crs);
        let result = verifier.verify(proof, vec![]);
        let proof_prf_result = PRFVerifier::verify(proof_prf, get_random_scalar(), rr);

        assert_eq!(result, true);
        assert_eq!(proof_prf_result, true);
    }

    #[test]
    fn rvrf_test_2() {
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

        // prove
        let (u, m1, m2, s_pie, t_pie, hash_vec) = PRFProver::prove_step_one(sk_witness, rr);
        let prover = Prover::new(witness, statment.clone(), crs);
        let (proof, hash) = prover.prove_return_hash(hash_vec.clone());
        let proof_prf = PRFProver::prove_step_two(sk_witness, -r, c, s_pie, t_pie, u, m1, m2, hash);

        //verify
        let mut hash_vec: Vec<Vec<u8>> = Vec::new();
        hash_vec.push(point_to_bytes(&m1));
        hash_vec.push(point_to_bytes(&m2));
        let verifier = Verifier::new(statment, crs);
        let result = verifier.verify(proof, hash_vec);
        let proof_prf_result =
            PRFVerifier::verify_with_hash(proof_prf, get_random_scalar(), rr, hash);

        assert_eq!(result, true);
        assert_eq!(proof_prf_result, true);
    }

    #[test]
    fn rvrf_test_3() {
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

        let rvrfproof = rvrf_prove(witness, statment.clone(), rr, r, c, sks[l as usize]);
        let res = rvrf_verify(rvrfproof, statment, rr);
        assert_eq!(res, true);
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
