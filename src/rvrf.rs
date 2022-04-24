use crate::one_out_of_many::*;
#[cfg(feature = "prove")]
use crate::prf::PRFProver;
#[cfg(feature = "prove")]
use crate::util::generate_sks;
#[cfg(feature = "prove")]
use crate::util::intermediary_sk;
#[cfg(feature = "prove")]
use crate::util::{generate_pk, Com};
#[cfg(feature = "prove")]
use ed25519_dalek::SecretKey;
#[cfg(feature = "prove")]
use zk_utils_test::get_random_scalar;

use crate::prf::{PRFPoof, PRFVerifier};
use crate::util::ed25519pubkey_to_ristrettopoint;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};
use zk_utils_test::point_to_bytes;

use crate::traits::{PointTrait, ScalarTrait};
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::{Mul, Neg};

#[derive(Clone, Debug, Default)]
pub struct VRFStatement<S: ScalarTrait, P: PointTrait> {
    pub pk_vec: Vec<P>,
    pub ph: PhantomData<S>,
}

#[cfg(feature = "prove")]
impl<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>> VRFStatement<S, P> {
    pub fn new(amount: u64, r: S) -> Self {
        let sks = generate_sks::<S, P>(amount);
        let pk_vec: Vec<P> = sks
            .into_iter()
            .map(|sk| Com::<S, P>::commit_scalar_2(sk, r).comm.point)
            .collect();

        Self {
            pk_vec,
            ph: Default::default(),
        }
    }
}

#[cfg(feature = "prove")]
pub fn generate_pks<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>>(
    amount: u64,
) -> Vec<P> {
    let sks = generate_sks::<S, P>(amount);
    let pk_vec: Vec<P> = sks.into_iter().map(|sk| generate_pk(sk)).collect();
    pk_vec
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RVRFProof<S: ScalarTrait, P: PointTrait> {
    pub m1: P,
    pub m2: P,
    pub proof: Proof<S, P>,
    pub proof_prf: PRFPoof<S, P>,
    pub c: P,
}

#[cfg(feature = "prove")]
pub fn rvrf_prove<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>>(
    witness: Witness<S>,
    statment: Statement<S, P>,
    rr: S,
    r: S,
    c: P,
    sk: S,
) -> RVRFProof<S, P> {
    let crs = CRS::new(S::random_scalar(), S::random_scalar());
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
        c,
    }
}

pub fn rvrf_verify<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>>(
    rvrfproof: RVRFProof<S, P>,
    statment: Statement<S, P>,
    rr: S,
) -> bool {
    let RVRFProof {
        m1,
        m2,
        proof,
        proof_prf,
        c: _,
    } = rvrfproof;
    let crs = CRS::new(S::default(), S::default());

    let mut hash_vec: Vec<Vec<u8>> = Vec::new();
    hash_vec.push(P::point_to_bytes(&m1));
    hash_vec.push(P::point_to_bytes(&m2));
    let verifier = Verifier::new(statment, crs);
    let (result, hash) = verifier.verify_return_hash(proof, hash_vec);
    let proof_prf_result = PRFVerifier::verify_with_hash(proof_prf, S::one(), rr, hash);

    if result == true && proof_prf_result == true {
        return true;
    }
    false
}

#[cfg(feature = "prove")]
/// public_keys链上公钥s  secret_key自己的私钥 rand链上随机数 index链上公钥中自己公钥的位置
pub fn rvrf_prove_simple<
    S: ScalarTrait + Mul<P, Output = P> + Neg<Output = S>,
    P: PointTrait + Mul<S, Output = P>,
>(
    public_keys: Vec<P>,
    secret_key: S,
    rand: S,
    index: u64,
) -> RVRFProof<S, P> {
    let l = index;
    let witness = Witness::<S>::new(l);
    let r = witness.r;
    let c = Com::<S, P>::commit_scalar_2(secret_key, -r).comm.point;

    let pks: Vec<P> = public_keys
        .clone()
        .into_iter()
        .map(|each| each - c)
        .collect();
    let statment: Statement<S, P> = pks.into();

    let rvrfproof = rvrf_prove(witness, statment.clone(), rand, r, c, secret_key);
    rvrfproof
}

/// rvrfproof证明  public_keys链上公钥s  rand链上随机数  如果true 返回 v 否则 none
pub fn rvrf_verify_simple<
    S: ScalarTrait + Mul<P, Output = P>,
    P: PointTrait + Mul<S, Output = P>,
>(
    rvrfproof: RVRFProof<S, P>,
    public_keys: Vec<P>,
    rand: S,
) -> Option<P> {
    let c = rvrfproof.c;
    let pks: Vec<P> = public_keys
        .clone()
        .into_iter()
        .map(|each| each - c)
        .collect();
    let statment: Statement<S, P> = pks.into();

    match rvrf_verify(rvrfproof.clone(), statment, rand) {
        true => Some(rvrfproof.proof_prf.get_v()),
        false => None,
    }
}

// #[cfg(feature = "prove")]
// pub fn rvrf_prove_ed25519(
//     public_keys: Vec<PublicKey>,
//     secret_key: SecretKey,
//     rand: Scalar,
//     index: u64,
// ) -> RVRFProof {
//     let pubkeys = ed25519pubkey_to_ristrettopoint(public_keys);
//     rvrf_prove_simple(pubkeys, intermediary_sk(&secret_key), rand, index)
// }

// pub fn rvrf_verfify_ed25519(
//     rvrfproof: RVRFProof,
//     public_keys: Vec<PublicKey>,
//     rand: Scalar,
// ) -> Option<RistrettoPoint> {
//     let pubkeys = ed25519pubkey_to_ristrettopoint(public_keys);
//     rvrf_verify_simple(rvrfproof, pubkeys, rand)
// }

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Index;
    use serde_json;

    #[test]
    fn rvrf_bench_simple_test() {
        use crate::ed25519::{PointSelfDefined, ScalarSelfDefined};
        for amount in 1..5 {
            let samples = 10;
            for i in 0..samples {
                // 链上的那一组公钥中自己的公钥的index
                let l = 0;
                let witness = Witness::<ScalarSelfDefined>::new(l);
                let r = witness.r;

                // 构造 输入参数
                // 一组 私钥 sks  （模拟每个人的私钥）
                let sks = generate_sks::<ScalarSelfDefined, PointSelfDefined>(amount);
                // 生成对应的 sks 的公钥集合 pk_vec  （链上获取）
                let pk_vec: Vec<PointSelfDefined> = sks
                    .clone()
                    .into_iter()
                    .map(|sk| generate_pk::<ScalarSelfDefined, PointSelfDefined>(sk))
                    .collect();
                // sks中，自己拥有的index的位置的 sk_witness  （自己的参数）
                let sk_witness = sks[l as usize];

                // 链上获取 就是 r 用来计算 prf
                let rr = ScalarSelfDefined::random_scalar();

                let rvrfproof = rvrf_prove_simple(pk_vec.clone(), sk_witness, rr, l);

                let res = rvrf_verify_simple(rvrfproof, pk_vec, rr);
                assert!(res.is_some());
            }
        }
    }

    // #[test]
    // fn ooom_test() {
    //     let l = 6;
    //     let witness = Witness::new(l);
    //     let r = witness.r;
    //     let amount = 8;
    //     let statment = Statement::new(amount, l, r);
    //     let crs = CRS::new(get_random_scalar(), r);
    //
    //     let prover = Prover::new(witness, statment.clone(), crs);
    //     let proof = prover.prove(vec![]);
    //
    //     let verifier = Verifier::new(statment, crs);
    //     let result = verifier.verify(proof, vec![]);
    //     assert_eq!(result, true);
    // }
}
