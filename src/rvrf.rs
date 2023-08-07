use crate::one_out_of_many::*;
#[cfg(feature = "prove")]
use crate::prf::PRFProver;
#[cfg(feature = "prove")]
use crate::util::generate_sks;

#[cfg(feature = "prove")]
use crate::util::{generate_pk, Com};

use crate::prf::{PRFPoof, PRFVerifier};

use serde::{Deserialize, Serialize};

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
    let pk_vec: Vec<P> = sks.into_iter().map(generate_pk).collect();
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
    statement: Statement<S, P>,
    rr: S,
    r: S,
    c: P,
    sk: S,
) -> RVRFProof<S, P> {
    let crs = CRS::new(S::random_scalar(), S::random_scalar());
    let sk_witness = sk;
    let (u, m1, m2, s_pie, t_pie, hash_vec) = PRFProver::prove_step_one(sk_witness, rr);
    let prover = Prover::new(witness, statement, crs);
    let (proof, hash) = prover.prove_return_hash(hash_vec);
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
    statement: Statement<S, P>,
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
    let verifier = Verifier::new(statement, crs);
    let (result, hash) = verifier.verify_return_hash(proof, hash_vec);
    let proof_prf_result = PRFVerifier::verify_with_hash(proof_prf, S::one(), rr, hash);

    if result && proof_prf_result {
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

    let pks: Vec<P> = public_keys.into_iter().map(|each| each - c).collect();
    let statement: Statement<S, P> = pks.into();

    rvrf_prove(witness, statement, rand, r, c, secret_key)
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
    let pks: Vec<P> = public_keys.into_iter().map(|each| each - c).collect();
    let statement: Statement<S, P> = pks.into();

    match rvrf_verify(rvrfproof.clone(), statement, rand) {
        true => Some(rvrfproof.proof_prf.get_v()),
        false => None,
    }
}

pub mod ed25519 {
    use super::*;
    use crate::ed25519::*;
    #[cfg(feature = "prove")]
    pub fn rvrf_prove_ed25519(
        public_keys: Vec<Public>,
        secret_key: Secret,
        rand: ScalarType,
        index: u64,
    ) -> RVRFProof<ScalarType, PointType> {
        let pubkeys = ed25519pubkey_to_ristrettopoint(public_keys);
        rvrf_prove_simple::<ScalarType, PointType>(
            pubkeys,
            intermediary_sk(&secret_key),
            rand,
            index,
        )
    }

    pub fn rvrf_verfify_ed25519(
        rvrfproof: RVRFProof<ScalarType, PointType>,
        public_keys: Vec<Public>,
        rand: ScalarType,
    ) -> Option<PointType> {
        let pubkeys = ed25519pubkey_to_ristrettopoint(public_keys);
        rvrf_verify_simple::<ScalarType, PointType>(rvrfproof, pubkeys, rand)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rvrf_bench_simple_test() {
        use crate::ed25519::{PointType, ScalarType};
        for amount in 2..8 {
            let samples = 10;
            for _i in 0..samples {
                let l = 1;
                let witness = Witness::<ScalarType>::new(l);
                let _r = witness.r;

                let sks = generate_sks::<ScalarType, PointType>(amount);

                let pk_vec: Vec<PointType> = sks
                    .clone()
                    .into_iter()
                    .map(generate_pk::<ScalarType, PointType>)
                    .collect();

                let sk_witness = sks[l as usize];

                let rr = ScalarType::random_scalar();

                let rvrfproof = rvrf_prove_simple(pk_vec.clone(), sk_witness, rr, l);

                let res = rvrf_verify_simple(rvrfproof, pk_vec.clone(), rr);
                assert!(res.is_some());

                let rvrfproof = rvrf_prove_simple(pk_vec.clone(), sk_witness, rr, l + 1);
                let res = rvrf_verify_simple(rvrfproof, pk_vec, rr);
                assert!(res.is_none());
            }
        }
    }

    #[test]
    fn rvrf_bench_ed25519_test() {
        use crate::ed25519::*;
        use ed25519::{rvrf_prove_ed25519, rvrf_verfify_ed25519};
        for amount in 1..5 {
            let samples = 10;
            for _i in 0..samples {
                let l = 0;
                let witness = Witness::<ScalarType>::new(l);
                let _r = witness.r;

                let sks: Vec<Secret> = (0..amount).into_iter().map(|_| Secret::random()).collect();

                let pk_vec: Vec<Public> = sks
                    .clone()
                    .into_iter()
                    .map(|sk| {
                        let pk: Public = sk.into();
                        pk
                    })
                    .collect();

                let sk_witness = sks[l as usize];

                let rr = ScalarType::random_scalar();

                let rvrfproof = rvrf_prove_ed25519(pk_vec.clone(), sk_witness, rr, l);

                let res = rvrf_verfify_ed25519(rvrfproof, pk_vec, rr);
                assert!(res.is_some());
            }
        }
    }
}
