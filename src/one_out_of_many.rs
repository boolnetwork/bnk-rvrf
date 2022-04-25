#[cfg(feature = "prove")]
use crate::util::{generate_sks, kronecker_delta};
#[cfg(feature = "prove")]
use crate::zero_or_one::Prover as ZOProver;
#[cfg(feature = "prove")]
use polynomials::*;
// #[cfg(feature = "prove")]
// use std::ops::Index;
use crate::util::{fix_len_binary, number_to_binary};
use crate::util::{x_pow_n, Com};
use crate::zero_or_one::{Proof as ZOProof, Verifier as ZOVerifier, CRS as ZOCRS};

use serde::{Deserialize, Serialize};

#[cfg(feature = "prove")]
use alloc::vec;
pub use alloc::vec::Vec;
#[cfg(feature = "prove")]
use core::ops::Index;

use crate::traits::{PointTrait, ScalarTrait};
use core::marker::PhantomData;
use core::ops::{Mul, Neg};

// Comck(m; r) = g^m*h^r
// Comck(m; r) = g*m+h*r

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct CRS<S: ScalarTrait, P: PointTrait> {
    pub c: P,
    pub ph: PhantomData<S>,
}

#[derive(Clone, Debug, Default)]
pub struct Statement<S: ScalarTrait, P: PointTrait> {
    pub pk_vec: Vec<P>,
    pub ph: PhantomData<S>,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Witness<S: ScalarTrait> {
    pub sk: S,
    pub l: u64,
    pub r: S,
}

#[derive(Clone, Debug, Default)]
pub struct Prover<S: ScalarTrait, P: PointTrait> {
    pub witness: Witness<S>,
    pub statement: Statement<S, P>,
    pub crs: CRS<S, P>,
}

#[derive(Clone, Debug, Default)]
pub struct Verifier<S: ScalarTrait, P: PointTrait> {
    pub statement: Statement<S, P>,
    pub crs: CRS<S, P>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ZoproofCrs<S: ScalarTrait, P: PointTrait> {
    proof: ZOProof<S, P>,
    crs: ZOCRS<S, P>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Proof<S: ScalarTrait, P: PointTrait> {
    pub clj: Vec<P>,
    pub fj: Vec<S>,
    pub cdk: Vec<P>,
    pub zd: S,
    pub zoproof: Vec<ZoproofCrs<S, P>>,
}

impl<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>> CRS<S, P> {
    pub fn new(m: S, r: S) -> Self {
        Self {
            c: Com::<S, P>::commit_scalar_2(m, r).comm.point,
            ph: Default::default(),
        }
    }
}
#[cfg(feature = "prove")]
impl<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>> Statement<S, P> {
    pub fn new(amount: u64, l: u64, r: S) -> Self {
        if amount < l {
            return Self::default();
        }

        let sks = generate_sks::<S, P>(amount);

        let mut pk_vec: Vec<P> = sks
            .into_iter()
            .map(|sk| Com::commit_scalar_2(sk, r).comm.point)
            .collect();

        pk_vec[l as usize] = Com::commit_scalar_2(S::zero(), r).comm.point;

        Self {
            pk_vec,
            ph: Default::default(),
        }
    }
}

impl<S: ScalarTrait, P: PointTrait> From<Vec<P>> for Statement<S, P> {
    fn from(pk: Vec<P>) -> Self {
        Self {
            pk_vec: pk,
            ph: Default::default(),
        }
    }
}

#[cfg(feature = "prove")]
impl<S: ScalarTrait> Witness<S> {
    pub fn new(l: u64) -> Self {
        Self {
            sk: S::zero(),
            l,
            r: S::random_scalar(),
        }
    }
}

#[cfg(feature = "prove")]
impl<S: ScalarTrait + Mul<P, Output = P>, P: PointTrait + Mul<S, Output = P>> Prover<S, P> {
    pub fn new(witness: Witness<S>, statement: Statement<S, P>, crs: CRS<S, P>) -> Self {
        Self {
            witness,
            statement,
            crs,
        }
    }

    pub fn proof_zero_or_one(l: Vec<u64>) -> (Vec<ZoproofCrs<S, P>>, Vec<S>) {
        let mut zo_proofs = Vec::new();
        let mut aj = Vec::new();
        for each in l {
            let p = ZOProver::<S, P>::new(S::from_u64(each));
            let (zoproof, a) = p.proof_with_a();
            aj.push(a);
            zo_proofs.push(ZoproofCrs {
                proof: zoproof,
                crs: p.crs,
            });
        }
        (zo_proofs, aj)
    }

    pub fn prove(self, extra_x: Vec<Vec<u8>>) -> Proof<S, P> {
        let CRS { c: _, .. } = self.crs;
        let Statement {
            pk_vec: ci_vec_comm,
            ..
        } = self.statement.clone();
        let Witness { sk: _, l, r } = self.witness;

        let number_of_public_keys = ci_vec_comm.len() as u64;
        let binary_j_vec = number_to_binary(number_of_public_keys);
        let binary_j_vec_len = binary_j_vec.len() as u64;

        let l_vec = fix_len_binary(l, number_of_public_keys);

        let (zero_one_proof, aj_vec) = Self::proof_zero_or_one(l_vec.clone());

        let mut rouk_vec: Vec<S> = Vec::new();

        for _j in 0..binary_j_vec_len {
            let rouk = S::random_scalar();
            rouk_vec.push(rouk);
        }

        let mut f_i_j_poly: Vec<Polynomial<S>> = Vec::new();
        let mut p_i_k: Vec<Vec<S>> = Vec::new();
        for i in 0..number_of_public_keys {
            let i_vec = fix_len_binary(i, number_of_public_keys);
            let n = i_vec.len();
            let mut f_j_ij_mul = poly![S::from_u64(1u64)];
            for j in 0..n {
                let f_j_ij = if i_vec[j] == 0 {
                    poly![-aj_vec[j], kronecker_delta(0, l_vec[j])] // (δ0,lj)*x-aj
                } else {
                    poly![aj_vec[j], kronecker_delta(1, l_vec[j])] // (δ1,lj)*x+aj
                };
                f_j_ij_mul *= f_j_ij;
            }
            f_i_j_poly.push(f_j_ij_mul.clone());
            let coefficients: Vec<S> = f_j_ij_mul.into();
            p_i_k.push(coefficients);
        }

        let mut cdk_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            for i in 0..number_of_public_keys as usize {
                let cdk = ci_vec_comm[i] * *p_i_k.index(i).index(j); //+ com_rouk.comm.point.clone();
                cdk_vec.push(cdk);
            }
        }

        let mut cdk_add_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            let com_rouk = Com::<S, P>::commit_scalar_2(S::zero(), rouk_vec[j]);
            let mut cdk_i = cdk_vec[number_of_public_keys as usize * j] + com_rouk.comm.point;
            for i in 1..number_of_public_keys as usize {
                cdk_i += cdk_vec[number_of_public_keys as usize * j + i];
            }
            cdk_add_vec.push(cdk_i);
        }

        let mut hash_vec = Vec::new();
        for i in 0..number_of_public_keys as usize {
            hash_vec.append(&mut ci_vec_comm[i].point_to_bytes());
        }
        for j in 0..binary_j_vec_len as usize {
            hash_vec.append(&mut zero_one_proof[j].crs.c.point_to_bytes());
            hash_vec.append(&mut zero_one_proof[j].proof.ca.point_to_bytes());
            hash_vec.append(&mut zero_one_proof[j].proof.cb.point_to_bytes());
            hash_vec.append(&mut cdk_add_vec[j].point_to_bytes());
        }
        for mut data in extra_x {
            hash_vec.append(&mut data)
        }
        let x = S::hash_to_scalar(&hash_vec);

        let mut rou_k_x_pow_k = rouk_vec[0] * S::one();
        for j in 1..binary_j_vec_len as usize {
            rou_k_x_pow_k += rouk_vec[j] * x_pow_n(x, j as u64);
        }
        let zd = x_pow_n(x, binary_j_vec_len as u64) * r - rou_k_x_pow_k;

        let mut fj_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            let fj = S::from_u64(l_vec[j]) * x + aj_vec[j];
            fj_vec.push(fj);
        }

        Proof {
            clj: vec![],
            fj: fj_vec,
            cdk: cdk_add_vec,
            zd,
            zoproof: zero_one_proof,
        }
    }

    pub fn prove_return_hash(self, extra_x: Vec<Vec<u8>>) -> (Proof<S, P>, S) {
        let CRS { c: _, .. } = self.crs;
        let Statement {
            pk_vec: ci_vec_comm,
            ..
        } = self.statement.clone();
        let Witness { sk: _, l, r } = self.witness;

        let number_of_public_keys = ci_vec_comm.len() as u64;
        let binary_j_vec = number_to_binary(number_of_public_keys);
        let binary_j_vec_len = binary_j_vec.len() as u64;

        let l_vec = fix_len_binary(l, number_of_public_keys);

        let (zero_one_proof, aj_vec) = Self::proof_zero_or_one(l_vec.clone());

        let mut rouk_vec: Vec<S> = Vec::new();

        for _j in 0..binary_j_vec_len {
            let rouk = S::random_scalar();
            rouk_vec.push(rouk);
        }

        let mut f_i_j_poly: Vec<Polynomial<S>> = Vec::new();
        let mut p_i_k: Vec<Vec<S>> = Vec::new();
        for i in 0..number_of_public_keys {
            let i_vec = fix_len_binary(i, number_of_public_keys);
            let n = i_vec.len();
            let mut f_j_ij_mul = poly![S::from_u64(1u64)];
            for j in 0..n {
                let f_j_ij = if i_vec[j] == 0 {
                    poly![-aj_vec[j], kronecker_delta(0, l_vec[j])] // (δ0,lj)*x-aj
                } else {
                    poly![aj_vec[j], kronecker_delta(1, l_vec[j])] // (δ1,lj)*x+aj
                };
                f_j_ij_mul *= f_j_ij;
            }
            f_i_j_poly.push(f_j_ij_mul.clone());
            let coefficients: Vec<S> = f_j_ij_mul.into();
            p_i_k.push(coefficients);
        }

        let mut cdk_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            for i in 0..number_of_public_keys as usize {
                let cdk = ci_vec_comm[i] * *p_i_k.index(i).index(j); //+ com_rouk.comm.point.clone();
                cdk_vec.push(cdk);
            }
        }

        let mut cdk_add_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            let com_rouk = Com::commit_scalar_2(S::zero(), rouk_vec[j]);
            let mut cdk_i = cdk_vec[number_of_public_keys as usize * j] + com_rouk.comm.point;
            for i in 1..number_of_public_keys as usize {
                cdk_i += cdk_vec[number_of_public_keys as usize * j + i];
            }
            cdk_add_vec.push(cdk_i);
        }

        let mut hash_vec = Vec::new();
        for i in 0..number_of_public_keys as usize {
            hash_vec.append(&mut ci_vec_comm[i].point_to_bytes());
        }
        for j in 0..binary_j_vec_len as usize {
            hash_vec.append(&mut zero_one_proof[j].crs.c.point_to_bytes());
            hash_vec.append(&mut zero_one_proof[j].proof.ca.point_to_bytes());
            hash_vec.append(&mut zero_one_proof[j].proof.cb.point_to_bytes());
            hash_vec.append(&mut cdk_add_vec[j].point_to_bytes());
        }
        for mut data in extra_x {
            hash_vec.append(&mut data)
        }
        let x = S::hash_to_scalar(&hash_vec);

        let mut rou_k_x_pow_k = rouk_vec[0] * S::one();
        for j in 1..binary_j_vec_len as usize {
            rou_k_x_pow_k += rouk_vec[j] * x_pow_n(x, j as u64);
        }
        let zd = x_pow_n(x, binary_j_vec_len as u64) * r - rou_k_x_pow_k;

        let mut fj_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            let fj = S::from_u64(l_vec[j]) * x + aj_vec[j];
            fj_vec.push(fj);
        }

        (
            Proof {
                clj: vec![],
                fj: fj_vec,
                cdk: cdk_add_vec,
                zd,
                zoproof: zero_one_proof,
            },
            x,
        )
    }
}

impl<S: ScalarTrait + Mul<P, Output = P> + Neg<Output = S>, P: PointTrait + Mul<S, Output = P>>
    Verifier<S, P>
{
    pub fn new(statement: Statement<S, P>, crs: CRS<S, P>) -> Self {
        Self { statement, crs }
    }

    pub fn verify_zero_or_one(proofs: Vec<ZoproofCrs<S, P>>) -> bool {
        let mut res = true;
        for proof in proofs {
            let v = ZOVerifier::new(proof.crs);
            let each = v.verify(proof.proof);
            res = res && each;
        }
        res
    }

    pub fn verify(self, proof: Proof<S, P>, extra_x: Vec<Vec<u8>>) -> bool {
        let CRS { c: _, .. } = self.crs;
        let Statement {
            pk_vec: ci_vec_comm,
            ..
        } = self.statement;
        let Proof {
            clj: _,
            fj: fj_vec,
            cdk: cdk_add_vec,
            zd,
            zoproof,
        } = proof;

        if !Self::verify_zero_or_one(zoproof.clone()) {
            return false;
        }

        let number_of_public_keys = ci_vec_comm.len() as u64;
        let binary_j_vec = number_to_binary(number_of_public_keys);
        let binary_j_vec_len = binary_j_vec.len() as u64;

        let zero_one_proof = zoproof;
        let mut hash_vec = Vec::new();
        for i in 0..number_of_public_keys as usize {
            hash_vec.append(&mut ci_vec_comm[i].point_to_bytes());
        }
        for j in 0..binary_j_vec_len as usize {
            hash_vec.append(&mut zero_one_proof[j].crs.c.point_to_bytes());
            hash_vec.append(&mut zero_one_proof[j].proof.ca.point_to_bytes());
            hash_vec.append(&mut zero_one_proof[j].proof.cb.point_to_bytes());
            hash_vec.append(&mut cdk_add_vec[j].point_to_bytes())
        }
        for mut data in extra_x {
            hash_vec.append(&mut data)
        }
        let x = S::hash_to_scalar(&hash_vec);

        let mut ci_pow_fji_2 = P::default();
        for i in 0..number_of_public_keys {
            let i_vec = fix_len_binary(i, number_of_public_keys);
            let n = i_vec.len();
            let mut each_f_j_ij = S::one();
            for j in 0..n {
                let f_j_ij = if i_vec[j] == 0 {
                    x - fj_vec[j]
                } else {
                    fj_vec[j]
                };
                each_f_j_ij *= f_j_ij;
            }
            ci_pow_fji_2 += ci_vec_comm[i as usize] * each_f_j_ij;
        }

        ci_pow_fji_2 -= P::default();

        let mut cd_k_xk = cdk_add_vec[0] * (-S::one());
        for j in 1..binary_j_vec_len as usize {
            cd_k_xk += cdk_add_vec[j] * (-x_pow_n(x, j as u64));
        }

        let left = ci_pow_fji_2 + cd_k_xk;
        let right = Com::commit_scalar_2(S::zero(), zd);

        left == right.comm.point
    }

    pub fn verify_return_hash(self, proof: Proof<S, P>, extra_x: Vec<Vec<u8>>) -> (bool, S) {
        let CRS { c: _, .. } = self.crs;
        let Statement {
            pk_vec: ci_vec_comm,
            ..
        } = self.statement;
        let Proof {
            clj: _,
            fj: fj_vec,
            cdk: cdk_add_vec,
            zd,
            zoproof,
        } = proof;

        if !Self::verify_zero_or_one(zoproof.clone()) {
            return (false, S::zero());
        }

        let number_of_public_keys = ci_vec_comm.len() as u64;
        let binary_j_vec = number_to_binary(number_of_public_keys);
        let binary_j_vec_len = binary_j_vec.len() as u64;

        let zero_one_proof = zoproof;
        let mut hash_vec = Vec::new();
        for i in 0..number_of_public_keys as usize {
            hash_vec.append(&mut ci_vec_comm[i].point_to_bytes());
        }
        for j in 0..binary_j_vec_len as usize {
            hash_vec.append(&mut zero_one_proof[j].crs.c.point_to_bytes());
            hash_vec.append(&mut zero_one_proof[j].proof.ca.point_to_bytes());
            hash_vec.append(&mut zero_one_proof[j].proof.cb.point_to_bytes());
            hash_vec.append(&mut cdk_add_vec[j].point_to_bytes())
        }
        for mut data in extra_x {
            hash_vec.append(&mut data)
        }
        let x = S::hash_to_scalar(&hash_vec);

        let mut ci_pow_fji_2 = P::default();
        for i in 0..number_of_public_keys {
            let i_vec = fix_len_binary(i, number_of_public_keys);
            let n = i_vec.len();
            let mut each_f_j_ij = S::one();
            for j in 0..n {
                let f_j_ij = if i_vec[j] == 0 {
                    x - fj_vec[j]
                } else {
                    fj_vec[j]
                };
                each_f_j_ij *= f_j_ij;
            }
            ci_pow_fji_2 += ci_vec_comm[i as usize] * each_f_j_ij;
        }

        ci_pow_fji_2 -= P::default();

        let mut cd_k_xk = cdk_add_vec[0] * (-S::one());
        for j in 1..binary_j_vec_len as usize {
            cd_k_xk += cdk_add_vec[j] * (-x_pow_n(x, j as u64));
        }

        let left = ci_pow_fji_2 + cd_k_xk;
        let right = Com::commit_scalar_2(S::zero(), zd);

        if left == right.comm.point {
            (true, x)
        } else {
            (false, x)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Index;

    #[test]
    fn ooom_ed25519_test() {
        use crate::ed25519::{PointSelfDefined, ScalarSelfDefined};
        let l = 5;
        let witness = Witness::<ScalarSelfDefined>::new(l);
        let r = witness.r;
        let amount = 10;
        let statment = Statement::<ScalarSelfDefined, PointSelfDefined>::new(amount, l, r);
        let crs = CRS::<ScalarSelfDefined, PointSelfDefined>::new(ScalarTrait::random_scalar(), r);

        let prover =
            Prover::<ScalarSelfDefined, PointSelfDefined>::new(witness, statment.clone(), crs);
        let proof = prover.prove(vec![]);

        let verifier = Verifier::new(statment, crs);
        let result = verifier.verify(proof, vec![]);
        assert_eq!(result, true);
    }

    #[test]
    fn ooom_p256_test() {
        use crate::p256::{PointSelfDefined, ScalarSelfDefined};
        let l = 5;
        let witness = Witness::<ScalarSelfDefined>::new(l);
        let r = witness.r;
        let amount = 10;
        let statment = Statement::<ScalarSelfDefined, PointSelfDefined>::new(amount, l, r);
        let crs = CRS::<ScalarSelfDefined, PointSelfDefined>::new(ScalarTrait::random_scalar(), r);

        let prover =
            Prover::<ScalarSelfDefined, PointSelfDefined>::new(witness, statment.clone(), crs);
        let proof = prover.prove(vec![]);

        let verifier = Verifier::new(statment, crs);
        let result = verifier.verify(proof, vec![]);
        assert_eq!(result, true);
    }
    //
    // #[test]
    // fn generate_sks_test() {
    //     let a = generate_sks(10);
    // }
    //
    // #[test]
    // fn commit_sks_test() {
    //     let a = generate_sks(10);
    //     let b: Vec<Com> = a.into_iter().map(|sk| Com::commit_scalar(sk)).collect();
    // }
    //
    #[test]
    fn poly_test() {
        use crate::p256::ScalarSelfDefined;
        use polynomials::*;

        let a = poly![
            ScalarSelfDefined::random_scalar(),
            ScalarSelfDefined::random_scalar()
        ];
        let b = poly![
            ScalarSelfDefined::random_scalar(),
            ScalarSelfDefined::random_scalar()
        ];

        let _c = a * b;

        // (x + 1)(2x + 3)(1)(1)(1) = 2x^2 + 5x + 3
        let a = poly![
            ScalarSelfDefined::from_u64(1),
            ScalarSelfDefined::from_u64(1)
        ]; // x + 1
        let b = poly![
            ScalarSelfDefined::from_u64(2),
            ScalarSelfDefined::from_u64(3)
        ]; // 2x + 3
        let c = poly![ScalarSelfDefined::from_u64(1)];
        assert_eq!(
            a * b * c.clone() * c.clone() * c,
            poly![
                ScalarSelfDefined::from_u64(2),
                ScalarSelfDefined::from_u64(5),
                ScalarSelfDefined::from_u64(3)
            ]
        );
    }

    #[test]
    fn poly_2_test() {
        use polynomials::*;

        let x = 5u64;
        let a = poly![6, 10]; // 6x+10  10x+6
        let b = poly![3, 9]; // 3x+9  9x+3
        let c = a * b;
        let result_eval = c.eval(x).unwrap();
        let coeff: Vec<u64> = c.into();
        let len = coeff.len();
        let mut result_coeff = coeff[0] * 1u64;
        for i in 1..len {
            let mut tmp_x = 1u64;
            for _bb in 0..i {
                tmp_x *= x;
            }
            result_coeff += coeff[i] * tmp_x;
        }
        assert_eq!(result_eval, result_coeff);
    }

    #[test]
    fn a_test() {
        //use crate::ed25519::{ScalarSelfDefined,PointSelfDefined};
        use crate::p256::{PointSelfDefined, ScalarSelfDefined};

        let number_of_public_keys = 10u64;
        let binary_j_vec = number_to_binary(number_of_public_keys);
        let binary_j_vec_len = binary_j_vec.len() as u64;

        // 假设 一共10commit（0..9） 其中 index为l（5）个是0
        let l_vec = fix_len_binary(5, number_of_public_keys);
        //println!("l_vec = {:?}", l_vec);
        let mut ci_vec = generate_sks::<ScalarSelfDefined, PointSelfDefined>(10);
        // index =  0 1 2 3 4 5 6 7 8 9
        ci_vec[5] = ScalarSelfDefined::zero();

        let mut rj_vec: Vec<ScalarSelfDefined> = Vec::new();
        let mut aj_vec: Vec<ScalarSelfDefined> = Vec::new();
        let mut sj_vec: Vec<ScalarSelfDefined> = Vec::new();
        let mut tj_vec: Vec<ScalarSelfDefined> = Vec::new();
        let mut rouk_vec: Vec<ScalarSelfDefined> = Vec::new();

        let _clj_vec: Vec<ScalarSelfDefined> = Vec::new();
        let _caj_vec: Vec<ScalarSelfDefined> = Vec::new();
        let _cbj_vec: Vec<ScalarSelfDefined> = Vec::new();
        let _cdk_vec: Vec<ScalarSelfDefined> = Vec::new();

        for j in 0..binary_j_vec_len {
            let rj = ScalarSelfDefined::random_scalar();
            rj_vec.push(rj);
            let aj = ScalarSelfDefined::random_scalar();
            aj_vec.push(aj);
            let sj = ScalarSelfDefined::random_scalar();
            sj_vec.push(sj);
            let tj = ScalarSelfDefined::random_scalar();
            tj_vec.push(tj);
            let rouk = ScalarSelfDefined::random_scalar();
            rouk_vec.push(rouk);
            let _clj = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(
                ScalarSelfDefined::from_u64(l_vec[j as usize]),
                rj,
            );
            let _caj = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(aj, sj);
            let _cbj = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(
                ScalarSelfDefined::from_u64(l_vec[j as usize]) * aj,
                tj,
            );
        }

        let mut f_i_j_poly: Vec<Polynomial<ScalarSelfDefined>> = Vec::new();
        let mut p_i_k: Vec<Vec<ScalarSelfDefined>> = Vec::new();
        // for each i : 得到除了x^n以外所有x^0..x^n-1的系数 ai,k k=0..n-1
        for i in 0..number_of_public_keys {
            // 让i变成2进制binary格式，长度不够前面填充0
            let i_vec = fix_len_binary(i, number_of_public_keys);
            //println!("i_vec = {:?}", i_vec);
            let n = i_vec.len();
            //println!("each i = {}, lenth of i/n = {}", i, n);
            let mut f_j_ij_mul = poly![ScalarSelfDefined::from_u64(1u64)];
            for j in 0..n {
                let f_j_ij = if i_vec[j] == 0 {
                    //poly![kronecker_delta(0, l_vec[j]), -aj_vec[j]]
                    poly![-aj_vec[j], kronecker_delta(0, l_vec[j])] // (δ0,lj)*x-aj
                } else {
                    //poly![kronecker_delta(1, l_vec[j]), aj_vec[j]]
                    poly![aj_vec[j], kronecker_delta(1, l_vec[j])] // (δ1,lj)*x+aj
                };
                f_j_ij_mul *= f_j_ij;
            }
            f_i_j_poly.push(f_j_ij_mul.clone());
            let coefficients: Vec<ScalarSelfDefined> = f_j_ij_mul.into();
            //coefficients.reverse();
            //println!("coefficients(X^n+...+x^0) = {:?}", coefficients);
            p_i_k.push(coefficients);
        }
        let _test = p_i_k.index(4).index(1);
        //println!("test coefficients(X^n+...+x^0) = {:?}", test);

        let x = ScalarSelfDefined::random_scalar();
        let r = ScalarSelfDefined::random_scalar();

        let mut ci_vec_comm = Vec::new();
        for i in 0..number_of_public_keys as usize {
            let ci = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(ci_vec[i], r);
            ci_vec_comm.push(ci.clone());
        }

        let mut cdk_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            let fj = ScalarSelfDefined::from_u64(l_vec[j]) * x + aj_vec[j];
            let _zaj = rj_vec[j] * x + sj_vec[j];
            let _zbj = rj_vec[j] * (x - fj) + tj_vec[j];
            let _com_rouk = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(
                ScalarSelfDefined::zero(),
                rouk_vec[j],
            );
            for i in 0..number_of_public_keys as usize {
                let cdk = ci_vec_comm[i].comm.point * p_i_k.index(i).index(j); //+ com_rouk.comm.point.clone();
                cdk_vec.push(cdk);
            }
        }

        let mut cdk_add_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            let com_rouk = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(
                ScalarSelfDefined::zero(),
                rouk_vec[j],
            );
            let mut cdk_i = cdk_vec[10 * j] + com_rouk.comm.point;
            //println!("10j = {}", 10 * j);
            for i in 1..number_of_public_keys as usize {
                cdk_i += cdk_vec[10 * j + i];
                //println!("aaaa = {}", 10 * j + i);
            }
            cdk_add_vec.push(cdk_i);
        }

        // 直接计算 fji带入方程
        let mut ci_pow_fji = ci_vec_comm[0].comm.point * f_i_j_poly.index(0).eval(x).unwrap();
        for i in 1..number_of_public_keys as usize {
            ci_pow_fji += ci_vec_comm[i].comm.point * f_i_j_poly.index(i).eval(x).unwrap();
        }
        //println!("ci_pow_fji = {:?}", ci_pow_fji);
        // lj aj 来组成 fj
        let mut fj_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            let fj = ScalarSelfDefined::from_u64(l_vec[j]) * x + aj_vec[j];
            fj_vec.push(fj);
        }
        let mut ci_pow_fji_2 = PointSelfDefined::default();
        for i in 0..number_of_public_keys {
            let i_vec = fix_len_binary(i, number_of_public_keys);
            let n = i_vec.len();
            let mut each_f_j_ij = ScalarSelfDefined::one();
            for j in 0..n {
                let f_j_ij = if i_vec[j] == 0 {
                    x - fj_vec[j]
                } else {
                    fj_vec[j]
                };
                each_f_j_ij *= f_j_ij;
            }
            ci_pow_fji_2 += ci_vec_comm[i as usize].comm.point * each_f_j_ij;
        }
        ci_pow_fji_2 -= PointSelfDefined::default();
        assert_eq!(ci_pow_fji, ci_pow_fji_2);
        //

        // 系数 x 测试
        let mut bbb = *p_i_k.index(4).index(0) * ScalarSelfDefined::one();
        for j in 1..(binary_j_vec_len + 1) as usize {
            bbb += *p_i_k.index(4).index(j) * x_pow_n(x, j as u64);
        }
        let _ccc = f_i_j_poly.index(4).eval(x).unwrap();
        //println!("bbbccc = {:?}", bbb);
        //println!("bbbccc = {:?}", ccc);
        //
        // 计算中间过程来验证：
        let mut xxxx = PointSelfDefined::default();
        for i in 0..number_of_public_keys as usize {
            for j in 0..binary_j_vec_len as usize {
                xxxx += ci_vec_comm[i].comm.point * p_i_k.index(i).index(j) * x_pow_n(x, j as u64);
            }
        }
        xxxx += ci_vec_comm[5].comm.point * x_pow_n(x, binary_j_vec_len + 1);
        xxxx -= PointSelfDefined::default();
        //println!("xxxx = {:?}", xxxx);

        //println!("cdk_vec len = {:?}", cdk_vec.len());
        let mut cd_k_xk = cdk_add_vec[0] * (-ScalarSelfDefined::one());
        for j in 1..binary_j_vec_len as usize {
            cd_k_xk += cdk_add_vec[j] * (-x_pow_n(x, j as u64));
        }

        let left = ci_pow_fji + cd_k_xk;
        //println!("left = {:?}", left);

        let mut rou_k_x_pow_k = rouk_vec[0] * ScalarSelfDefined::one();
        for j in 1..binary_j_vec_len as usize {
            rou_k_x_pow_k += rouk_vec[j] * x_pow_n(x, j as u64);
        }
        let zd = x_pow_n(x, binary_j_vec_len as u64) * r - rou_k_x_pow_k;
        let right = Com::<ScalarSelfDefined, PointSelfDefined>::commit_scalar_2(
            ScalarSelfDefined::zero(),
            zd,
        );
        //println!("right = {:?}", right.comm.point);

        if left == right.comm.point {
            //println!("ok");
        } else {
            //println!("bad");
        }
        assert_eq!(left, right.comm.point);
    }
}
