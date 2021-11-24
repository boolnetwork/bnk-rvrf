use crate::util::{fix_len_binary, number_to_binary};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use polynomials::*;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_scalar, get_random_scalar, hash_to_scalar, point_to_bytes, scalar_to_bytes,
    BASEPOINT_G1, BASEPOINT_G2,
};

// Comck(m; r) = g^m*h^r
// Comck(m; r) = g*m+h*r

#[derive(Copy, Clone, Debug, Default)]
pub struct CRS {
    pub ck: Scalar,
}

#[derive(Clone, Debug, Default)]
pub struct Statement {
    pub pk_vec: Vec<RistrettoPoint>,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Witness {
    pub r: Scalar,
    pub l: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Prover {
    pub witness: Witness,
    pub statement: Statement,
    pub crs: CRS,
}

#[derive(Clone, Debug, Default)]
pub struct Verifier {
    pub statement: Statement,
    pub crs: CRS,
}

#[derive(Clone, Debug, Default)]
pub struct Com {
    pub comm: Commitment,
    pub secret: Secret,
}

#[derive(Clone, Debug, Default)]
pub struct Commitment {
    pub point: RistrettoPoint,
}

#[derive(Clone, Debug, Default)]
pub struct Secret {
    value: Scalar,
    secret: Scalar,
}

impl Com {
    pub fn commit_scalar(value: Scalar) -> Self {
        let secret = get_random_scalar();
        let commitment_point =
            RistrettoPoint::multiscalar_mul([value, secret], &[*BASEPOINT_G1, *BASEPOINT_G2]);

        Self {
            comm: Commitment {
                point: commitment_point,
            },
            secret: Secret { value, secret },
        }
    }

    pub fn commit_scalar_2(value: Scalar, value2: Scalar) -> Self {
        let commitment_point =
            RistrettoPoint::multiscalar_mul([value, value2], &[*BASEPOINT_G1, *BASEPOINT_G2]);

        Self {
            comm: Commitment {
                point: commitment_point,
            },
            secret: Secret {
                value,
                secret: value2,
            },
        }
    }
}

pub fn generate_sks(amount: u64) -> Vec<Scalar> {
    let sks_vec: Vec<Scalar> = (0..amount)
        .into_iter()
        .map(|_| get_random_scalar())
        .collect();
    sks_vec
}

pub fn kronecker_delta(a: u64, b: u64) -> Scalar {
    if a == b {
        Scalar::from(1u64)
    } else {
        Scalar::from(0u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Index;

    #[test]
    fn generate_sks_test() {
        let a = generate_sks(10);
        println!("a = {:?}", a);
        println!("a len = {:?}", a.len());
    }

    #[test]
    fn commit_sks_test() {
        let a = generate_sks(10);
        let b: Vec<Com> = a.into_iter().map(|sk| Com::commit_scalar(sk)).collect();
    }

    #[test]
    fn poly_test() {
        use polynomials::*;

        let a = poly![get_random_scalar(), get_random_scalar()];
        let b = poly![get_random_scalar(), get_random_scalar()];

        let c = a * b;
    }

    #[test]
    fn a_test() {
        let number_of_public_keys = 10u64;
        let binary_j_vec = number_to_binary(number_of_public_keys);
        let binary_j_vec_len = binary_j_vec.len() as u64;

        // 假设 一共10commit（0..9） 其中 第l（5）个是0
        let l_vec = fix_len_binary(5, number_of_public_keys);
        println!("l_vec = {:?}", l_vec);

        let mut rj_vec: Vec<Scalar> = Vec::new();
        let mut aj_vec: Vec<Scalar> = Vec::new();
        let mut sj_vec: Vec<Scalar> = Vec::new();
        let mut tj_vec: Vec<Scalar> = Vec::new();
        let mut rouk_vec: Vec<Scalar> = Vec::new();

        let mut clj_vec: Vec<Scalar> = Vec::new();
        let mut caj_vec: Vec<Scalar> = Vec::new();
        let mut cbj_vec: Vec<Scalar> = Vec::new();
        let mut cdk_vec: Vec<Scalar> = Vec::new();

        for j in 0..binary_j_vec_len {
            let rj = get_random_scalar();
            rj_vec.push(rj);
            let aj = get_random_scalar();
            aj_vec.push(aj);
            let sj = get_random_scalar();
            sj_vec.push(sj);
            let tj = get_random_scalar();
            tj_vec.push(tj);
            let rouk = get_random_scalar();
            rouk_vec.push(rouk);
            let clj = Com::commit_scalar_2(Scalar::from(l_vec[j as usize]), rj);
            let caj = Com::commit_scalar_2(aj, sj);
            let cbj = Com::commit_scalar_2(Scalar::from(l_vec[j as usize]) * aj, tj);
        }

        let mut p_i_k: Vec<Vec<Scalar>> = Vec::new();
        // for each i : 得到除了x^n以外所有x^0..x^n-1的系数 ai,k k=0..n-1
        for i in 0..number_of_public_keys {
            // 让i变成2进制binary格式，长度不够前面填充0
            let i_vec = fix_len_binary(i, number_of_public_keys);
            println!("i_vec = {:?}", i_vec);
            let n = i_vec.len();
            println!("each i = {}, lenth of i/n = {}", i, n);
            let mut f_j_ij_mul = poly![Scalar::from(1u64)];
            for j in 0..n {
                let f_j_ij = if i_vec[j] == 0 {
                    poly![
                        kronecker_delta(0, l_vec[j]),
                        -aj_vec[j]
                    ]   // (δ0,lj)*x-aj
                } else {
                    poly![
                        kronecker_delta(1, l_vec[j]),
                        aj_vec[j]
                    ]   // (δ1,lj)*x+aj
                };
                f_j_ij_mul *= f_j_ij;
            }
            let mut coefficients: Vec<Scalar> = f_j_ij_mul.into();
            println!("coefficients(X^n+...+x^0) = {:?}", coefficients);
            coefficients.reverse();
            p_i_k.push(coefficients);
        }
        let test = p_i_k.index(4).index(1);
        println!("test coefficients(X^n+...+x^0) = {:?}", test);

        let x = get_random_scalar();





    }
}
