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
        Scalar::one()
    } else {
        Scalar::zero()
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

        // (x + 1)(x - 1)(1)(1)(1) = x^2 - 1
        let a = poly![1, 1]; // x + 1
        let b = poly![1, -1]; // x - 1
        let c = poly![1];
        assert_eq!(a * b * c.clone() * c.clone() * c, poly![1, 0, -1]);
    }

    #[test]
    fn poly_2_test() {
        use polynomials::*;

        let x = 5u64;
        let a = poly![6, 10]; // 6x+10  10x+6
        let b = poly![3, 9]; // 3x+9  9x+3
        let c = a * b;
        let result_eval = c.eval(x).unwrap();
        println!("coeff={:?}",c); // 18x^2+84x+90  90x^2+84x+18 //[18, 84, 90]
        let mut coeff:Vec<u64> = c.into();
        //coeff.reverse();
        let len = coeff.len();
        let mut result_coeff = coeff[0] * 1u64;
        println!("result_coeff={:?}",result_coeff);
        for i in 1..len{
            let mut tmp_x = 1u64;
            for bb in 0..i{
                tmp_x *= x;
            }
            result_coeff += coeff[i] * tmp_x;
            println!("result_coeff={:?}",result_coeff);
        }
        assert_eq!(result_eval,result_coeff);
    }

    #[test]
    fn a_test() {
        let number_of_public_keys = 10u64;
        let binary_j_vec = number_to_binary(number_of_public_keys);
        let binary_j_vec_len = binary_j_vec.len() as u64;

        // 假设 一共10commit（0..9） 其中 index为l（5）个是0
        let l_vec = fix_len_binary(5, number_of_public_keys);
        println!("l_vec = {:?}", l_vec);
        let mut ci_vec = generate_sks(10);
        // index =  0 1 2 3 4 5 6 7 8 9
        ci_vec[5] = Scalar::zero();

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

        let mut f_i_j_poly: Vec<Polynomial<Scalar>> = Vec::new();
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
                    //poly![kronecker_delta(0, l_vec[j]), -aj_vec[j]]
                    poly![-aj_vec[j],kronecker_delta(0, l_vec[j])] // (δ0,lj)*x-aj
                } else {
                    //poly![kronecker_delta(1, l_vec[j]), aj_vec[j]]
                    poly![aj_vec[j],kronecker_delta(1, l_vec[j])] // (δ1,lj)*x+aj
                };
                f_j_ij_mul *= f_j_ij;
            }
            f_i_j_poly.push(f_j_ij_mul.clone());
            let mut coefficients: Vec<Scalar> = f_j_ij_mul.into();
            //coefficients.reverse();
            println!("coefficients(X^n+...+x^0) = {:?}", coefficients);
            p_i_k.push(coefficients);
        }
        let test = p_i_k.index(4).index(1);
        println!("test coefficients(X^n+...+x^0) = {:?}", test);



        let x = get_random_scalar();
        let r = get_random_scalar();

        let mut ci_vec_comm = Vec::new();
        for i in 0..number_of_public_keys as usize {
            let ci = Com::commit_scalar_2(ci_vec[i], r);
            ci_vec_comm.push(ci.clone());
        }

        let mut cdk_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            let fj = Scalar::from(l_vec[j]) * x + aj_vec[j];
            let zaj = rj_vec[j] * x + sj_vec[j];
            let zbj = rj_vec[j] * (x - fj) + tj_vec[j];
            let com_rouk = Com::commit_scalar_2(Scalar::zero(), rouk_vec[j]);
            for i in 0..number_of_public_keys as usize {
                let cdk =
                    ci_vec_comm[i].comm.point.clone() * p_i_k.index(i).index(j);//+ com_rouk.comm.point.clone();
                cdk_vec.push(cdk);
            }
        }

        let mut cdk_add_vec = Vec::new();
        for j in 0..binary_j_vec_len as usize {
            let com_rouk = Com::commit_scalar_2(Scalar::zero(), rouk_vec[j]);
            let mut cdk_i = cdk_vec[10*j] + com_rouk.comm.point;
            println!("10j = {}",10*j);
            for i in 1..number_of_public_keys as usize{
                cdk_i += cdk_vec[10*j+i];
                println!("aaaa = {}",10*j+i);
            }
            cdk_add_vec.push(cdk_i);
        }

        let mut ci_pow_fji =
            ci_vec_comm[0].comm.point.clone() * f_i_j_poly.index(0).eval(x).unwrap();
        for i in 1..number_of_public_keys as usize {
            ci_pow_fji += ci_vec_comm[i].comm.point.clone() * f_i_j_poly.index(i).eval(x).unwrap();
        }
        println!("ci_pow_fji = {:?}",ci_pow_fji);

        // 系数 x 测试
        let mut bbb = p_i_k.index(4).index(0) * Scalar::one();
        for j in 1..(binary_j_vec_len+1) as usize {
            let mut x_tmp = Scalar::one();
            for k in 0..j{
                x_tmp *= x;
            }
            bbb += p_i_k.index(4).index(j) * x_tmp;
        }
        let ccc = f_i_j_poly.index(4).eval(x).unwrap();
        println!("bbbccc = {:?}", bbb);
        println!("bbbccc = {:?}", ccc);
        //
        // 计算中间过程来验证：
        let mut xxxx = RistrettoPoint::default();
        for i in 0..number_of_public_keys as usize {
            for j in 0..binary_j_vec_len as usize {
                let mut x_tmp = Scalar::one();
                for k in 0..j {
                    x_tmp *= x;
                }
                xxxx += ci_vec_comm[i].comm.point.clone()*p_i_k.index(i).index(j) * x_tmp;
            }
        }
        let mut x_tmp = Scalar::one();
        for k in 0..binary_j_vec_len+1 {
            x_tmp *= x;
        }
        xxxx += ci_vec_comm[5].comm.point.clone() * x_tmp;
        xxxx -= RistrettoPoint::default();
        println!("xxxx = {:?}",xxxx);
        //


        println!("cdk_vec len = {:?}",cdk_vec.len());
        let mut cd_k_xk = cdk_add_vec[0] * (-Scalar::one());
        for j in 1..binary_j_vec_len as usize {
            let mut x_tmp = Scalar::one();
            for k in 0..j {
                x_tmp *= x;
            }
            cd_k_xk += cdk_add_vec[j] * (-x_tmp);
        }

        let left = ci_pow_fji + cd_k_xk;
        println!("left = {:?}",left);

        let mut x_pow_n = Scalar::one();
        for k in 0..binary_j_vec_len as usize {
            x_pow_n *= x;
        }

        let mut rou_k_x_pow_k = rouk_vec[0] * Scalar::one();
        for j in 1..binary_j_vec_len as usize {
            let mut x_tmp = Scalar::one();
            for k in 0..j {
                println!("k = {:?}",k);
                x_tmp *= x;
            }
            rou_k_x_pow_k += rouk_vec[j] * x_tmp;
        }
        let zd = x_pow_n * r - rou_k_x_pow_k;
        let right = Com::commit_scalar_2(Scalar::zero(), zd);
        println!("right = {:?}",right.comm.point);

        if left == right.comm.point{
            println!("ok");
        }else {
            println!("bad");
        }
        assert_eq!(left,right.comm.point);
    }
}
