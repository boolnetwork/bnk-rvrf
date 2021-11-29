use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use wedpr_l_crypto_zkp_utils::{
    bytes_to_scalar, get_random_scalar, hash_to_scalar, point_to_bytes, scalar_to_bytes,
    BASEPOINT_G1, BASEPOINT_G2,
};

pub fn number_to_binary(num: u64) -> Vec<u64> {
    let binary: Vec<u64> = format!("{:b}", num)
        .chars()
        .map(|x| if x == '0' { 0u64 } else { 1u64 })
        .collect();
    binary
}

pub fn fix_len_binary(num: u64, max: u64) -> Vec<u64> {
    let max = number_to_binary(max);
    let max_len = max.len();
    let mut raw = number_to_binary(num);
    let raw_len = raw.len();
    if raw_len == max_len {
        return raw;
    }
    let mut new = vec![0u64; max_len - raw_len];
    new.append(&mut raw);
    return new;
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
    #[test]
    fn number_to_binary_test() {
        let a = number_to_binary(50);
        println!("a = {:?}", a);
        println!("a len = {:?}", a.len());
    }

    #[test]
    fn fix_len_number_to_binary_test() {
        let b = number_to_binary(50);
        let a = fix_len_binary(2, 50);
        assert_eq!(a.len(), b.len());
    }
}
