use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use ed25519_dalek::{PublicKey, SecretKey};
use sha2::{Digest, Sha512};
use zk_utils_test::{get_random_scalar, hash_to_scalar, BASEPOINT_G1, BASEPOINT_G2};

pub fn ed25519pubkey_to_ristrettopoint(public_keys: Vec<PublicKey>) -> Vec<RistrettoPoint> {
    let pubkeys: Vec<RistrettoPoint> = public_keys
        .into_iter()
        .map(|pubkey| {
            let compressed = CompressedEdwardsY {
                0: pubkey.to_bytes(),
            };
            let edwards = compressed.decompress().unwrap();
            RistrettoPoint { 0: edwards }
        })
        .collect();
    pubkeys
}
pub fn intermediary_sk(secret_key: &SecretKey) -> Scalar {
    let mut h: Sha512 = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut digest: [u8; 32] = [0u8; 32];

    h.update(secret_key.as_bytes());
    hash.copy_from_slice(h.finalize().as_slice());

    digest.copy_from_slice(&hash[..32]);

    mangle_scalar_bits(&mut digest)
}

fn mangle_scalar_bits(bits: &mut [u8; 32]) -> Scalar {
    bits[0] &= 248;
    bits[31] &= 127;
    bits[31] |= 64;

    Scalar::from_bits(*bits)
}

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

#[allow(dead_code)]
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

pub fn generate_pk(sk: Scalar) -> RistrettoPoint {
    let commitment_point = RistrettoPoint::multiscalar_mul([sk], &[*BASEPOINT_G1]);
    commitment_point
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

pub fn hash_x(bytes_to_hash: Vec<Vec<u8>>) -> Scalar {
    let mut hash_vec = Vec::new();
    for mut bytes in bytes_to_hash {
        hash_vec.append(&mut bytes)
    }
    hash_to_scalar(&hash_vec)
}

// return x^n
pub fn x_pow_n(x: Scalar, n: u64) -> Scalar {
    let mut x_tmp = Scalar::one();
    for _k in 0..n {
        x_tmp *= x;
    }
    x_tmp
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

    #[test]
    fn x_pow_n_test() {
        let b = x_pow_n(Scalar::from(3u64), 8);
        assert_eq!(b, Scalar::from(6561u64));
    }

    #[test]
    fn kronecker_delta_test() {
        assert_eq!(kronecker_delta(1, 0), Scalar::zero());
        assert_eq!(kronecker_delta(0, 1), Scalar::zero());
        assert_eq!(kronecker_delta(1, 1), Scalar::one());
        assert_eq!(kronecker_delta(0, 0), Scalar::one());
    }
}
