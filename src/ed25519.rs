use crate::traits::{Hash, PointTrait, ScalarTrait, HASH};
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
#[cfg(feature = "std-rand")]
use rand_core::OsRng;

use crate::alloc::string::{String, ToString};
use core::convert::{TryFrom, TryInto};
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar};
use sha2::{Digest, Sha512};
use sha3::Sha3_512;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScalarSelfDefined {
    pub data: Scalar,
}

impl ScalarSelfDefined {
    pub fn from_bytes(bytes: &[u8]) -> Result<ScalarSelfDefined, String> {
        Ok(ScalarSelfDefined {
            data: Secret::from_bytes(bytes)?.0,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PointSelfDefined {
    pub data: RistrettoPoint,
}

impl MulAssign<ScalarSelfDefined> for ScalarSelfDefined {
    fn mul_assign(&mut self, rhs: ScalarSelfDefined) {
        *self = ScalarSelfDefined {
            data: self.data * rhs.data,
        };
    }
}

impl AddAssign<ScalarSelfDefined> for ScalarSelfDefined {
    fn add_assign(&mut self, rhs: ScalarSelfDefined) {
        *self = ScalarSelfDefined {
            data: self.data + rhs.data,
        };
    }
}

impl Mul<ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn mul(self, other: ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data * other.data,
        }
    }
}

impl<'o> Mul<&'o ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn mul(self, other: &'o ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data * other.data,
        }
    }
}

impl Add<ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn add(self, other: ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data + other.data,
        }
    }
}

impl Sub<ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn sub(self, other: ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data - other.data,
        }
    }
}

impl<'o> Sub<&'o ScalarSelfDefined> for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn sub(self, other: &'o ScalarSelfDefined) -> ScalarSelfDefined {
        ScalarSelfDefined {
            data: self.data - other.data,
        }
    }
}

impl Neg for ScalarSelfDefined {
    type Output = ScalarSelfDefined;
    fn neg(self) -> ScalarSelfDefined {
        ScalarSelfDefined { data: -self.data }
    }
}

impl ScalarTrait for ScalarSelfDefined {
    type ScalarType = Scalar;

    #[cfg(feature = "std-prove")]
    fn random_scalar() -> Self {
        let mut csprng = OsRng;
        ScalarSelfDefined {
            data: Scalar::random(&mut csprng),
        }
    }

    #[cfg(feature = "sgx-prove")]
    fn random_scalar() -> Self {
        use rand_sgx::OsRng;
        use rand_sgx::RngCore;
        let mut csprng = OsRng;
        let mut scalar_bytes = [0u8; 64];
        csprng.fill_bytes(&mut scalar_bytes);
        let res = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
        ScalarSelfDefined { data: res }
    }

    fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        let mut array = [0; 32];
        array.clone_from_slice(&HASH.hash(input));
        ScalarSelfDefined {
            data: Scalar::from_bytes_mod_order(array),
        }
    }

    fn get_self(&self) -> Self {
        *self
    }

    fn one() -> Self {
        ScalarSelfDefined {
            data: Scalar::one(),
        }
    }

    fn zero() -> Self {
        ScalarSelfDefined {
            data: Scalar::zero(),
        }
    }

    fn from_u64(n: u64) -> Self {
        ScalarSelfDefined {
            data: Scalar::from(n),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.data.as_bytes().to_vec()
    }
}

// ============

impl Mul<ScalarSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, scalar: ScalarSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data * scalar.data,
        }
    }
}

impl Mul<&ScalarSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, scalar: &ScalarSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data * scalar.data,
        }
    }
}

impl Mul<PointSelfDefined> for ScalarSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, point: PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data * point.data,
        }
    }
}

impl Mul<&PointSelfDefined> for ScalarSelfDefined {
    type Output = PointSelfDefined;

    fn mul(self, point: &PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data * point.data,
        }
    }
}

// ==============

impl AddAssign<PointSelfDefined> for PointSelfDefined {
    fn add_assign(&mut self, rhs: PointSelfDefined) {
        *self = PointSelfDefined {
            data: self.data + rhs.data,
        };
    }
}

impl Add<PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn add(self, other: PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data + other.data,
        }
    }
}

impl Sub<PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn sub(self, other: PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data - other.data,
        }
    }
}

impl<'o> Sub<&'o PointSelfDefined> for PointSelfDefined {
    type Output = PointSelfDefined;
    fn sub(self, other: &'o PointSelfDefined) -> PointSelfDefined {
        PointSelfDefined {
            data: self.data - other.data,
        }
    }
}

impl SubAssign for PointSelfDefined {
    fn sub_assign(&mut self, other: PointSelfDefined) {
        *self = PointSelfDefined {
            data: self.data - other.data,
        };
    }
}

impl PointTrait for PointSelfDefined {
    fn hash_to_point<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        PointSelfDefined {
            data: RistrettoPoint::hash_from_bytes::<Sha3_512>(input.as_ref()),
        }
    }

    fn generator() -> PointSelfDefined {
        PointSelfDefined {
            data: RISTRETTO_BASEPOINT_POINT,
        }
    }

    fn generator_2() -> Self {
        PointSelfDefined {
            data: RistrettoPoint::hash_from_bytes::<Sha3_512>(
                RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            ),
        }
    }

    fn point_to_bytes(&self) -> Vec<u8> {
        self.data.compress().to_bytes().to_vec()
    }
}

// =============================================================//
pub fn ed25519pubkey_to_ristrettopoint(public_keys: Vec<Public>) -> Vec<PointSelfDefined> {
    let pubkeys: Vec<PointSelfDefined> = public_keys
        .into_iter()
        .map(|pubkey| PointSelfDefined {
            data: RistrettoPoint { 0: pubkey.0 .0 },
        })
        .collect();
    pubkeys
}

pub fn intermediary_sk(secret_key: &Secret) -> ScalarSelfDefined {
    let mut h: Sha512 = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut digest: [u8; 32] = [0u8; 32];

    h.update(secret_key.0.as_bytes());
    hash.copy_from_slice(h.finalize().as_slice());

    digest.copy_from_slice(&hash[..32]);

    ScalarSelfDefined {
        data: mangle_scalar_bits(&mut digest),
    }
}

fn mangle_scalar_bits(bits: &mut [u8; 32]) -> Scalar {
    bits[0] &= 248;
    bits[31] &= 127;
    bits[31] |= 64;

    Scalar::from_bits(*bits)
}

//====================================================================//

pub const SIGNATURE_LENGTH: usize = 64;
#[derive(Copy, Clone)]
pub struct Secret(pub Scalar);

impl Secret {
    pub fn random() -> Self {
        Secret(ScalarSelfDefined::random_scalar().data)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err("invalid length".into());
        }
        let mut raw_bytes = [0u8; 32];
        raw_bytes.copy_from_slice(&bytes);
        let scalar = Scalar::from_bits(raw_bytes);
        Ok(Secret(scalar))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

#[derive(Copy, Clone)]
pub struct Public(pub RistrettoPoint);

impl Public {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err("invalid length".into());
        }
        let compressed_ristretto = CompressedRistretto::from_slice(bytes);
        let ristretto_point = compressed_ristretto
            .decompress()
            .ok_or("invalid bytes".to_string())?;
        Ok(Public(ristretto_point))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.compress().as_bytes().to_vec()
    }
}

#[derive(Copy, Clone)]
pub struct Keypair {
    pub secret: Secret,
    pub public: Public,
}

impl Keypair {
    pub fn random() -> Self {
        let sk = Secret::random();
        let pk: Public = sk.into();
        Keypair {
            secret: sk,
            public: pk,
        }
    }

    pub fn from_secret(secret: &Secret) -> Self {
        Keypair {
            secret: secret.clone(),
            public: secret.clone().into(),
        }
    }
}
#[derive(Copy, Clone)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bytes.try_into()
    }
}
pub struct ExpandedSecretKey {
    pub(crate) key: Scalar,
    pub(crate) nonce: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct InternalSignature {
    pub(crate) R: CompressedEdwardsY,
    pub(crate) s: Scalar,
}

impl InternalSignature {
    /// Convert this `Signature` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];

        signature_bytes[..32].copy_from_slice(&self.R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&self.s.as_bytes()[..]);
        signature_bytes
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<InternalSignature, String> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err("signature lenth".to_string());
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..]);

        let s: Scalar;

        match check_scalar(upper) {
            Ok(x) => s = x,
            Err(x) => return Err(x),
        }

        Ok(InternalSignature {
            R: CompressedEdwardsY(lower),
            s: s,
        })
    }
}

impl TryFrom<&Signature> for InternalSignature {
    type Error = String;

    fn try_from(sig: &Signature) -> Result<InternalSignature, String> {
        InternalSignature::from_bytes(sig.as_bytes())
    }
}

impl From<InternalSignature> for Signature {
    fn from(sig: InternalSignature) -> Signature {
        Signature::from_bytes(&sig.to_bytes()).unwrap()
    }
}

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = String;

    fn try_from(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err("error".to_string());
        }

        if bytes[SIGNATURE_LENGTH - 1] & 0b1110_0000 != 0 {
            return Err("error".to_string());
        }

        let mut arr = [0u8; SIGNATURE_LENGTH];
        arr.copy_from_slice(bytes);
        Ok(Signature(arr))
    }
}

impl ExpandedSecretKey {
    pub fn sign(&self, message: &[u8], public_key: &Public) -> Signature {
        let mut h: Sha512 = Sha512::new();
        let R: CompressedEdwardsY;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        h.update(&self.nonce);
        h.update(&message);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        r = Scalar::from_bytes_mod_order_wide(&output);

        R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new();
        h.update(R.as_bytes());
        h.update(public_key.0.compress().as_bytes());
        h.update(&message);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        k = Scalar::from_bytes_mod_order_wide(&output);

        s = &(&k * &self.key) + &r;

        InternalSignature { R, s }.into()
    }
}

impl<'a> From<&'a Secret> for ExpandedSecretKey {
    fn from(secret_key: &'a Secret) -> ExpandedSecretKey {
        let mut h: Sha512 = Sha512::default();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        h.update(secret_key.0.as_bytes());
        hash.copy_from_slice(h.finalize().as_slice());

        lower.copy_from_slice(&hash[00..32]);
        upper.copy_from_slice(&hash[32..64]);

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        ExpandedSecretKey {
            key: Scalar::from_bits(lower),
            nonce: upper,
        }
    }
}

impl Keypair {
    pub fn sign(&self, message: &[u8]) -> Result<Signature, String> {
        let expanded: ExpandedSecretKey = (&self.secret).into();
        Ok(expanded.sign(&message, &self.public).into())
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), String> {
        self.public.verify(message, signature)
    }
}

impl Public {
    #[allow(non_snake_case)]
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), String> {
        let signature = InternalSignature::try_from(signature)?;

        let mut h: Sha512 = Sha512::new();
        let R: EdwardsPoint;
        let k: Scalar;
        let minus_A: EdwardsPoint = -self.0 .0;

        h.update(signature.R.as_bytes());
        h.update(self.0.compress().as_bytes());
        h.update(&message);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        k = Scalar::from_bytes_mod_order_wide(&output);

        R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &signature.s);

        if R.compress() == signature.R {
            Ok(())
        } else {
            Err("VerifyError".to_string())
        }
    }
}

impl From<Secret> for Public {
    fn from(s: Secret) -> Self {
        let mut h: Sha512 = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut digest: [u8; 32] = [0u8; 32];

        h.update(s.0.as_bytes());
        hash.copy_from_slice(h.finalize().as_slice());

        digest.copy_from_slice(&hash[..32]);

        mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut digest)
    }
}

fn mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(
    bits: &mut [u8; 32],
) -> Public {
    bits[0] &= 248;
    bits[31] &= 127;
    bits[31] |= 64;

    let point = &Scalar::from_bits(*bits) * &constants::ED25519_BASEPOINT_TABLE;

    Public(RistrettoPoint(point))
}

fn check_scalar(bytes: [u8; 32]) -> Result<Scalar, String> {
    if bytes[31] & 240 == 0 {
        return Ok(Scalar::from_bits(bytes));
    }

    match Scalar::from_canonical_bytes(bytes) {
        None => return Err("ScalarFormatError".to_string()),
        Some(x) => return Ok(x),
    };
}

#[test]
fn sign_test() {
    let keypair = Keypair::random();

    let message = b"ed25519 signature test";

    let sig = keypair.sign(message).unwrap();
    let verify_result = keypair.verify(message, &sig);

    assert!(verify_result.is_ok());

    let fake_message = b"ed25519 signature test fake";

    let verify_result = keypair.verify(fake_message, &sig);

    assert!(verify_result.is_err());

    let fake_keypair = Keypair::random();
    let verify_result = fake_keypair.verify(message, &sig);

    assert!(verify_result.is_err());
}
