use crate::traits::{Hash, PointTrait, ScalarTrait, HASH};
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
#[cfg(feature = "std-rand")]
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::alloc::string::{String, ToString};
use core::convert::{TryFrom, TryInto};
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar};
use serde_json::{from_slice, to_vec};
use sha2::{Digest, Sha512};
use sha3::Sha3_512;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ScalarType {
    pub data: Scalar,
}

impl ScalarType {
    pub fn from_bytes(bytes: &[u8]) -> Result<ScalarType, String> {
        Ok(ScalarType {
            data: Secret::from_bytes(bytes)?.0,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PointType {
    pub data: RistrettoPoint,
}

impl MulAssign<ScalarType> for ScalarType {
    fn mul_assign(&mut self, rhs: ScalarType) {
        *self = ScalarType {
            data: self.data * rhs.data,
        };
    }
}

impl AddAssign<ScalarType> for ScalarType {
    fn add_assign(&mut self, rhs: ScalarType) {
        *self = ScalarType {
            data: self.data + rhs.data,
        };
    }
}

impl Mul<ScalarType> for ScalarType {
    type Output = ScalarType;
    fn mul(self, other: ScalarType) -> ScalarType {
        ScalarType {
            data: self.data * other.data,
        }
    }
}

impl<'o> Mul<&'o ScalarType> for ScalarType {
    type Output = ScalarType;
    fn mul(self, other: &'o ScalarType) -> ScalarType {
        ScalarType {
            data: self.data * other.data,
        }
    }
}

impl Add<ScalarType> for ScalarType {
    type Output = ScalarType;
    fn add(self, other: ScalarType) -> ScalarType {
        ScalarType {
            data: self.data + other.data,
        }
    }
}

impl Sub<ScalarType> for ScalarType {
    type Output = ScalarType;
    fn sub(self, other: ScalarType) -> ScalarType {
        ScalarType {
            data: self.data - other.data,
        }
    }
}

impl<'o> Sub<&'o ScalarType> for ScalarType {
    type Output = ScalarType;
    fn sub(self, other: &'o ScalarType) -> ScalarType {
        ScalarType {
            data: self.data - other.data,
        }
    }
}

impl Neg for ScalarType {
    type Output = ScalarType;
    fn neg(self) -> ScalarType {
        ScalarType { data: -self.data }
    }
}

impl ScalarTrait for ScalarType {
    type ScalarType = Scalar;

    #[cfg(feature = "std-prove")]
    fn random_scalar() -> Self {
        let mut csprng = OsRng;
        ScalarType {
            data: Scalar::random(&mut csprng),
        }
    }

    #[cfg(feature = "sgx-prove")]
    fn random_scalar() -> Self {
        use rand_sgx::{OsRng, RngCore};
        let mut csprng = OsRng;
        let mut scalar_bytes = [0u8; 64];
        csprng.fill_bytes(&mut scalar_bytes);
        let res = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
        ScalarType { data: res }
    }

    fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        let mut array = [0; 32];
        array.clone_from_slice(&HASH.hash(input));
        ScalarType {
            data: Scalar::from_bytes_mod_order(array),
        }
    }

    fn get_self(&self) -> Self {
        *self
    }

    fn one() -> Self {
        ScalarType {
            data: Scalar::one(),
        }
    }

    fn zero() -> Self {
        ScalarType {
            data: Scalar::zero(),
        }
    }

    fn from_u64(n: u64) -> Self {
        ScalarType {
            data: Scalar::from(n),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.data.as_bytes().to_vec()
    }
}

// ============

impl Mul<ScalarType> for PointType {
    type Output = PointType;

    fn mul(self, scalar: ScalarType) -> PointType {
        PointType {
            data: self.data * scalar.data,
        }
    }
}

impl Mul<&ScalarType> for PointType {
    type Output = PointType;

    fn mul(self, scalar: &ScalarType) -> PointType {
        PointType {
            data: self.data * scalar.data,
        }
    }
}

impl Mul<PointType> for ScalarType {
    type Output = PointType;

    fn mul(self, point: PointType) -> PointType {
        PointType {
            data: self.data * point.data,
        }
    }
}

impl Mul<&PointType> for ScalarType {
    type Output = PointType;

    fn mul(self, point: &PointType) -> PointType {
        PointType {
            data: self.data * point.data,
        }
    }
}

// ==============

impl AddAssign<PointType> for PointType {
    fn add_assign(&mut self, rhs: PointType) {
        *self = PointType {
            data: self.data + rhs.data,
        };
    }
}

impl Add<PointType> for PointType {
    type Output = PointType;
    fn add(self, other: PointType) -> PointType {
        PointType {
            data: self.data + other.data,
        }
    }
}

impl Sub<PointType> for PointType {
    type Output = PointType;
    fn sub(self, other: PointType) -> PointType {
        PointType {
            data: self.data - other.data,
        }
    }
}

impl<'o> Sub<&'o PointType> for PointType {
    type Output = PointType;
    fn sub(self, other: &'o PointType) -> PointType {
        PointType {
            data: self.data - other.data,
        }
    }
}

impl SubAssign for PointType {
    fn sub_assign(&mut self, other: PointType) {
        *self = PointType {
            data: self.data - other.data,
        };
    }
}

impl PointTrait for PointType {
    fn hash_to_point<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        PointType {
            data: RistrettoPoint::hash_from_bytes::<Sha3_512>(input.as_ref()),
        }
    }

    fn generator() -> PointType {
        PointType {
            data: RISTRETTO_BASEPOINT_POINT,
        }
    }

    fn generator_2() -> Self {
        PointType {
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
pub fn ed25519pubkey_to_ristrettopoint(public_keys: Vec<Public>) -> Vec<PointType> {
    let pubkeys: Vec<PointType> = public_keys
        .into_iter()
        .map(|pubkey| PointType {
            data: RistrettoPoint { 0: pubkey.0 .0 },
        })
        .collect();
    pubkeys
}

pub fn intermediary_sk(secret_key: &Secret) -> ScalarType {
    let mut h: Sha512 = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut digest: [u8; 32] = [0u8; 32];

    h.input(secret_key.0.as_bytes());
    hash.copy_from_slice(h.result().as_slice());

    digest.copy_from_slice(&hash[..32]);

    ScalarType {
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
    #[cfg(feature = "prove")]
    pub fn random() -> Self {
        Secret(ScalarType::random_scalar().data)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err("invalid length".into());
        }
        let mut raw_bytes = [0u8; 32];
        raw_bytes.copy_from_slice(bytes);
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
        let compress_ed_y = CompressedEdwardsY::from_slice(bytes);
        let ed_point = compress_ed_y
            .decompress()
            .ok_or_else(|| "CompressedEdwardsY decompress err".to_string())?;
        Ok(Public(RistrettoPoint(ed_point)))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0 .0.compress().as_bytes().to_vec()
    }
}

#[derive(Copy, Clone)]
pub struct Keypair {
    pub secret: Secret,
    pub public: Public,
}

impl Keypair {
    #[cfg(feature = "prove")]
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
            public: (*secret).into(),
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
            s,
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

        h.input(&self.nonce);
        h.input(&message);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.result().as_slice());
        r = Scalar::from_bytes_mod_order_wide(&output);

        R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new();
        h.input(R.as_bytes());
        h.input(public_key.0 .0.compress().as_bytes().to_vec());
        h.input(&message);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.result().as_slice());
        k = Scalar::from_bytes_mod_order_wide(&output);

        s = (k * self.key) + r;

        InternalSignature { R, s }.into()
    }
}

impl<'a> From<&'a Secret> for ExpandedSecretKey {
    fn from(secret_key: &'a Secret) -> ExpandedSecretKey {
        let mut h: Sha512 = Sha512::default();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        h.input(secret_key.0.as_bytes());
        hash.copy_from_slice(h.result().as_slice());

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
        Ok(expanded.sign(message, &self.public))
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

        h.input(signature.R.as_bytes());
        h.input(self.0 .0.compress().as_bytes().to_vec());
        h.input(&message);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.result().as_slice());
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

        h.input(s.0.as_bytes());
        hash.copy_from_slice(h.result().as_slice());

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
        None => Err("ScalarFormatError".to_string()),
        Some(x) => Ok(x),
    }
}

#[test]
fn sign_test() {
    const c_public: [u8; 32] = [
        138u8, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9,
        191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
    ];
    const c_signature: [u8; 64] = [
        145u8, 31, 10, 79, 191, 27, 91, 151, 47, 91, 186, 52, 154, 61, 133, 227, 200, 229, 105, 58,
        94, 149, 143, 188, 232, 33, 127, 172, 198, 190, 104, 188, 67, 181, 79, 181, 13, 82, 145,
        56, 87, 40, 245, 81, 33, 80, 30, 39, 233, 201, 93, 168, 228, 76, 141, 109, 205, 90, 159,
        132, 10, 31, 77, 12,
    ];

    let secret = Secret::from_bytes(&[1; 32]).unwrap();
    let keypair = Keypair::from_secret(&secret);

    assert_eq!(keypair.public.as_bytes(), c_public);
    // std::println!("public: {:?}", keypair.public.as_bytes());
    let message = b"ed25519 signature test";

    let sig = keypair.sign(message).unwrap();
    let verify_result = keypair.verify(message, &sig);

    assert!(verify_result.is_ok());
    // std::println!("sig: {:?}", sig.as_bytes());
    assert_eq!(sig.as_bytes(), c_signature);

    let fake_message = b"ed25519 signature test fake";

    let verify_result = keypair.verify(fake_message, &sig);

    assert!(verify_result.is_err());

    let fake_keypair = Keypair::random();
    let verify_result = fake_keypair.verify(message, &sig);

    assert!(verify_result.is_err());
}
