use curv::*;
use std::prelude::v1::*;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

use curv::BigInt;
//use curv::curves::secp256_k1::elliptic::Secp256k1Point;
//use curv::curves::secp256_k1::elliptic::Secp256k1Scalar;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::elliptic::curves::secp256_k1::Secp256k1Point;
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;

pub fn serialize_rand_pk_verify_pad() {
    println!("1");
    let vx = BigInt::from_hex(
        &"ccaf75ab7960a01eb421c0e2705f6e84585bd0a094eb6af928c892a4a2912508".to_string(),
    )
        .unwrap();

    let vy = BigInt::from_hex(
        &"e788e294bd64eee6a73d2fc966897a31eb370b7e8e9393b0d8f4f820b48048df".to_string(),
    )
        .unwrap();

    println!("2");
    Secp256k1Point::from_coor(&vx, &vy); // x and y of size 32

    let x = BigInt::from_hex(
        &"5f6853305467a385b56a5d87f382abb52d10835a365ec265ce510e04b3c3366f".to_string(),
    )
        .unwrap();

    let y = BigInt::from_hex(
        &"b868891567ca1ee8c44706c0dc190dd7779fe6f9b92ced909ad870800451e3".to_string(),
    )
        .unwrap();

    Secp256k1Point::from_coor(&x, &y); // x and y not of size 32 each

    println!("3");
    let r = Secp256k1Point::random_point();
    println!("4");
    let r_expected = Secp256k1Point::from_coor(&r.x_coor().unwrap(), &r.y_coor().unwrap());

    println!("5");
    assert_eq!(r.x_coor().unwrap(), r_expected.x_coor().unwrap());
    assert_eq!(r.y_coor().unwrap(), r_expected.y_coor().unwrap());
}

use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::ErrorKey;


#[should_panic]
fn test_serdes_bad_pk() {
//    let pk = GE::generator();
//    let s = serde_json::to_string(&pk).expect("Failed in serialization");
//    // we make sure that the string encodes invalid point:
//    let s: String = s.replace("79be", "79bf");
//    let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
//    assert_eq!(des_pk, pk);
}


pub fn test_from_bytes() {
    let g = Secp256k1Point::generator();
    let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
    let hash_vec = BigInt::to_bytes(&hash);
    let result = Secp256k1Point::from_bytes(&hash_vec);
    assert_eq!(result.unwrap_err(), ErrorKey::InvalidPublicKey)
}


pub fn test_from_bytes_3() {
    let test_vec = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 2, 3, 4, 5, 6,
    ];
    let result = Secp256k1Point::from_bytes(&test_vec);
    assert!(result.is_ok() | result.is_err())
}


pub fn test_from_bytes_4() {
    let test_vec = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6,
    ];
    let result = Secp256k1Point::from_bytes(&test_vec);
    assert!(result.is_ok() | result.is_err())
}


pub fn test_from_bytes_5() {
    let test_vec = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5,
        6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4,
        5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3,
        4, 5, 6,
    ];
    let result = Secp256k1Point::from_bytes(&test_vec);
    assert!(result.is_ok() | result.is_err())
}


pub fn test_minus_point() {
    let a: FE = ECScalar::new_random();
    let b: FE = ECScalar::new_random();
    let b_bn = b.to_big_int();
    let order = FE::q();
    let minus_b = BigInt::mod_sub(&order, &b_bn, &order);
    let a_minus_b = BigInt::mod_add(&a.to_big_int(), &minus_b, &order);
    let a_minus_b_fe: FE = ECScalar::from(&a_minus_b);
    let base: GE = ECPoint::generator();
    let point_ab1 = base.clone() * a_minus_b_fe;

    let point_a = base.clone() * a;
    let point_b = base.clone() * b;
    let point_ab2 = point_a.sub_point(&point_b.get_element());
    assert_eq!(point_ab1.get_element(), point_ab2.get_element());
}


pub fn test_invert() {
    let a: FE = ECScalar::new_random();
    let a_bn = a.to_big_int();
    let a_inv = a.invert();
    let a_inv_bn_1 = BigInt::mod_inv(&a_bn, &FE::q()).unwrap();
    let a_inv_bn_2 = a_inv.to_big_int();
    assert_eq!(a_inv_bn_1, a_inv_bn_2);
}


pub fn test_scalar_mul_scalar() {
    let a: FE = ECScalar::new_random();
    let b: FE = ECScalar::new_random();
    let c1 = a.mul(&b.get_element());
    let c2 = a * b;
    assert_eq!(c1.get_element(), c2.get_element());
}


pub fn test_pk_to_key_slice() {
    for _ in 1..200 {
        let r = FE::new_random();
        let rg = GE::generator() * r;
        let key_slice = rg.pk_to_key_slice();

        assert!(key_slice.len() == 65);
        assert!(key_slice[0] == 4);

        let rg_prime: GE = ECPoint::from_bytes(&key_slice[1..65]).unwrap();
        assert_eq!(rg_prime.get_element(), rg.get_element());
    }
}


pub fn test_base_point2() {
    /* Show that base_point2() is returning a point of unknown discrete logarithm.
    It is done by using SHA256 repeatedly as a pseudo-random function, with the generator
    as the initial input, until receiving a valid Secp256k1 point. */

    let base_point2 = Secp256k1Point::base_point2();

    let g = Secp256k1Point::generator();
    let mut hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
    hash = HSha256::create_hash(&[&hash]);
    hash = HSha256::create_hash(&[&hash]);

    assert_eq!(hash, base_point2.x_coor().unwrap(),);

    // check that base_point2 is indeed on the curve (from_coor() will fail otherwise)
    assert_eq!(
        Secp256k1Point::from_coor(
            &base_point2.x_coor().unwrap(),
            &base_point2.y_coor().unwrap()
        ),
        base_point2
    );
}
