use crate::util::{fix_len_binary, number_to_binary};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use polynomials::*;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_scalar, get_random_scalar, hash_to_scalar, point_to_bytes, scalar_to_bytes,
    BASEPOINT_G1, BASEPOINT_G2,
};
use crate::util::{Com, Secret, Commitment};

#[derive(Copy, Clone, Debug, Default)]
pub struct CRS {
    pub c: RistrettoPoint,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Prover {
    pub crs: CRS,
    pub m: Scalar,
    pub r: Scalar,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Proof {
    pub ca: RistrettoPoint,
    pub cb: RistrettoPoint,
    pub f: Scalar,
    pub za: Scalar,
    pub zb: Scalar,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Verifier {
    pub crs: CRS,
}

impl CRS{
    pub fn new(m:Scalar,r:Scalar) -> Self{
        Self{
            c: Com::commit_scalar_2(m,r).comm.point,
        }
    }
}

impl Prover {
    pub fn new(m:Scalar) -> Prover{
        let r= get_random_scalar();
        Prover{
            crs:CRS::new(m,r),
            m,
            r:r,
        }
    }

    pub fn proof(self) -> Proof{
        let m = self.m.clone();
        let r = self.r.clone();
        let a = get_random_scalar();
        let s = get_random_scalar();
        let t = get_random_scalar();

        let ca = Com::commit_scalar_2(a,s);
        let cb = Com::commit_scalar_2(a*m,t);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(&ca.comm.point));
        hash_vec.append(&mut point_to_bytes(&cb.comm.point));

        let x = hash_to_scalar(&hash_vec);
        let f = m*x+a;
        Proof{
            ca: ca.comm.point,
            cb: cb.comm.point,
            f: f,
            za: r*x+s,
            zb: r*(x-f)+t,
        }
    }
}

impl Verifier {
    pub fn new(crs: CRS) -> Verifier {
        Self{
            crs,
        }
    }

    pub fn verify(self,proof:Proof) -> bool {
        let Proof{ca:ca,cb:cb,f:f,za:za,zb:zb} = proof;
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(&ca));
        hash_vec.append(&mut point_to_bytes(&cb));

        let x = hash_to_scalar(&hash_vec);
        let c = self.crs.c.clone();


        let left_1 = c * x + ca;
        let right_1 = Com::commit_scalar_2(f,za).comm.point;

        let left_2 = c * (x-f) + cb;
        let right_2 = Com::commit_scalar_2(Scalar::zero(),zb).comm.point;

        if left_1 == right_1 && left_2 == right_2{
            return true;
        }else {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Index;

    #[test]
    fn zero_or_one_raw_test() {
        // proof
        let m = Scalar::one();
        let r = get_random_scalar();
        let a = get_random_scalar();
        let s = get_random_scalar();
        let t = get_random_scalar();

        let c = Com::commit_scalar_2(m,r).comm.point;
        let ca = Com::commit_scalar_2(a,s);
        let cb = Com::commit_scalar_2(a*m,t);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(&ca.comm.point));
        hash_vec.append(&mut point_to_bytes(&cb.comm.point));

        let x = hash_to_scalar(&hash_vec);

        let f = m*x+a;
        let ca = ca.comm.point;
        let cb = cb.comm.point;
        let f = f;
        let za = r*x+s;
        let zb = r*(x-f)+t;

        // verify
        let left_1 = c * x + ca;
        let right_1 = Com::commit_scalar_2(f,za).comm.point;

        let left_2 = c * (x-f) + cb;
        let right_2 = Com::commit_scalar_2(Scalar::zero(),zb).comm.point;

        assert_eq!(left_1,right_1);
        assert_eq!(left_2,right_2);
    }

    #[test]
    fn zero_or_one_test() {
        let m = Scalar::zero();
        let p = Prover::new(m);

        let proof = p.proof();

        let v = Verifier::new(p.crs);
        let res = v.verify(proof);
        assert_eq!(res,true);
    }
}