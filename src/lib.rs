#![no_std]
#![allow(clippy::all)]
#![allow(warnings)]

#[cfg(all(feature = "std", feature = "mesalock_sgx", target_env = "sgx"))]
#[macro_use]
extern crate std;
#[cfg(all(feature = "std", feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "rand_sgx")]
pub extern crate rand_sgx;

pub extern crate alloc;
#[macro_use]
extern crate lazy_static;
extern crate sha2;

mod one_out_of_many;
mod prf;
pub mod rvrf;
mod traits;
mod util;
mod zero_or_one;

pub mod ed25519;
#[cfg(feature = "pk256")]
pub mod p256;
#[cfg(feature = "pk256")]
pub mod secp256k1;

#[cfg(feature = "prove")]
pub use rvrf::rvrf_prove_simple;
pub use rvrf::rvrf_verify_simple;

#[cfg(test)]
mod tests {

    #[test]
    fn protocol_test() {}
}
