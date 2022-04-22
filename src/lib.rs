#![no_std]
pub extern crate alloc;

// mod one_out_of_many;
// mod prf;
// pub mod rvrf;
mod util;
mod zero_or_one;
mod traits;

// pub use one_out_of_many::{Prover, Verifier};
// pub use prf::{PRFProver, PRFVerifier};
// #[cfg(feature = "prove")]
// pub use rvrf::rvrf_prove_simple;
// pub use rvrf::rvrf_verify_simple;
// pub use util::*;

#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_test() {
    }
}
