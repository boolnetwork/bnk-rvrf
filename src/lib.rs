mod one_out_of_many;
mod prf;
mod rvrf;
mod util;
mod zero_or_one;

pub use one_out_of_many::{Prover, Verifier};
pub use prf::{PRFProver, PRFVerifier};
pub use util::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_test() {
        let a = format!("{:b}", 50);
        println!("a = {}", a);
    }
}
