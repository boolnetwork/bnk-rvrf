mod one_out_of_many;
mod prf;
mod util;
mod vrf;
mod zero_or_one;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_test() {
        let a = format!("{:b}", 50);
        println!("a = {}", a);
    }
}
