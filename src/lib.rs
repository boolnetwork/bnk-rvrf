mod one_out_of_many;
mod util;
mod zero_or_one;
mod prf;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_test() {
        let a = format!("{:b}", 50);
        println!("a = {}", a);
    }
}
