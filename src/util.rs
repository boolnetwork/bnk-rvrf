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
}
