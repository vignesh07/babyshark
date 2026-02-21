pub fn usage_exit_code(args: &[&str]) -> i32 {
    if args.is_empty() {
        return 2;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_args_returns_2() {
        assert_eq!(usage_exit_code(&[]), 2);
    }
}
