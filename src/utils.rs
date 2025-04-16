use std::env;

/// Process environment variables from CLI flags
///
/// This function processes strings in either of these formats:
/// - KEY=VALUE: Uses the provided value
/// - KEY: Takes the value from the current environment
///
/// Returns a vector of environment variables in the format KEY=VALUE
pub fn process_environment_vars(env_flags: &[String]) -> Vec<String> {
    let mut result = Vec::new();

    for env_flag in env_flags {
        // If the flag is just a key (no = sign), get the value from the current environment
        if !env_flag.contains('=') {
            if let Ok(val) = env::var(env_flag) {
                result.push(format!("{}={}", env_flag, val));
            }
        } else {
            // Flag already contains the value (KEY=VALUE format)
            result.push(env_flag.clone());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_process_environment_vars_key_value() {
        let vars = vec![String::from("KEY1=value1"), String::from("KEY2=value2")];
        let result = process_environment_vars(&vars);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "KEY1=value1");
        assert_eq!(result[1], "KEY2=value2");
    }

    #[test]
    fn test_process_environment_vars_existing_key() {
        env::set_var("TEST_ENV_VAR", "test_value");

        let vars = vec![String::from("TEST_ENV_VAR")];
        let result = process_environment_vars(&vars);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "TEST_ENV_VAR=test_value");

        env::remove_var("TEST_ENV_VAR");
    }

    #[test]
    fn test_process_environment_vars_nonexistent_key() {
        env::remove_var("NONEXISTENT_TEST_VAR");

        let vars = vec![String::from("NONEXISTENT_TEST_VAR")];
        let result = process_environment_vars(&vars);

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_process_environment_vars_mixed() {
        env::set_var("TEST_ENV_VAR", "test_value");

        let vars = vec![
            String::from("KEY1=value1"),
            String::from("TEST_ENV_VAR"),
            String::from("NONEXISTENT_TEST_VAR"),
        ];

        let result = process_environment_vars(&vars);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "KEY1=value1");
        assert_eq!(result[1], "TEST_ENV_VAR=test_value");

        env::remove_var("TEST_ENV_VAR");
    }
}

