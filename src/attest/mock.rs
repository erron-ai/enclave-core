//! Mock PCRs for development mode.

use std::collections::BTreeMap;

use crate::config::env::Environment;

pub fn mock_pcrs(env: Environment) -> BTreeMap<String, String> {
    if env != Environment::Development {
        panic!("mock_pcrs called in non-development environment");
    }
    let mut m = BTreeMap::new();
    m.insert("PCR0".to_owned(), "0".repeat(64));
    m.insert("PCR1".to_owned(), "1".repeat(64));
    m
}
