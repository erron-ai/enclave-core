use enclave_core::DomainTag;

#[test]
fn rejects_empty_purpose() {
    assert!(DomainTag::new("dorsalmail", "", 1).is_err());
}

#[test]
fn rejects_uppercase_product() {
    assert!(DomainTag::new("DorsalMail", "transit", 1).is_err());
}

#[test]
fn distinct_tuples_distinct_bytes() {
    let a = DomainTag::new("dorsalmail", "transit", 1).unwrap();
    let b = DomainTag::new("dorsalmail", "transit", 2).unwrap();
    let c = DomainTag::new("dorsalfiles", "transit", 1).unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
    assert_ne!(a.as_bytes(), c.as_bytes());
    assert_ne!(b.as_bytes(), c.as_bytes());
}

#[test]
fn encoded_form_is_ascii() {
    let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
    assert_eq!(tag.as_bytes(), b"dorsalmail-transit-v1");
}
