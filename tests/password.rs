use secret_sealing::password;

static PASSWORD: &str = "password";
static BETTER_PASSWORD: &str = "b3tt3r p4$5w0rd!!! (w\"; return main();";

#[test]
fn password_hashing_test() {
    let hash_1 = password::hash(PASSWORD.as_bytes()).unwrap();
    let hash_2 = password::hash(BETTER_PASSWORD.as_bytes()).unwrap();
    assert_ne!(hash_1, hash_2);
    assert!(password::verify(PASSWORD.as_bytes(), &hash_1).is_ok());
    assert!(password::verify(PASSWORD.as_bytes(), &hash_2).is_err());
    assert!(password::verify(BETTER_PASSWORD.as_bytes(), &hash_2).is_ok());
    assert!(password::verify(BETTER_PASSWORD.as_bytes(), &hash_1).is_err());
}
