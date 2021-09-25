use secret_sealing::non_password;

static MESSAGE_1: &str = "hello";
static MESSAGE_2: &str = "world";

#[test]
fn non_password_hash_test() {
    let hash_1 = non_password::hash(MESSAGE_1.as_bytes());
    let hash_2 = non_password::hash(MESSAGE_2.as_bytes());
    assert_ne!(hash_1, hash_2);
    assert_eq!(hash_1, non_password::hash(MESSAGE_1.as_bytes()));
    assert_eq!(hash_2, non_password::hash(MESSAGE_2.as_bytes()));
}
