use secret_sealing::signing::*;

static ALICE_MESSAGE: &str = "Marisa, I love you.";
static PATCHE_MESSAGE: &str = "Marisa, stop stealing my books.";

#[test]
fn signing_test() {
    let (alice_public_key, alice_private_key) = generate_signing_keys().unwrap();
    let (patche_public_key, patche_private_key) = generate_signing_keys().unwrap();

    let alice_signature = sign(&alice_private_key, ALICE_MESSAGE.as_bytes()).unwrap();
    let patche_signature = sign(&patche_private_key, PATCHE_MESSAGE.as_bytes()).unwrap();

    assert!(verify(&alice_public_key, ALICE_MESSAGE.as_bytes(), &alice_signature).is_ok());
    assert!(verify(&alice_public_key, ALICE_MESSAGE.as_bytes(), &patche_signature).is_err());
    assert!(verify(&patche_public_key, ALICE_MESSAGE.as_bytes(), &alice_signature).is_err());
    assert!(verify(&patche_public_key, ALICE_MESSAGE.as_bytes(), &patche_signature).is_err());

    assert!(verify(&patche_public_key, PATCHE_MESSAGE.as_bytes(), &patche_signature).is_ok());
    assert!(verify(&patche_public_key, PATCHE_MESSAGE.as_bytes(), &alice_signature).is_err());
    assert!(verify(&alice_public_key, PATCHE_MESSAGE.as_bytes(), &patche_signature).is_err());
    assert!(verify(&alice_public_key, PATCHE_MESSAGE.as_bytes(), &alice_signature).is_err());
}
