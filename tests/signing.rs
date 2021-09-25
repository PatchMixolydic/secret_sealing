use secret_sealing::signing::*;

static ALICE_MESSAGE: &str = "Marisa, I love you.";
static PATCHE_MESSAGE: &str = "Marisa, stop stealing my books.";

#[test]
fn signing_test() {
    let context = SigningContext::new().unwrap();
    let (alice_public_key, alice_private_key) = context.generate_signing_keys().unwrap();
    let (patche_public_key, patche_private_key) = context.generate_signing_keys().unwrap();

    let alice_signature = context
        .sign(&alice_private_key, ALICE_MESSAGE.as_bytes())
        .unwrap();
    let patche_signature = context
        .sign(&patche_private_key, PATCHE_MESSAGE.as_bytes())
        .unwrap();

    // rustfmt wraps these lines, ironically making them less readable
    #[rustfmt::skip]
    {
        assert!(context.verify(&alice_public_key, ALICE_MESSAGE.as_bytes(), &alice_signature).is_ok());
        assert!(context.verify(&alice_public_key, ALICE_MESSAGE.as_bytes(), &patche_signature).is_err());
        assert!(context.verify(&patche_public_key, ALICE_MESSAGE.as_bytes(), &alice_signature).is_err());
        assert!(context.verify(&patche_public_key, ALICE_MESSAGE.as_bytes(), &patche_signature).is_err());

        assert!(context.verify(&patche_public_key, PATCHE_MESSAGE.as_bytes(), &patche_signature).is_ok());
        assert!(context.verify(&patche_public_key, PATCHE_MESSAGE.as_bytes(), &alice_signature).is_err());
        assert!(context.verify(&alice_public_key, PATCHE_MESSAGE.as_bytes(), &patche_signature).is_err());
        assert!(context.verify(&alice_public_key, PATCHE_MESSAGE.as_bytes(), &alice_signature).is_err());
    };
}
