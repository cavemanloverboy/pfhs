use bls_signatures::{aggregate, verify_messages, PrivateKey};

fn main() {
    // Initialize Agents
    let alice = PrivateKey::new(rand::random::<[u8; 32]>());
    let bob = PrivateKey::new(rand::random::<[u8; 32]>());

    // Construct and sign some message
    // Messages must be distinct due to rogue key attack
    let message = b"gmonad";
    let alice_message = [b"alice".as_ref(), message].concat();
    let bob_message = [b"bob".as_ref(), message].concat();
    let alice_sig = alice.sign(&alice_message);
    let bob_sig = bob.sign(&bob_message);

    // Verify individual signatures
    assert!(verify_messages(
        &alice_sig,
        &[&alice_message],
        &[alice.public_key()]
    ));
    assert!(verify_messages(
        &bob_sig,
        &[&bob_message],
        &[bob.public_key()]
    ));

    // Aggregate and verify sig
    let aggregated_sig = aggregate(&[alice_sig, bob_sig]).unwrap();
    assert!(verify_messages(
        &aggregated_sig,
        &[&alice_message, &bob_message],
        &[alice.public_key(), bob.public_key()]
    ));
}
