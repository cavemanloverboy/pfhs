use bls_signatures::{
    verify_messages, PrivateKey, PublicKey, Serialize, Signature,
};
use borsh::BorshSerialize;
use rand::{random, thread_rng};

#[derive(Clone, Debug)]
pub struct Transaction {
    message: Vec<u8>,
    signature: Signature,
    pubkey: PublicKey,
}

impl BorshSerialize for Transaction {
    fn serialize<W: std::io::prelude::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        writer.write_all(&self.message)?;
        writer.write_all(&self.signature.as_bytes())?;
        writer.write_all(&self.pubkey.as_bytes())
    }
}

impl Transaction {
    /// Verifies the internal signature
    pub fn verify(&self) -> bool {
        verify_messages(
            &self.signature,
            &[&self.message],
            &[self.pubkey],
        )
    }

    /// Produces a new random transaction that should have self.verify()
    /// == true
    pub fn new_valid() -> Transaction {
        // Generate new user, message
        let user = PrivateKey::generate(&mut thread_rng());
        let message = (0..128).map(|_| random()).collect();

        // Produce valid signature
        let signature = user.sign(&message);

        // Bundle into transaction
        Transaction {
            message,
            signature,
            pubkey: user.public_key(),
        }
    }

    /// Produces a new random transaction that should have self.verify()
    /// == false
    pub fn new_invalid() -> Transaction {
        // Generate new user, message
        let user = PrivateKey::generate(&mut thread_rng());
        let message = (0..128).map(|_| random()).collect();

        // Produce invalid signature
        // (vanishingly 1 in 256^96 ≈ 10^231 chance of being valid)
        let signature = Signature::from_bytes(&[0; 96]).unwrap();

        // Bundle into transaction
        Transaction {
            message,
            signature,
            pubkey: user.public_key(),
        }
    }
}
