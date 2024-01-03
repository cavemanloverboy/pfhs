use bls_signatures::{verify_messages, PrivateKey, Serialize};
use borsh::BorshSerialize;

use crate::{
    block::Block,
    certificates::QuorumCertificate,
    crypto::{PublicKey, Signature},
};

#[derive(Debug, BorshSerialize, Clone)]
pub enum MessageType {
    Vote(Vote),
    NewView(NewView),
    Block(Block),
}

#[derive(Debug, BorshSerialize, Hash, PartialEq, Eq, Clone)]
pub struct NewView {
    pub view: u64,
    pub certificate: QuorumCertificate,
}

#[derive(Clone, Debug, BorshSerialize, Hash, PartialEq, Eq)]
pub struct Vote {
    pub view: u64,
    pub blockhash: Signature,
}

#[derive(Debug, Clone)]
pub struct SignedMessage {
    /// The type of message transmitted
    pub message_type: MessageType,

    /// The peer which transmitted this message
    pub transmitter: PublicKey,

    /// Signature of the message payload by the transmitter
    pub signature: Signature,
}

impl SignedMessage {
    /// Verifies signature for the serialized form of the message. In
    /// this poc, messages are always prepended with the transmitter's
    /// publickey due to a possible rogue key attack in the underlying
    /// cryptographic scheme used that requires all messages to be
    /// unique for an aggregated signature.
    pub fn verify(&self) -> bool {
        // Construct signed byte array = pubkey bytes + message
        let mut signed_message = self.transmitter.as_bytes();
        borsh::to_writer(&mut signed_message, &self.message_type)
            .unwrap();

        // Verify
        verify_messages(
            &self.signature.0,
            &[&signed_message],
            &[self.transmitter.0],
        )
    }

    pub fn block(block: Block, signer: &PrivateKey) -> SignedMessage {
        let mut message = signer.public_key().as_bytes();
        let message_type = MessageType::Block(block);
        borsh::to_writer(&mut message, &message_type).unwrap();

        SignedMessage {
            message_type,
            transmitter: PublicKey(signer.public_key()),
            signature: Signature(signer.sign(&message)),
        }
    }

    pub fn vote(vote: Vote, signer: &PrivateKey) -> SignedMessage {
        let mut message = signer.public_key().as_bytes();
        let message_type = MessageType::Vote(vote);
        borsh::to_writer(&mut message, &message_type).unwrap();

        SignedMessage {
            message_type,
            transmitter: PublicKey(signer.public_key()),
            signature: Signature(signer.sign(&message)),
        }
    }
}
