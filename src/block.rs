use borsh::BorshSerialize;

use crate::{
    certificates::QuorumCertificate, crypto::Signature,
    transaction::Transaction,
};

#[derive(Clone, Debug, BorshSerialize)]
pub struct Block {
    pub transactions: Vec<Transaction>,
    pub certificate: QuorumCertificate,
    pub last_blockhash: Signature,
    pub view: u64,
}

// TODO: verify block has valid transactions
