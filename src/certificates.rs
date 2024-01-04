use bls_signatures::{verify_messages, PrivateKey, Serialize};
use borsh::BorshSerialize;
use indexmap::IndexSet;

use crate::{
    crypto::{aggregate_signatures, PublicKey, Signature},
    message::{MessageType, NewView, Vote},
};

#[derive(Debug, BorshSerialize, Hash, PartialEq, Eq, Clone)]
pub enum QuorumCertificate {
    /// Happy certificate is constructed if the primary receives
    /// n-f votes for previous view.
    ///
    /// In this case, the vote signatures are aggregated (QC).
    Happy(QC),

    /// Sad certificate is constructed if the primary receives
    /// n-f new views for current view.
    ///
    ///
    /// In this case, the qc signatures are aggregated (AggQC).
    Sad(AggQC),

    Genesis,
}

impl QuorumCertificate {
    /// At this stage, it is assumed all vote signatures have been
    /// verified and that they are all for the same view (current_view -
    /// 1), and that the number corresponds to the supermajority (2f+1).
    pub fn from_votes(
        vote: Vote,
        vote_signatures: &Vec<Signature>,
        signers: IndexSet<PublicKey>,
        signer: &PrivateKey,
    ) -> QuorumCertificate {
        let aggregated_signature = aggregate_signatures(&vote_signatures).expect("all messages have been sigverified and are guaranteed to be unique due to pubkey prepend");
        QuorumCertificate::Happy(QC {
            vote,
            aggregated_signature,
            signers,
            signature: Signature({
                // TODO: this allocates which is sad
                let mut message = signer.public_key().as_bytes();
                borsh::to_writer(
                    &mut message,
                    &aggregated_signature.as_bytes(),
                )
                .unwrap();
                signer.sign(message)
            }),
            producer: PublicKey(signer.public_key()),
        })
    }

    /// At this stage, it is assumed all new view signatures have been
    /// verified and that they are all for the same view (current_view),
    /// and that the number corresponds to the supermajority (2f+1).
    pub fn from_newviews(
        etas: Vec<NewView>,
        eta_signatures: Vec<Signature>,
        signers: IndexSet<PublicKey>,
        signer: &PrivateKey,
    ) -> QuorumCertificate {
        // Gather all qcs
        let qcs = etas
            .into_iter()
            .flat_map(|eta| match eta.certificate {
                QuorumCertificate::Happy(qc) => Some(qc),
                _ => None,
            })
            .collect();
        let new_view_aggregated_signature =
            aggregate_signatures(&eta_signatures)
            .expect("all messages have been sigverified and are guaranteed to be unique due to pubkey prepend");

        QuorumCertificate::Sad(AggQC {
            qcs,
            aggregated_signature: new_view_aggregated_signature,
            signers,
            signature: Signature({
                // TODO: this allocates which is sad
                let mut message = signer.public_key().as_bytes();
                borsh::to_writer(
                    &mut message,
                    &new_view_aggregated_signature.as_bytes(),
                )
                .unwrap();
                signer.sign(message)
            }),
            producer: PublicKey(signer.public_key()),
        })
    }
}

#[derive(Debug, BorshSerialize, PartialEq, Eq, Clone)]
pub struct QC {
    /// For a QC, quorum is signing for the same block (in prev view)
    pub vote: Vote,
    pub aggregated_signature: Signature,
    #[borsh(serialize_with = "index_map_impl::serialize_index_set")]
    pub signers: IndexSet<PublicKey>,
    pub signature: Signature,
    pub producer: PublicKey,
}

impl QC {
    /// A QC is valid if
    /// 1) number of signers is supermajority
    /// 2) signers are in quorum
    /// 3) aggregated signature is valid
    pub fn valid(&self, quorum: &[PublicKey]) -> bool {
        let is_supermajority = {
            #[inline(always)]
            || self.signers.len() > 2 * quorum.len() / 3
        };

        let signers_in_quorum = {
            #[inline(always)]
            || {
                for signer in &self.signers {
                    if quorum
                        .iter()
                        .find(|peer| **peer == *signer)
                        .is_none()
                    {
                        return false;
                    }
                }
                true
            }
        };

        let valid_aggregated_signature = {
            #[inline(always)]
            || {
                // PERF TODO: this is super sad lol
                let vote = MessageType::Vote(self.vote.clone());
                let messages: Vec<Vec<u8>> = self
                    .signers
                    .iter()
                    .map(|signer| {
                        let mut message = signer.as_bytes();
                        borsh::to_writer(&mut message, &vote).unwrap();
                        message
                    })
                    .collect();
                let vec_slice: Vec<&[u8]> = messages
                    .iter()
                    .map(|msg| msg.as_slice())
                    .collect();
                let slice_slice = vec_slice.as_slice();
                let signers: Vec<bls_signatures::PublicKey> = self
                    .signers
                    .iter()
                    .map(|pk| pk.0)
                    .collect();

                verify_messages(
                    &self.aggregated_signature,
                    slice_slice,
                    &signers,
                )
            }
        };

        // This is sorted by compute cost and will short circuit if one
        // of them is false
        is_supermajority()
            && signers_in_quorum()
            && valid_aggregated_signature()
    }
}

#[derive(Debug, BorshSerialize, PartialEq, Eq, Clone)]
pub struct AggQC {
    /// For an aggQC, quorum is signing for their own highQC
    pub qcs: Vec<QC>,
    pub aggregated_signature: Signature,
    #[borsh(serialize_with = "index_map_impl::serialize_index_set")]
    pub signers: IndexSet<PublicKey>,

    pub signature: Signature,
    pub producer: PublicKey,
}

impl AggQC {
    /// An AggQC is valid if
    /// 1) number of qcs is supermajority
    /// 2) signers are in quorum
    /// 3) high qc is valid
    /// 4) aggregated signature is valid
    pub fn valid(&self, quorum: &[PublicKey]) -> bool {
        let is_supermajority = {
            #[inline(always)]
            || self.signers.len() > 2 * quorum.len() / 3
        };

        let signers_in_quorum = {
            #[inline(always)]
            || {
                for signer in &self.signers {
                    if quorum
                        .iter()
                        .find(|peer| **peer == *signer)
                        .is_none()
                    {
                        return false;
                    }
                }
                true
            }
        };

        let valid_high_qc = {
            #[inline(always)]
            || {
                let mut high_qc = None;
                let mut high_qc_view = 0;
                for qc in &self.qcs {
                    if qc.vote.view > high_qc_view {
                        high_qc_view = qc.vote.view;
                        high_qc = Some(qc);
                    }
                }

                high_qc.unwrap().valid(quorum)
            }
        };

        let valid_aggregated_signature = {
            #[inline(always)]
            || {
                // PERF TODO: this is super sad lol
                let messages: Vec<Vec<u8>> = self
                    .signers
                    .iter()
                    .zip(self.qcs.iter())
                    .map(|(signer, qc)| {
                        let mut message = signer.as_bytes();
                        borsh::to_writer(
                            &mut message,
                            &qc.aggregated_signature.as_bytes(),
                        )
                        .unwrap();
                        message
                    })
                    .collect();
                let vec_slice: Vec<&[u8]> = messages
                    .iter()
                    .map(|msg| msg.as_slice())
                    .collect();
                let slice_slice = vec_slice.as_slice();
                let signers: Vec<bls_signatures::PublicKey> = self
                    .signers
                    .iter()
                    .map(|pk| pk.0)
                    .collect();

                verify_messages(
                    &self.aggregated_signature,
                    slice_slice,
                    &signers,
                )
            }
        };

        // This is sorted by compute cost and will short circuit if one
        // of them is false
        is_supermajority()
            && signers_in_quorum()
            && valid_high_qc()
            && valid_aggregated_signature()
    }

    pub fn find_high_qc(&self) -> Option<&QC> {
        let mut high_qc = None;
        let mut high_qc_view = 0;
        for qc in &self.qcs {
            if qc.vote.view > high_qc_view {
                high_qc_view = qc.vote.view;
                high_qc = Some(qc);
            }
        }

        high_qc
    }
}

mod index_map_impl {
    use indexmap::IndexSet;

    pub fn serialize_index_set<K, W>(
        obj: &IndexSet<K>,
        writer: &mut W,
    ) -> ::core::result::Result<(), borsh::io::Error>
    where
        K: borsh::ser::BorshSerialize,
        W: borsh::io::Write,
    {
        // TODO: this allocates which is sad
        let values = obj.iter().collect::<Vec<_>>();
        borsh::BorshSerialize::serialize(&values, writer)?;
        Ok(())
    }
}

impl std::hash::Hash for QC {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.vote.hash(state);
        self.aggregated_signature.hash(state);
        for signer in &self.signers {
            signer.hash(state);
        }
        self.signature.hash(state);
        self.producer.hash(state);
    }
}

impl std::hash::Hash for AggQC {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.qcs.hash(state);
        self.aggregated_signature.hash(state);
        for signer in &self.signers {
            signer.hash(state);
        }
        self.signature.hash(state);
        self.producer.hash(state);
    }
}
