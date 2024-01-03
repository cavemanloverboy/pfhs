use std::{
    collections::{HashMap, VecDeque},
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};

use bls_signatures::{PrivateKey, Serialize};
use indexmap::IndexSet;

use crate::{
    block::Block,
    certificates::{AggQC, QuorumCertificate, QC},
    crypto::{PublicKey, Signature},
    message::{MessageType, NewView, SignedMessage, Vote},
};

const TIMEOUT_MILLIS: u128 = 4_000;

pub struct Endpoint {
    /// Identity of the peer
    identity: Identity,
    peers: Vec<Peer>,
    quorum: Vec<PublicKey>,

    // Instead of sending to ourselves via channel, we keep a self_vote
    self_vote: Option<SignedMessage>,

    /// Current view
    current_view: u64,

    /// FIFO queue for recent views
    recent_views: VecDeque<View>,
}

#[derive(Debug)]
pub struct View {
    pub height: u64,
    pub leader: PublicKey,
    pub block: Block,
    pub blockhash: Signature,
}

impl Endpoint {
    pub fn new_genesis(
        identity: Identity,
        peers: Vec<Peer>,
    ) -> Endpoint {
        let mut quorum: Vec<PublicKey> = peers
            .iter()
            .map(|p| p.public_key)
            .collect();
        quorum.push(identity.public_key);
        Endpoint {
            identity,
            peers,
            quorum,
            self_vote: None,
            current_view: 0,
            recent_views: Default::default(),
        }
    }

    /// Broadcasts a message to all other peers in the network
    pub fn broadcast(&self, message: SignedMessage) {
        for peer in &self.peers {
            peer.sender
                .send(message.clone())
                .expect("receivers are never dropped in this poc");
        }
    }

    /// Sends a message to specific peer in the network
    pub fn send_to(&self, peer: &PublicKey, message: SignedMessage) {
        self.peers
            .iter()
            .find(|p| p.public_key == *peer)
            .expect("guaranteed to exist in this poc")
            .sender
            .send(message)
            .expect("receivers are never dropped in this poc");
    }

    // Obtain an iterator over all outstanding messages. The iterator
    // filters messages that fail sigverify
    fn _pending_messages<'a>(
        &'a self,
    ) -> impl Iterator<Item = SignedMessage> + 'a {
        self.peers
            .iter()
            // This is susceptible to DoS if one peer spams faster than
            // we can process.
            .flat_map(|peer| peer.receiver.try_iter())
            // Discard messages that fail verification
            .filter(|msg| {
                if msg.verify() {
                    true
                } else {
                    println!("message {msg:?} failed sigverify");
                    false
                }
            })
    }

    /// Obtain an incoming message if one exists. Messages that fail
    /// verification are discarded
    fn next_message(&self) -> Option<SignedMessage> {
        for peer in &self.peers {
            // This is susceptible to DoS if one peer spams faster than
            // we can process. Especially one of the first
            // peers in our list.
            if let Ok(msg) = peer.receiver.try_recv() {
                if msg.verify() {
                    return Some(msg);
                } else {
                    println!("message {msg:?} failed sigverify");
                }
            }
        }
        None
    }

    /// Check for pending message from a specific peer. Does not verify!
    fn try_next_message_from(
        &self,
        peer: PublicKey,
    ) -> Option<SignedMessage> {
        self.peers
            .iter()
            .find(|p| p.public_key == peer)
            .and_then(|peer| peer.receiver.try_recv().ok())
    }

    /// Obtain next message from a specific peer.
    /// If it returns None, it is because the message verify failed
    fn _next_message_from(
        &self,
        peer: PublicKey,
    ) -> Option<SignedMessage> {
        self.peers
            .iter()
            .find(|p| p.public_key == peer)
            .and_then(|peer| peer.receiver.recv().ok())
            // Discard message if not valid
            .filter(|msg| {
                if msg.verify() {
                    true
                } else {
                    println!("message {msg:?} failed sigverify");
                    false
                }
            })
    }

    // Size of quorum
    fn quorum_size(&self) -> u64 {
        self.peers.len() as u64 + 1
    }

    pub fn start_consensus(&mut self) {
        // We start view at 1 because view 0 is genesis
        for view in 1..=200 {
            self.current_view = view;

            println!("{}: current view is {view}", self.identity.name);
            match self.primary_for_view(view) {
                // We are primary, run primary logic as per pipelined
                // fast-hotstuff
                Primary::OurTurn => self.primary_logic(),

                // We are not primary, run nonprimary logic
                Primary::Peer(peer) => self.nonprimary_logic(peer),
            };
        }
        #[allow(deprecated)]
        std::thread::sleep_ms(1000);
        println!("\n");
        #[allow(deprecated)]
        std::thread::sleep_ms(1000);
        println!(
            "{}; view {}; blockhash {}",
            self.identity.name,
            self.current_view,
            bs58::encode(
                self.recent_views
                    .back()
                    .unwrap()
                    .blockhash
                    .as_bytes()
            )
            .into_string()
        )
    }

    /// The code to be run for a view when the current node IS a primary
    ///
    ///
    /// Happy Path: Primary can only propose a block during view v if it
    /// can build a QuorumCertificate from n-f votes received for
    /// view v-1. The block only contains QuorumCertificate for view
    /// v-1.
    ///
    /// Sad Path (Primary failure for v-1): Primary can only propose a
    /// block during view v if it has received n-f eta/newview
    /// messages.
    pub fn primary_logic(&mut self) {
        println!("{} is running primary logic", self.identity.name);

        // NewView and Vote signer aggregators
        let mut new_views_received = Vec::<NewView>::new();
        let mut new_views_received_sigs = Vec::<Signature>::new();
        let mut new_views_received_peers = IndexSet::<PublicKey>::new();
        let mut votes_received = HashMap::<
            Vote,
            (Vec<Signature>, IndexSet<PublicKey>),
        >::new();

        // Check if we have a vote
        if let Some(SignedMessage {
            message_type: MessageType::Vote(vote),
            transmitter,
            signature,
        }) = self.self_vote.take()
        {
            votes_received
                .insert(vote, (vec![signature], [transmitter].into()));
        }

        // TODO: for now we assume a primary cannot be a primary twice
        // in a row. If this is relaxed, we need to collect

        let start_timer = Instant::now();
        let certificate: QuorumCertificate = if self.current_view == 1 {
            QuorumCertificate::Genesis
        } else {
            'message_loop: loop {
                // Check if we've timed out
                if start_timer.elapsed().as_millis() > TIMEOUT_MILLIS {
                    return;
                }

                let Some(SignedMessage {
                    message_type,
                    transmitter,
                    signature,
                }) = self.next_message()
                else {
                    // In this poc implementation, busy loop until we
                    // get a new message
                    continue;
                };

                // BYZANTINE:
                // We must check that the transmitter in the (verified)
                // message is a peer in the quorum.
                //
                // PERF todo: pubkey check is cheaper than sigverify, so
                // swap order.
                let not_in_quorum = self
                    .peers
                    .iter()
                    .find(|p| p.public_key == transmitter)
                    .is_none();
                if not_in_quorum {
                    // Ignore this message
                    println!(
                        "received message from peer not in quorum"
                    );
                    continue;
                }

                match message_type {
                    MessageType::Vote(v) => {
                        // If the vote is for the last view append to
                        // votes. Otherwise just
                        // discard.
                        //
                        // TODO:
                        // If the node is behind, they'll see more
                        // recent QCs. Nodes
                        // probably won't run
                        // behind in this POC.
                        if v.view == self.current_view - 1 {
                            votes_received
                                .entry(v)
                                .and_modify(|(sigs, peers)| {
                                    if peers.insert(transmitter) {
                                        sigs.push(signature);
                                    };
                                })
                                .or_insert_with(|| {
                                    (
                                        vec![signature],
                                        [transmitter].into(),
                                    )
                                });

                            // Check if we have enough votes for qc
                            let (vote, (sigs, ref mut peers)) = {
                                let mut most_common_vote = None;
                                let mut high_count = 0;
                                for vote in votes_received.iter_mut() {
                                    if vote.1 .1.len() > high_count {
                                        high_count = vote.1 .1.len();
                                        most_common_vote = Some(vote);
                                    }
                                }
                                most_common_vote.unwrap()
                            };

                            if self.is_supermajority(peers.len()) {
                                // If so make the qc using vote
                                // blockhash
                                println!(
                                    "{} building QC",
                                    self.identity.name
                                );
                                let qc = QuorumCertificate::from_votes(
                                    vote.clone(),
                                    &sigs,
                                    // okay to take because we are
                                    // discarding everything right
                                    // after
                                    core::mem::take(peers),
                                    &self.identity.private_key,
                                );
                                break 'message_loop qc;
                            }
                        }
                    }

                    MessageType::NewView(eta) => {
                        // If the new view message is for next view
                        // append to new views.
                        // Otherwise just
                        // discard.
                        //
                        // TODO:
                        // If the node is behind, they'll see more
                        // recent new views.
                        // Nodes probably
                        // won't run behind in this POC.
                        if eta.view == self.current_view {
                            if new_views_received_peers
                                .insert(transmitter)
                            {
                                new_views_received.push(eta);
                                new_views_received_sigs.push(signature);
                            }

                            // Check if we have enough votes for aggqc
                            if self.is_supermajority(
                                new_views_received_sigs.len(),
                            ) {
                                println!("building aggQC");
                                let aggqc =
                                    QuorumCertificate::from_newviews(
                                        new_views_received,
                                        new_views_received_sigs,
                                        new_views_received_peers,
                                        &self.identity.private_key,
                                    );
                                break 'message_loop aggqc;
                            }
                        }
                    }

                    MessageType::Block(block) => {
                        // Should never receive block as primary. Drop.
                        drop(block);
                    }
                }
            }
        };

        // Build block with certificate
        let block = Block {
            transactions: vec![],
            certificate,
            view: self.current_view,
            last_blockhash: self
                .recent_views
                .back()
                .map(|view| view.blockhash)
                .unwrap_or(Signature(
                    // Genesis
                    bls_signatures::PrivateKey::from_bytes(&[0; 32])
                        .unwrap()
                        .sign(&[]),
                )),
        };

        // Broadcast block
        let block_message = SignedMessage::block(
            block.clone(),
            &self.identity.private_key,
        );
        // Add to our views
        self.recent_views.push_back(View {
            height: self.current_view,
            leader: self.identity.public_key,
            block,
            blockhash: block_message.signature,
        });

        self.broadcast(block_message);
    }

    pub fn is_supermajority(&self, num: usize) -> bool {
        num > 2 * self.quorum_size() as usize / 3
    }

    /// The code to be run for a view when the current node IS NOT a
    /// primary
    pub fn nonprimary_logic(&mut self, primary: PublicKey) {
        let consensus_result;
        println!("{} is running nonprimary logic", self.identity.name);

        // We must wait for block from primary
        let start_timer = Instant::now();
        'receive_block_and_vote: loop {
            if start_timer.elapsed().as_millis() > TIMEOUT_MILLIS {
                return;
            }

            let Some(message) = self.try_next_message_from(primary)
            else {
                continue;
            };

            if !message.verify() {
                println!("message from primary failed sigverify");
                continue;
            }

            match message.message_type {
                MessageType::Block(block) => {
                    println!(
                        "{}: received block {}",
                        self.identity.name,
                        bs58::encode(message.signature.as_bytes())
                            .into_string()
                    );
                    match &block.certificate {
                        QuorumCertificate::Genesis => {
                            // Only true if first view
                            if self.current_view == 1 {
                                // Send vote to next primary
                                let signed_vote = SignedMessage::vote(
                                    Vote {
                                        view: self.current_view,
                                        blockhash: block.last_blockhash,
                                    },
                                    &self.identity.private_key,
                                );
                                self.recent_views.push_back(View {
                                    height: block.view,
                                    leader: message.transmitter,
                                    block: block,
                                    blockhash: message.signature,
                                });

                                match self.primary_for_view(
                                    self.current_view + 1,
                                ) {
                                    #[allow(unused_must_use)]
                                    Primary::OurTurn => {
                                        // Record self vote
                                        self.self_vote
                                            .insert(signed_vote);
                                    }
                                    Primary::Peer(next_primary) => {
                                        // Otherwise send to next
                                        // primary
                                        self.send_to(
                                            &next_primary,
                                            signed_vote,
                                        );
                                    }
                                }

                                // Success means we sent vote
                                println!(
                                    "{}: sent vote",
                                    self.identity.name,
                                );
                                consensus_result =
                                    ConsensusResult::Success;
                                break 'receive_block_and_vote;
                            } else {
                                println!("invalid genesis");
                            }
                        }

                        QuorumCertificate::Happy(qc) => {
                            if qc.valid(&self.quorum) {
                                if pipeline_safe_block_qc(
                                    &block,
                                    &qc,
                                    self.current_view,
                                ) {
                                    // Send vote to next primary
                                    let signed_vote =
                                        SignedMessage::vote(
                                            Vote {
                                                view: self.current_view,
                                                blockhash: block
                                                    .last_blockhash,
                                            },
                                            &self.identity.private_key,
                                        );
                                    self.recent_views.push_back(View {
                                        height: block.view,
                                        leader: message.transmitter,
                                        block: block,
                                        blockhash: message.signature,
                                    });

                                    match self.primary_for_view(
                                        self.current_view + 1,
                                    ) {
                                        #[allow(unused_must_use)]
                                        Primary::OurTurn => {
                                            // Record self vote
                                            self.self_vote
                                                .insert(signed_vote);
                                        }
                                        Primary::Peer(next_primary) => {
                                            // Otherwise send to next
                                            // primary
                                            self.send_to(
                                                &next_primary,
                                                signed_vote,
                                            );
                                        }
                                    }

                                    // Success means we sent vote
                                    println!(
                                        "{}: sent vote",
                                        self.identity.name
                                    );
                                    consensus_result =
                                        ConsensusResult::Success;
                                    break 'receive_block_and_vote;
                                }
                            } else {
                                // TODO: keep proof and blacklist
                                println!("invalid qc");
                            }
                        }
                        QuorumCertificate::Sad(aggqc) => {
                            if aggqc.valid(&self.quorum) {
                                if pipeline_safe_block_aggqc(
                                    &block,
                                    &aggqc,
                                    self.current_view,
                                ) {
                                    // Send vote to next primary
                                    let signed_vote =
                                        SignedMessage::vote(
                                            Vote {
                                                view: self.current_view,
                                                blockhash: block
                                                    .last_blockhash,
                                            },
                                            &self.identity.private_key,
                                        );
                                    self.recent_views.push_back(View {
                                        height: block.view,
                                        leader: message.transmitter,
                                        block: block,
                                        blockhash: message.signature,
                                    });

                                    match self.primary_for_view(
                                        self.current_view + 1,
                                    ) {
                                        #[allow(unused_must_use)]
                                        Primary::OurTurn => {
                                            // Record self vote
                                            self.self_vote
                                                .insert(signed_vote);
                                        }
                                        Primary::Peer(next_primary) => {
                                            // Otherwise send to next
                                            // primary
                                            self.send_to(
                                                &next_primary,
                                                signed_vote,
                                            );
                                        }
                                    }

                                    // Success means we sent vote
                                    println!(
                                        "{}: sent vote",
                                        self.identity.name
                                    );
                                    consensus_result =
                                        ConsensusResult::Success;
                                    break 'receive_block_and_vote;
                                }
                            } else {
                                // TODO: keep proof and blacklist
                                println!("invalid qc");
                            }
                        }
                    }
                }

                _ => {
                    // ignore other message
                    println!("received unexpected ")
                }
            }
        }

        match consensus_result {
            ConsensusResult::Success => {
                let mut rev_iter = self.recent_views.iter().rev();

                let mut block_grandparent: Option<&View> = None;
                let commit_through_grandparent = match (
                    rev_iter.next(),
                    rev_iter.next(),
                    rev_iter.next(),
                ) {
                    (Some(latest), Some(parent), Some(grandparent)) => {
                        block_grandparent = Some(grandparent);
                        let direct_parent = latest.block.last_blockhash
                            == parent.blockhash;
                        let direct_grandparent =
                            parent.block.last_blockhash
                                == grandparent.blockhash;

                        // commit through grandparent
                        direct_parent & direct_grandparent
                    }
                    _ => {
                        // not enough blocks
                        false
                    }
                };

                if commit_through_grandparent {
                    let grandparent =
                        block_grandparent.unwrap().blockhash;
                    while let Some(block) =
                        self.recent_views.pop_front()
                    {
                        let stop = block.blockhash == grandparent;
                        self.execute(block);
                        if stop {
                            break;
                        }
                    }
                }
            }
            ConsensusResult::Timeout => {
                //
            }
        }
    }

    /// Deterministic function that determines primary from view
    pub fn primary_for_view(&self, view: u64) -> Primary {
        // Determine primary index
        let primary_index = view % self.quorum_size();

        if primary_index == self.identity.index {
            // If primary index == our index, we are primary
            return Primary::OurTurn;
        } else {
            // Otherwise, find primary
            for (peer, idx) in self
                .peers
                .iter()
                // Skip over our index
                .zip((0..).filter(|i| *i != self.identity.index))
            {
                if idx == primary_index {
                    return Primary::Peer(peer.public_key);
                }
            }

            unreachable!(
                "early return from loop guaranteed: {}",
                primary_index
            )
        }
    }

    fn execute(&self, grandparent: View) {
        println!(
            "{} committing block {} at height {}",
            self.identity.name,
            bs58::encode(grandparent.blockhash.as_bytes())
                .into_string(),
            grandparent.height
        );
    }
}

#[derive(Debug)]
pub enum ConsensusResult {
    Success,
    Timeout,
}

pub enum Primary {
    OurTurn,
    Peer(PublicKey),
}

#[derive(Debug)]
pub struct Peer {
    pub public_key: PublicKey,
    pub sender: Sender<SignedMessage>,
    pub receiver: Receiver<SignedMessage>,
}

pub struct Identity {
    pub name: &'static str,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    /// Deterministic index determined by sorting. Can be
    /// lexicographically, bytewise, or by another sorting key such
    /// as stake weight.
    pub index: u64,
}

fn pipeline_safe_block_qc(
    block: &Block,
    qc: &QC,
    current_view: u64,
) -> bool {
    // new block
    block.view >= current_view
        //and directly follows block qc points to
        && block.view == qc.vote.view + 1
}

fn pipeline_safe_block_aggqc(
    block: &Block,
    qc: &AggQC,
    current_view: u64,
) -> bool {
    // new block
    block.view >= current_view
        // and extends block qc points to
        && block.last_blockhash
            == qc
                .find_high_qc()
                .unwrap()
                .vote
                .blockhash
}
