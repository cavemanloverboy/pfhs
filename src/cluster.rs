use std::sync::mpsc::channel;

use bls_signatures::PrivateKey;
use rand::thread_rng;

use crate::{
    crypto::PublicKey,
    endpoint::{Endpoint, Identity, Peer},
};

fn name_gen(i: u64) -> String {
    let generation = i / 5;
    let basename = i % 5;
    match basename {
        0 => format!("alice{generation}"),
        1 => format!("bob{generation}"),
        2 => format!("carol{generation}"),
        3 => format!("dave{generation}"),
        4 => format!("eric{generation}"),
        _ => unreachable!(),
    }
}

pub fn setup_cluster(f: u64) -> Vec<Endpoint> {
    let quorum_size = 3 * f + 1;

    // Set up identities
    let mut identities = vec![];
    for peer in 0..quorum_size {
        let name = name_gen(peer);
        let private_key = PrivateKey::generate(&mut thread_rng());
        identities.push(Identity {
            name: name.leak(),
            public_key: PublicKey(private_key.public_key()),
            private_key: private_key,
            index: peer as u64,
        });
    }

    // Set up peers
    let mut peers: Vec<Vec<Peer>> = (0..quorum_size)
        .map(|_| vec![])
        .collect();
    for one in 0..quorum_size {
        for two in 0..one {
            let (sender_1, receiver_2) = channel();
            let (sender_2, receiver_1) = channel();
            peers[one as usize].push(Peer {
                public_key: identities[two as usize].public_key,
                sender: sender_1,
                receiver: receiver_1,
            });
            peers[two as usize].push(Peer {
                public_key: identities[one as usize].public_key,
                sender: sender_2,
                receiver: receiver_2,
            })
        }
    }

    // Set up endpoints
    let mut endpoints = vec![];
    for (identity, peers) in identities.into_iter().zip(peers) {
        endpoints.push(Endpoint::new_genesis(identity, peers))
    }
    endpoints
}
