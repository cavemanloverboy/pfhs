use std::thread::JoinHandle;

use pfhs::cluster::setup_cluster;

fn main() {
    let endpoints = setup_cluster(1);

    let handles: Vec<JoinHandle<()>> = endpoints
        .into_iter()
        .map(|mut endpoint| {
            std::thread::spawn(move || endpoint.start_consensus())
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}
