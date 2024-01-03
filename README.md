# Pipelined Fast-Hotstuff in Rust

Notes:
- Happy and sad path are implemented
- The handling of several byzantine attack vectors (e.g. invalid messages, incorrect qc, etc) is implemented but not tested
- Currently, only honest nodes are simulated in `examples/cluster.rs`.