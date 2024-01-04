# Pipelined Fast-Hotstuff in Rust
[paper](https://arxiv.org/abs/2010.11454)

Notes:
- Happy and sad path are implemented
- The handling of several byzantine attack vectors (e.g. invalid messages, incorrect qc, etc) is implemented but not tested
- Currently, only honest nodes are simulated in `examples/cluster.rs`.
