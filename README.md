# Toy Confidential Ledger

The repo contains a toy confidential payment system built on Ethereum. This is for learning purposes only.

- Balances are represented as Pedersen commitments.
- Transfers update commitments homomorphically.
- Zero-knowledge range proofs are verified off-chain by a trusted verifier. If the verifier is malicious, funds can be corrupted.
