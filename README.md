# Zero-Trust Peer-to-Peer (P2P) File Sharing Network

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B.svg)](https://streamlit.io/)
[![Cryptography](https://img.shields.io/badge/Cryptography-41.0+-success.svg)](https://cryptography.io/)
[![Tests](https://img.shields.io/badge/Tests-Pytest%20Passing-brightgreen.svg)]()

A decentralized, Zero-Trust Peer-to-Peer (P2P) file sharing and distribution system built with Python, cryptographic verification (RFC 6962 Domain-Separated Merkle Trees & RSA-PSS), SQLite-backed peer reputation management, 4-byte framed wire protocol with replay protection, dynamic swarm discovery, and interactive real-time Streamlit dashboards.

---

## 🌟 Key Features

- **Zero-Trust Cryptographic Verification**:
  - **RFC 6962 Domain-Separated Merkle Trees**: Files are segmented into discrete 64 KB binary chunks. Leaf hashes use `\x00 || chunk` and interior nodes use `\x01 || left || right`. Odd-node duplicate pre-image collisions (CVE-2012-2459) are eliminated via direct promotion.
  - **Sibling-Hash Inclusion Proofs**: Chunks are verified against authentic Merkle audit paths (`verify_chunk_proof`) **strictly before** any bytes are saved to disk. Corrupted chunks are discarded immediately with zero disk persistence.
  - **Asymmetric Peer Identity**: Nodes generate unique RSA 2048-bit keypairs stored with restricted permissions (`0o600` / Windows ACLs). Node addresses are derived cryptographically as `SHA-256(public_key_pem)`.

- **Hardened Wire Protocol & Transport Security**:
  - **4-Byte Length-Prefixed TCP Framing**: Solves TCP stream fragmentation and coalescing with a 4-byte big-endian length prefix and a 16 MB maximum message guard against DoS.
  - **RSA-PSS Signed Control Envelopes**: All control messages (`PING`, `PONG`, `GET_CHUNK`, `CHUNK_DATA`, `SHARE_FILE_INFO`, `CORRUPTION_ALERT`) are wrapped in canonical JSON envelopes signed with RSA-PSS SHA-256.
  - **Anti-Replay Protection**: Enforces a 60-second sliding timestamp drift window combined with an in-memory nonce deduplication cache.
  - **Path Traversal Defense**: All filenames and chunk paths are sanitized against directory traversal (`..`, absolute paths, null bytes, UNC paths, and reserved OS device names) and verified via `os.path.commonpath`.

- **Reputation & Anti-Framing Defense Engine**:
  - SQLite-backed peer trust score tracking with thread-safe connection locking.
  - **Scoring Formula**:
    - Initial baseline trust: `50`
    - Valid chunk delivery reward: `+2` (capped at `100`)
    - Corrupted/tampered chunk penalty: `-25` (floored at `0`)
    - Permanent Blacklist threshold: `0`
  - **Verifiable File Quarantine**: Providers serving corrupt data are quarantined specifically for that file.
  - **Anti-Framing Cryptographic Proof**: `CORRUPTION_ALERT` broadcasts require non-repudiable provider-signed response receipts matching chunk index, filename, and Merkle root before altering reputation or quarantine status.

- **Dynamic Swarm & Distributed Chunk Pulling**:
  - **Distributed Swarm Downloads**: Downloads are round-robin balanced across all healthy providers holding the requested Merkle root (`file_id`).
  - **Auto-Discovery**: Swarm peers dynamically discover and sync active files through automated registry gossip.
  - **Zero Scoping Leaks**: Reputation penalties in multi-provider transfers are strictly targeted to the specific offending peer.

- **Real-Time Interactive Dashboard**:
  - Built with Streamlit featuring real-time auto-refresh (`streamlit-autorefresh`).
  - **Live Transfer Stream Visualizer**: Real-time packet pipeline displaying chunks in transit.
  - **Local Storage Management**: Upload files with automated path sanitization and immediate swarm gossip broadcast.
  - **Thread-Safe Async Coordination**: UI commands dispatched to the node's background event loop via `asyncio.run_coroutine_threadsafe`.

---

## 📁 Repository Structure

```
.
├── src/
│   ├── app/
│   │   └── dashboard.py          # Interactive Streamlit UI dashboard
│   ├── core/
│   │   ├── crypto.py             # RFC 6962 MerkleTree, RSA-PSS PeerIdentity, key permissions
│   │   ├── file_manager.py       # Chunking, path sanitization, 0-byte file support
│   │   ├── p2p_node.py           # Framed P2P network node, signed envelopes, swarm verification
│   │   └── reputation.py         # SQLite peer reputation, blacklisting, and quarantine engine
│   └── simulation/
│       └── run_sim.py            # Multi-node automated test launcher
├── tests/                        # 4-Tier Automated Pytest Test Suite (>390 tests)
│   ├── conftest.py               # Shared test fixtures, mock identities, and sockets
│   ├── test_tier1_crypto.py      # Tier 1: MerkleTree, proofs, RSA-PSS signatures
│   ├── test_tier1_file_manager.py# Tier 1: Path sanitization, chunking, 0-byte files
│   ├── test_tier1_p2p_node.py    # Tier 1: Core P2P networking and state
│   ├── test_tier1_reputation.py  # Tier 1: SQLite reputation and blacklisting
│   ├── test_tier1_transport.py   # Tier 1: 4-byte framing, signed envelopes, replay cache
│   ├── test_tier2_negative.py    # Tier 2: Boundary and negative attack tests
│   ├── test_tier3_cross_feature.py # Tier 3: Cross-feature integrations
│   ├── test_tier4_scenarios.py   # Tier 4: Multi-peer real-world scenarios
│   ├── test_challenger_m*.py     # Adversarial challenger and framing suites
├── start_node.py                 # CLI launcher with automatic port allocation
├── requirements.txt              # Project dependencies
├── LICENSE                       # MIT License
└── README.md                     # Project documentation
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.9 or higher
- Git

### 2. Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/Vallurikeerthiram/zero-trust-p2p-network.git
cd zero-trust-p2p-network
pip install -r requirements.txt
```

---

## 💻 Running the Swarm

### Option A: Manual Multi-Node Swarm (Recommended for testing UI)

Open separate terminal windows and start individual nodes with custom aliases:

**Terminal 1 (Node Alice):**
```bash
python start_node.py a
```

**Terminal 2 (Node Bob):**
```bash
python start_node.py b
```

**Terminal 3 (Node Charlie):**
```bash
python start_node.py c
```

Each command automatically:
- Assigns available P2P communication and Streamlit UI ports.
- Creates an isolated storage directory (`node_data_a/`, `node_data_b/`, etc.).
- Registers the node in the swarm.
- Launches the web browser UI automatically.

### Option B: Automated Simulation Swarm

To launch a predefined 3-node swarm (ports 8001, 8002, 8003) simultaneously:

```bash
python src/simulation/run_sim.py
```

---

## 🧪 Running Automated Tests

Run the full automated test suite covering unit tests, negative attacks, framing defense, and swarm scenarios:

```bash
pytest -v
```

---

## 🛡️ Zero-Trust Security Workflow

1. **File Partitioning**: When a user adds a file, it is split into 64 KB binary chunks. An RFC 6962 domain-separated Merkle Tree (`\x00` leaf prefix, `\x01` interior node prefix) computes the immutable root hash.
2. **Gossip Protocol**: Nodes advertise verified 4-tuples (`filename`, `file_size`, `merkle_root`, `total_chunks`) via RSA-PSS signed `SHARE_FILE_INFO` messages.
3. **Swarm Request**: When a peer pulls a file, requests for chunks are distributed round-robin across healthy swarm providers.
4. **Pre-Disk Proof Verification**: Each chunk received is cryptographically validated using `MerkleTree.verify_chunk_proof` against the expected Merkle root before disk writes.
5. **Targeted Defense**: If a chunk fails verification, strictly the offending provider is penalized (-25) and quarantined for that file. An authentic proof-backed `CORRUPTION_ALERT` is broadcast to the swarm.
6. **Self-Healing Reassembly**: The downloader continues pulling from remaining honest peers. Once all verified chunks are collected, the file is reassembled and final root integrity is confirmed.

---

## 📜 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more details.
