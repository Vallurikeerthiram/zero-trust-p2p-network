# Zero-Trust Peer-to-Peer (P2P) File Sharing Network

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B.svg)](https://streamlit.io/)
[![Cryptography](https://img.shields.io/badge/Cryptography-41.0+-success.svg)](https://cryptography.io/)
[![Tests](https://img.shields.io/badge/Tests-739%20Passing-brightgreen.svg)]()

A decentralized, Zero-Trust Peer-to-Peer (P2P) file sharing and distribution system built with Python, cryptographic verification (RFC 6962 Domain-Separated Merkle Trees & RSA-PSS), SQLite-backed peer reputation management, 4-byte framed wire protocol with replay protection, **dual-mode hybrid discovery (LAN UDP 50050 broadcast + WAN RFC 5389 STUN & Bootstrap Tracker)**, human-friendly username abstraction over cryptographic Device IDs, and interactive real-time Streamlit dashboards.

---

## 🌟 Key Features

- **Zero-Trust Cryptographic Verification**:
  - **RFC 6962 Domain-Separated Merkle Trees**: Files are segmented into discrete 64 KB binary chunks. Leaf hashes use `\x00 || chunk` and interior nodes use `\x01 || left || right`. Odd-node duplicate pre-image collisions (CVE-2012-2459) are eliminated via direct promotion.
  - **Sibling-Hash Inclusion Proofs**: Chunks are verified against authentic Merkle audit paths (`verify_chunk_proof`) **strictly before** any bytes are saved to disk. Corrupted chunks are discarded immediately with zero disk persistence.
  - **Asymmetric Peer Identity**: Nodes generate unique RSA 2048-bit keypairs stored with restricted permissions (`0o600` / Windows ACLs). Cryptographic Device IDs are derived as `SHA-256(public_key_pem)`.
  - **Human-Friendly Usernames**: Users select human-readable aliases (`Alice`, `Bob`, `Keerthi`) for outward display in the UI and peer rosters, while all security operations remain strictly bound to cryptographic Device IDs.

- **Dual-Mode Hybrid Discovery (Real-World Multi-Machine Networking)**:
  - **Local Wi-Fi Auto-Discovery (LAN UDP Beacon)**: Broadcasts presence on UDP port `50050` with sub-second pairing (17–51 ms) across laptops on the same Wi-Fi with zero manual configuration.
  - **Internet WAN Discovery (STUN & Cloud Bootstrap Tracker)**: Integrates an RFC 5389 binary STUN client (`stun.l.google.com`) for public NAT address resolution and an asynchronous HTTP Bootstrap Tracker server for cross-network rendezvous.
  - **Manual Direct Connect**: Form-based direct connection widget in the Streamlit UI supporting direct `IP:Port` pairing with instant feedback.
  - **Multi-Interface 0.0.0.0 Binding**: Default listener binds across all network adapters while dynamically advertising reachable local LAN or public WAN addresses.

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
  - **Network & Swarm Card**: Displays username, local LAN IP, public WAN STUN IP, listening port, and connection status.
  - **Manual Connect Form**: Allows direct connection to any peer by IP and Port.
  - **Live Transfer Stream Visualizer**: Real-time packet pipeline displaying chunks in transit.
  - **Local Storage Management**: Upload files with automated path sanitization and immediate swarm gossip broadcast.
  - **Thread-Safe Async Coordination**: UI commands dispatched to the node's background event loop via `asyncio.run_coroutine_threadsafe`.

---

## 📁 Repository Structure

```
.
├── src/
│   ├── app/
│   │   └── dashboard.py          # Interactive Streamlit UI dashboard with manual connect
│   ├── core/
│   │   ├── crypto.py             # RFC 6962 MerkleTree, RSA-PSS PeerIdentity, key permissions
│   │   ├── file_manager.py       # Chunking, path sanitization, 0-byte file support
│   │   ├── p2p_node.py           # 0.0.0.0 framed P2P node, signed envelopes, swarm verification
│   │   └── reputation.py         # SQLite peer reputation, blacklisting, and quarantine engine
│   ├── discovery/
│   │   ├── stun_client.py        # RFC 5389 STUN NAT resolution & public IP discovery
│   │   ├── lan_beacon.py         # UDP 50050 broadcast beacon for sub-second Wi-Fi discovery
│   │   ├── tracker_client.py     # Background client heartbeating to bootstrap tracker
│   │   └── bootstrap_server.py   # Standalone HTTP rendezvous tracker server
│   └── simulation/
│       └── run_sim.py            # Multi-node automated test launcher
├── tests/                        # 739 Automated Pytest Test Cases (100% Pass Rate)
│   ├── conftest.py               # Global test fixtures, mock identities, offline guards
│   ├── test_tier1_crypto.py      # Tier 1: MerkleTree, proofs, RSA-PSS signatures
│   ├── test_tier1_file_manager.py# Tier 1: Path sanitization, chunking, 0-byte files
│   ├── test_tier1_p2p_node.py    # Tier 1: Core P2P networking and state
│   ├── test_tier1_reputation.py  # Tier 1: SQLite reputation and blacklisting
│   ├── test_tier1_transport.py   # Tier 1: 4-byte framing, signed envelopes, replay cache
│   ├── test_tier2_negative.py    # Tier 2: Boundary and negative attack tests
│   ├── test_tier3_cross_feature.py # Tier 3: Cross-feature integrations
│   ├── test_tier4_scenarios.py   # Tier 4: Multi-peer real-world scenarios
│   ├── test_discovery_*.py       # Discovery tests: LAN beacon, STUN RFC 5389, Tracker
│   ├── test_manual_connect.py    # Direct IP:Port connection & validation tests
│   └── test_challenger_m*.py     # Adversarial challenger and framing suites
├── start_node.py                 # CLI launcher with interactive username prompt & discovery
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

### Option A: Real-World Distributed Network (Across Multiple Laptops)

To run across different machines on the same Wi-Fi or across the Internet:

1. **Start on Laptop 1 (e.g. Alice):**
   ```bash
   python start_node.py -u Alice -d
   ```

2. **Start on Laptop 2 (e.g. Bob):**
   ```bash
   python start_node.py -u Bob -d
   ```

Nodes on the same Wi-Fi will automatically discover each other in under 1 second via UDP port `50050`!

To connect across different networks or over the Internet:
- Use the **Connect to Peer (Manual)** box on your Streamlit dashboard and enter the remote peer's `IP:Port`.
- Or run a central Bootstrap Tracker:
  ```bash
  python -m src.discovery.bootstrap_server --port 9000
  ```
  And start nodes with:
  ```bash
  python start_node.py -u Alice -d --tracker-url http://YOUR_TRACKER_IP:9000
  ```

### Option B: Local Multi-Node Testing on a Single Machine

Open separate terminal windows:

**Terminal 1:**
```bash
python start_node.py -u Alice
```

**Terminal 2:**
```bash
python start_node.py -u Bob
```

### Option C: Automated 3-Node Simulation Swarm

To launch the predefined 3-node simulation cluster (ports 8501, 8502, 8503) simultaneously:

```bash
python src/simulation/run_sim.py
```

---

## 🧪 Running Automated Tests

Run the full automated test suite covering all 10 project milestones:

```bash
pytest -v
```

All 739 test cases execute deterministically with offline isolation.
