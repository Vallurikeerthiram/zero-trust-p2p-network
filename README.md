# Zero-Trust Peer-to-Peer (P2P) File Sharing Network

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B.svg)](https://streamlit.io/)
[![Cryptography](https://img.shields.io/badge/Cryptography-41.0+-success.svg)](https://cryptography.io/)

A decentralized, Zero-Trust Peer-to-Peer (P2P) file sharing and distribution system built with Python, cryptographic verification (Merkle Trees & RSA), peer reputation management, dynamic swarm discovery, and interactive real-time Streamlit dashboards.

---

## 🌟 Key Features

- **Zero-Trust Cryptographic Verification**:
  - **Merkle Tree File Integrity**: Files are segmented into discrete binary chunks, hashed using SHA-256, and validated against a computed Merkle Root. Corrupted or tampered chunks are discarded immediately before touching local storage.
  - **Asymmetric Peer Identity**: Nodes maintain unique RSA 2048-bit keypairs for peer identification and address generation.

- **Dynamic Swarm & Distributed Chunk Pulling**:
  - **Distributed Swarm Downloads**: Downloads are round-robin balanced across all available peers holding the requested file, embodying true peer-to-peer distribution.
  - **Auto-Discovery**: Swarm peers dynamically discover and sync active files through automated registry gossip.

- **Real-Time Interactive Dashboard**:
  - Built with Streamlit featuring real-time auto-refresh (`streamlit-autorefresh`).
  - **Live Packet Stream Animation**: Real-time visual pipeline graph displaying chunks as they fly from specific swarm peers to the downloader.
  - **Local Storage Management**: Upload files via drag-and-drop or manage existing local files directly from the UI.

- **Reputation & Blacklisting Engine**:
  - SQLite-backed peer reputation tracking.
  - Nodes that serve valid chunks earn positive trust scores (+1).
  - Nodes serving tampered or malicious chunks (`CORRUPT` prefix) are penalized (-10) and automatically blacklisted from future network communication.

---

## 📁 Repository Structure

```
.
├── src/
│   ├── app/
│   │   └── dashboard.py       # Interactive Streamlit UI dashboard
│   ├── core/
│   │   ├── crypto.py          # MerkleTree, RSA PeerIdentity, and hashing
│   │   ├── file_manager.py    # Chunking, chunk storage, and file reassembly
│   │   ├── p2p_node.py        # Asynchronous P2P network node engine & swarm protocol
│   │   └── reputation.py      # SQLite-based peer reputation & blacklisting engine
│   └── simulation/
│       └── run_sim.py         # Multi-node automated test launcher
├── start_node.py              # CLI launcher with automatic port allocation
├── requirements.txt           # Project dependencies
├── LICENSE                    # MIT License
└── README.md                  # Project documentation
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

## 🛡️ Zero-Trust Security Workflow

1. **File Partitioning**: When a user adds a file, it is split into 64KB chunks and a Merkle Tree is built to generate a cryptographic root hash.
2. **Gossip Protocol**: Only the file metadata (`filename`, `merkle_root`, `total_chunks`) is advertised to peers.
3. **Swarm Request**: When a peer pulls a file, it requests chunks across multiple providers.
4. **Verification**: Each arriving chunk is immediately verified. Tampered chunks trigger an instant penalty and node blacklist.
5. **Reassembly**: Once all valid chunks are collected, the complete file is reassembled and verified against the advertised Merkle Root.

---

## 📜 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more details.
