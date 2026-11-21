# Space-Efficient Diagrams for IEEE Papers & Slides

In IEEE two-column papers (e.g. 6-page strict limit), **horizontal space is constrained to a single column (~3.5 inches / 88 mm)**. Wide 6-column horizontal diagrams consume excessive page height if stretched or become illegible when shrunk.

To solve this, two **compact, space-optimized diagrams** have been designed specifically to fit within a single column (`\columnwidth`) or a clean slide layout:

1. **Compact 3-Tier System Architecture (`compact_architecture.mmd`):**
   - **FigJam Board:** [Open Compact Architecture in FigJam](https://www.figma.com/online-whiteboard/create-diagram/3bc58890-977e-49f7-abd0-df57e40e9398?utm_source=other&utm_content=edit_in_figjam&oai_id=&request_id=c89c8bcc-4765-453e-9df0-ee3c8eb5bc12)
   - **Height in LaTeX:** Occupies only ~2.2 inches of vertical column space.
2. **Zero-Trust Chunk & Anti-Framing Pipeline (`compact_pipeline.mmd`):**
   - **FigJam Board:** [Open Compact Pipeline in FigJam](https://www.figma.com/online-whiteboard/create-diagram/1be75884-58c5-4de3-a6f5-871a848c8adb?utm_source=other&utm_content=edit_in_figjam&oai_id=&request_id=f6d118b4-bc7e-4f63-b2e4-e01bbe272370)
   - **Height in LaTeX:** Occupies only ~2.0 inches of vertical column space.

---

## Diagram Index & FigJam Links

| Diagram Name | Primary Focus | Best Use Case | Editable FigJam Link |
| :--- | :--- | :--- | :--- |
| **Compact 3-Tier Architecture** | Client, Core Security, Storage & Discovery | Paper Sec. III (Single Column) | [View FigJam](https://www.figma.com/online-whiteboard/create-diagram/3bc58890-977e-49f7-abd0-df57e40e9398?utm_source=other&utm_content=edit_in_figjam&oai_id=&request_id=c89c8bcc-4765-453e-9df0-ee3c8eb5bc12) |
| **Zero-Trust Chunk Pipeline** | In-Memory Barrier & Anti-Framing | Paper Sec. III-B / III-C | [View FigJam](https://www.figma.com/online-whiteboard/create-diagram/1be75884-58c5-4de3-a6f5-871a848c8adb?utm_source=other&utm_content=edit_in_figjam&oai_id=&request_id=f6d118b4-bc7e-4f63-b2e4-e01bbe272370) |
| **Full Horizontal Architecture** | Sprawling Microservices & Daemons | Full-width Slide / Poster | [View FigJam](https://www.figma.com/online-whiteboard/create-diagram/cd80a95f-cde0-4172-b08b-3b9f134b80c2?utm_source=other&utm_content=edit_in_figjam&oai_id=&request_id=820f4e8e-c6c2-4aaf-b0c9-c1ef39308a3a&architecture=true) |
| **RFC 6962 Merkle Tree** | Odd-Node Promotion (CVE-2012-2459) | Paper Sec. III-B | [View FigJam](https://www.figma.com/online-whiteboard/create-diagram/7d413152-4258-491e-a58b-802a03fbbe50?utm_source=other&utm_content=edit_in_figjam&oai_id=&request_id=f61199b5-16b5-4638-ae4f-8f7cc9dcd62b) |
| **Protocol Sequence Diagram** | Transaction Steps & Signed Receipts | Paper Sec. III-A / III-C | [View FigJam](https://www.figma.com/online-whiteboard/create-diagram/cb0019d2-eb38-43e2-a593-676dd20a3c37?utm_source=other&utm_content=edit_in_figjam&oai_id=&request_id=dc02f79e-0c0c-4cec-9595-e83e7c98dbb0) |
| **Reputation State Machine** | Trust Transitions & Socket Drops | Presentation Slide | [View FigJam](https://www.figma.com/online-whiteboard/create-diagram/10b45833-fc6c-4bf9-8b2d-6b98144b1758?utm_source=other&utm_content=edit_in_figjam&oai_id=&request_id=bee914a4-5180-4556-a18e-24b5f25e0dea) |

---

## 1. Compact 3-Tier Architecture Diagram (Single-Column)

```mermaid
flowchart TD
    subgraph L1 ["1. Client & Access Layer"]
        WebHub["Web & Mobile Hub (Streamlit :8500)"]
        NativePeer["Native Workstation Node (:8000)"]
    end

    subgraph L2 ["2. Zero-Trust Security & Processing Engine"]
        WireFramer["Wire Protocol (4B Length Prefix, 16MB DoS Cap)"]
        MerkleEngine["RFC 6962 In-Memory Merkle Verifier (64KB Chunks)"]
        CryptoAuth["2048-bit RSA-PSS Auth & 60s Sliding Nonce Filter"]
        ReputationEngine["Dynamic Trust Engine (0-100 Scoring & Targeted Quarantine)"]
    end

    subgraph L3 ["3. Storage & Hybrid Discovery"]
        LocalStorage[("Zero-Contamination Storage & SQLite DB")]
        DiscoveryNet["Dual Discovery: UDP 50050 Beacon + RFC 5389 STUN / Tracker"]
    end

    WebHub -->|"HTTP / WS"| WireFramer
    NativePeer -->|"Raw TCP"| WireFramer
    WireFramer --> MerkleEngine
    WireFramer --> CryptoAuth
    MerkleEngine -->|"Pre-Commit Pass/Fail"| ReputationEngine
    ReputationEngine -->|"Update Trust"| LocalStorage
    MerkleEngine -->|"Persist Clean Chunks"| LocalStorage
    CryptoAuth -.->|"Signed Presence"| DiscoveryNet
```

---

## 2. Zero-Trust Pipeline & Anti-Framing Workflow (Single-Column)

```mermaid
flowchart TD
    ChunkIn["Inbound Chunk C_k + Proof Pi_k + Signed Receipt Sigma_prov"] --> MemoryBuffer["Volatile RAM Buffer (Zero-Trust Pre-Commit Barrier)"]
    MemoryBuffer --> MerkleCheck{"RFC 6962 Merkle Check: Reconstructed Root == R_F?"}
    MerkleCheck -->|"VALID (Clean Chunk)"| DiskCommit["Commit to Secondary Disk Storage | Trust Reward: +2"]
    MerkleCheck -->|"CORRUPT (Poisoned Chunk)"| DropMemory["Purge RAM Buffer (Zero Disk Contamination) | File Quarantine: Q(P, R_F)=1 | Trust Penalty: -25"]
    DropMemory --> BroadcastAlert["Broadcast Alert with Signed Provider Receipt Sigma_prov"]
    BroadcastAlert --> WitnessCheck{"Witness Verify Receipt Signature?"}
    WitnessCheck -->|"Valid Signature"| SwarmQuarantine["Swarm-Wide Provider Isolation"]
    WitnessCheck -->|"Invalid Signature"| RejectFraming["Reject Slander & Penalize Reporting Peer"]
```

```mermaid
flowchart LR

    subgraph client ["Participating Swarm Clients"]
        webClient["Web & Mobile Browser<br>(Cross-Platform Hub)"]
        desktopPeer["Native Workstation Peer<br>(Python Daemon)"]
    end

    subgraph gateway ["Transport & Gateway Layer"]
        hubGateway["Swarm Web Gateway<br>(Streamlit Port 8500)"]
        wireFramer["Length-Prefixed Wire Framer<br>(4-byte Big-Endian, 16MB Cap)"]
    end

    subgraph service ["Core Zero-Trust Microservices"]
        p2pOrchestrator["P2P Node Orchestrator<br>(Asyncio Event Loop)"]
        cryptoSigner["Crypto Identity & Envelope Signer<br>(2048-bit RSA-PSS, MGF1)"]
        merkleVerifier["In-Memory Merkle Verifier<br>(RFC 6962 Domain Separated)"]
        reputationEngine["Dynamic Trust & Quarantine Engine<br>(Score Dynamics 0-100)"]
    end

    subgraph datastore ["Persistent Storage Layer"]
        sqliteDB[("Peer Reputation Database<br>(SQLite with WAL Mode)")]
        fileStorage[("Verified Chunk Storage<br>(Zero-Contamination Directory)")]
    end

    subgraph async ["Asynchronous Event & Security Daemons"]
        lanBeaconDaemon["UDP Beacon Broadcaster<br>(Port 50050 Presence Beacons)"]
        replayCache["Anti-Replay Nonce Cache<br>(60s Window, Sliding Filter)"]
    end

    subgraph external ["External Discovery Infrastructure"]
        stunReflector["Public STUN Reflectors<br>(RFC 5389 Port 19302)"]
        bootstrapRendezvous["HTTP Rendezvous Tracker<br>(WAN Swarm Registry)"]
    end

    %% Client to Gateway
    webClient <-->|"WebSocket / HTTP"| hubGateway
    desktopPeer <-->|"Raw TCP Socket"| wireFramer
    hubGateway -->|"Local Socket Dispatch"| wireFramer

    %% Gateway to Service
    wireFramer -->|"Decoded Canonical Envelope"| p2pOrchestrator

    %% Service to Service
    p2pOrchestrator -->|"Validate Sender & Sign"| cryptoSigner
    p2pOrchestrator -->|"Verify Chunk Audit Path"| merkleVerifier
    p2pOrchestrator -->|"Update Trust & Quarantine"| reputationEngine
    merkleVerifier -->|"Pre-Commit Decision"| reputationEngine

    %% Service to Datastore
    reputationEngine -->|"Record Behavioral Score"| sqliteDB
    merkleVerifier -->|"Commit Clean Chunk Only"| fileStorage

    %% Service to Async Daemons
    p2pOrchestrator -.->|"Check & Record Nonce"| replayCache
    p2pOrchestrator -.->|"Transmit & Receive Beacons"| lanBeaconDaemon

    %% Service to External
    p2pOrchestrator -.->|"Resolve Public Reflexive IP"| stunReflector
    p2pOrchestrator -.->|"Announce Swarm Membership"| bootstrapRendezvous
```

---

## 2. RFC 6962 Domain-Separated Merkle Tree & Odd-Node Promotion

```mermaid
graph TD
    subgraph Level2 ["Level 2: Merkle Root"]
        Root["Merkle Root (R_F)<br>SHA-256(0x01 || Node_01 || Node_23_promoted)"]
    end

    subgraph Level1 ["Level 1: Interior Nodes"]
        Node01["Interior Node 0-1<br>SHA-256(0x01 || Leaf0 || Leaf1)"]
        Node2Promoted["Directly Promoted Odd Node<br>Leaf 2 (No Duplicate Hashing - CVE-2012-2459 Fix)"]
    end

    subgraph Level0 ["Level 0: Domain-Separated Leaves (64 KB Chunks)"]
        Leaf0["Leaf 0<br>SHA-256(0x00 || Chunk 0)"]
        Leaf1["Leaf 1<br>SHA-256(0x00 || Chunk 1)"]
        Leaf2["Leaf 2 (Odd Leaf)<br>SHA-256(0x00 || Chunk 2)"]
    end

    subgraph RawChunks ["Input File Stream (Chunked)"]
        C0["Chunk 0 (64 KB)"]
        C1["Chunk 1 (64 KB)"]
        C2["Chunk 2 (64 KB)"]
    end

    C0 -->|"Prefix with 0x00"| Leaf0
    C1 -->|"Prefix with 0x00"| Leaf1
    C2 -->|"Prefix with 0x00"| Leaf2

    Leaf0 -->|"Left Child (0x01 Prefix)"| Node01
    Leaf1 -->|"Right Child"| Node01
    Leaf2 -->|"Direct Promotion (Odd Node Rule)"| Node2Promoted

    Node01 -->|"Left Child (0x01 Prefix)"| Root
    Node2Promoted -->|"Right Child"| Root
```

---

## 3. In-Memory Pre-Commit & Anti-Framing Protocol Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Downloader as Downloader Node (P_down)
    actor Provider as Provider Node (P_prov)
    actor Witness as Swarm Witness Peers (P_witness)

    Note over Downloader,Provider: Handshake & Identity Establishment
    Downloader->>Provider: PING (Signed Envelope: Timestamp, Nonce, ID_down)
    Provider-->>Downloader: PONG (Signed Envelope: ID_prov, Trust Verification)

    Note over Downloader,Provider: Discrete Chunk Transfer Request
    Downloader->>Provider: GET_CHUNK (File Root R_F, Chunk Index k)
    Provider-->>Downloader: CHUNK_DATA (Chunk C_k, Merkle Proof Pi_k, Signed Receipt Sigma_prov)

    Note over Downloader: Step 1: Pre-Commit Memory Barrier (RAM Only)
    rect rgb(240, 248, 255)
        Downloader->>Downloader: Verify Merkle Proof: Reconstruct Root H against Expected R_F
        alt Proof Reconstructed Root Matches R_F (Valid Chunk)
            Downloader->>Downloader: Commit C_k to Secondary Disk Storage
            Downloader->>Downloader: Update Provider Trust Score: +2 (Reward)
        else Proof Verification Fails (Corrupted Chunk Detected)
            Downloader->>Downloader: Purge Corrupt Buffer from Memory (0 Bytes to Disk)
            Downloader->>Downloader: File Quarantine: Q(P_prov, R_F) = 1
            Downloader->>Downloader: Penalize Provider Trust Score: -25
            
            Note over Downloader,Witness: Anti-Framing Non-Repudiation Alert Broadcast
            Downloader->>Witness: CORRUPTION_ALERT (Bad ID, Chunk C_k, Signed Receipt Sigma_prov)
            rect rgb(255, 240, 240)
                Witness->>Witness: Verify Provider Signature on Receipt Sigma_prov
                alt Valid Provider Signature Verified (Genuine Alert)
                    Witness->>Witness: Quarantine P_prov for File R_F & Apply -25 Penalty
                else Invalid or Missing Provider Signature (Malicious Framing)
                    Witness->>Witness: Discard Alert & Penalize Slandering Downloader P_down
                end
            end
        end
    end
```

---

## 4. Dynamic Peer Reputation & Quarantine State Machine

```mermaid
stateDiagram-v2
    [*] --> NewPeer: Fresh Device ID Generated (ID = SHA-256(PEM(K_pub)))

    NewPeer --> Baseline: Initial Trust Initialization (T_0 = 50)

    state Baseline {
        [*] --> ActiveStandard
        ActiveStandard: Standard Swarm Participant
        ActiveStandard: Moderate Download Rate Privileges
    }

    Baseline --> Trusted: Valid Chunk Delivered (+2 Reward)
    Trusted --> Trusted: Continuous Honest Serving (Score capped at 100)

    state Trusted {
        [*] --> HighPriority
        HighPriority: High Trust Rank (T in [52, 100])
        HighPriority: Preferred Provider in Swarm Rotation
    }

    Trusted --> Degraded: Single Corrupted Chunk Delivered (-25 Penalty)
    Baseline --> Degraded: Single Corrupted Chunk Delivered (-25 Penalty)

    state Degraded {
        [*] --> TargetedQuarantine
        TargetedQuarantine: File-Specific Quarantine Q(P, R_F) = 1
        TargetedQuarantine: Low Trust Rank (T in [1, 49])
        TargetedQuarantine: Excluded from active download sets for file F
    }

    Degraded --> Trusted: Serves Clean Chunks for Other Files (+2 per chunk)
    Degraded --> Blacklisted: Repeated Corruption / Trust Score Reaches 0

    state Blacklisted {
        [*] --> PermanentDrop
        PermanentDrop: Trust Score T = 0
        PermanentDrop: Transport Socket Dropped on Connection
        PermanentDrop: All Swarm Handshakes Immediately Terminated
    }

    Blacklisted --> [*]: Irreversible Ban (Cryptographic Identity Bound)
```

---

## 5. How to Embed in IEEE LaTeX Papers

Use the standard `figure` environment in your LaTeX paper:

```latex
\begin{figure*}[htbp]
\centering
\includegraphics[width=0.95\textwidth]{figures/system_architecture.pdf}
\caption{Overall Zero-Trust P2P system architecture illustrating client connectivity, wire framing, cryptographic validation services, SQLite reputation engine, and dual-mode discovery.}
\label{fig:system_architecture}
\end{figure*}
```

And for a single-column Merkle tree or sequence diagram:

```latex
\begin{figure}[htbp]
\centering
\includegraphics[width=\columnwidth]{figures/merkle_verification.pdf}
\caption{RFC 6962 domain-separated Merkle tree construction featuring direct odd-node promotion to mitigate CVE-2012-2459 pre-image collision attacks.}
\label{fig:merkle_tree}
\end{figure}
```
