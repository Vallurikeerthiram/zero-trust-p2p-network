# Architecture & System Diagrams for Zero-Trust P2P Network

This directory contains the production-grade architectural and protocol diagrams designed specifically for **academic research papers (IEEE format)** and **conference / project slide presentations**.

---

## Diagram Index

1. **System Architecture Diagram (`system_architecture.mmd`):**
   - **Type:** Software Infrastructure Architecture Flowchart (Left-to-Right).
   - **Purpose:** Full end-to-end view showing clients, transport framer, core P2P microservices, SQLite reputation datastore, zero-contamination chunk storage, async UDP/nonce daemons, and external STUN/Bootstrap infrastructure.
   - **Best For:** Paper Section III (*System Architecture*) and Overview presentation slide.

2. **RFC 6962 Domain-Separated Merkle Tree (`merkle_verification.mmd`):**
   - **Type:** Hierarchical Tree Flowchart.
   - **Purpose:** Visualizes discrete 64 KB chunks, `0x00` leaf domain separation, `0x01` interior node domain separation, and direct odd-node promotion preventing second pre-image attacks (CVE-2012-2459 mitigation).
   - **Best For:** Paper Section III-B (*Merkle Verification*) and Cryptographic Design slide.

3. **In-Memory Pre-Commit & Anti-Framing Protocol (`protocol_sequence.mmd`):**
   - **Type:** UML Sequence Diagram with Autonumbering.
   - **Purpose:** Step-by-step transaction flow between Downloader, Provider, and Swarm Witnesses showing in-memory pre-commit verification barrier, zero disk contamination, and signed receipt ($\Sigma_{prov}$) verification against malicious slander/framing.
   - **Best For:** Paper Section III-C (*Reputation & Anti-Framing*) and Protocol Walkthrough slide.

4. **Dynamic Peer Reputation & Quarantine State Machine (`reputation_state_machine.mmd`):**
   - **Type:** UML State Diagram (`stateDiagram-v2`).
   - **Purpose:** Illustrates state transitions across Baseline ($T_0=50$), Trusted ($[52, 100]$), Degraded/Quarantined ($[1, 49]$), and permanent Blacklist ($T=0$) with socket termination.
   - **Best For:** Paper Section III-C (*Reputation Engine*) and Security Mitigation slide.

---

## 1. System Architecture Diagram

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
