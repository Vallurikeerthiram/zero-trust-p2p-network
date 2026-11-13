import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header on pages > 1
        if self._pageNumber > 1:
            self.drawString(54, 752, "Zero-Trust Peer-to-Peer Network -- Architecture & Security Walkthrough")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 746, 558, 746)
            
        # Footer on all pages
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_str)
        self.drawString(54, 32, "Zero-Trust P2P File Sharing System -- Execution Dry Run Report")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 42, 558, 42)
        self.restoreState()

def build_pdf(filename="Zero_Trust_P2P_Security_Explained.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=50,
        bottomMargin=50
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=10
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0F766E"),
        spaceBefore=6,
        spaceAfter=2,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=4
    )

    body_bold = ParagraphStyle(
        'Body_Bold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0F172A")
    )
    
    callout_style = ParagraphStyle(
        'CalloutText',
        parent=body_style,
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#1E3A8A")
    )

    story = []
    
    # ---------------- PAGE 1 ----------------
    story.append(Paragraph("Zero-Trust Peer-to-Peer Network", title_style))
    story.append(Paragraph("<b>End-to-End Execution Trace & Cryptographic Security Walkthrough</b><br/>"
                           "Topology: Peers A, B, C, D, E, F | Files: a.pdf, b.pdf | Defense & Quarantine Mechanics", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563EB"), spaceAfter=8))
    
    summary_data = [[
        Paragraph("<b>EXECUTIVE OVERVIEW:</b> This document gives a literal, step-by-step trace of how your Zero-Trust P2P file-sharing implementation operates in practice. It follows 6 peers (<b>A, B, C, D, E, F</b>) booting up, exchanging RSA cryptographic identities, partitioning files into <b>SHA-256 Merkle Trees</b>, pulling chunks concurrently via <b>round-robin swarm distribution</b>, detecting deliberate byte-corruption by Peer B, and instantly deploying <b>automatic quarantine, reputation penalties, and swarm-wide alert broadcast</b>.", callout_style)
    ]]
    summary_table = Table(summary_data, colWidths=[504])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#EFF6FF")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#93C5FD")),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 6))
    
    story.append(Paragraph("1. Network Topology & Scenario Roles", h1_style))
    cast_data = [
        [Paragraph("<b>Entity</b>", body_bold), Paragraph("<b>Role / Initial State</b>", body_bold), Paragraph("<b>P2P Port / Storage Dir</b>", body_bold), Paragraph("<b>Cryptographic ID</b>", body_bold)],
        [Paragraph("<b>Peer A</b>", body_style), Paragraph("Initial Seeder of <code>a.pdf</code> (240 KB)", body_style), Paragraph("Port 8000<br/><code>node_data_a/</code>", body_style), Paragraph("RSA-2048 Keypair<br/><code>peer_id_A = SHA256(PubA)</code>", code_style)],
        [Paragraph("<b>Peer B</b>", body_style), Paragraph("Initial Seeder of <code>b.pdf</code>. Later turns rogue.", body_style), Paragraph("Port 8001<br/><code>node_data_b/</code>", body_style), Paragraph("RSA-2048 Keypair<br/><code>peer_id_B = SHA256(PubB)</code>", code_style)],
        [Paragraph("<b>Peer C</b>", body_style), Paragraph("Honest Downloader & Second Relay Peer", body_style), Paragraph("Port 8002<br/><code>node_data_c/</code>", body_style), Paragraph("RSA-2048 Keypair<br/><code>peer_id_C = SHA256(PubC)</code>", code_style)],
        [Paragraph("<b>Peer D</b>", body_style), Paragraph("Downloader testing Zero-Trust Verification", body_style), Paragraph("Port 8003<br/><code>node_data_d/</code>", body_style), Paragraph("RSA-2048 Keypair<br/><code>peer_id_D = SHA256(PubD)</code>", code_style)],
        [Paragraph("<b>Peer E, F</b>", body_style), Paragraph("Swarm Witness & Relay Peers", body_style), Paragraph("Ports 8004, 8005<br/><code>node_data_e/, f/</code>", body_style), Paragraph("RSA-2048 Keypairs<br/><code>peer_id_E, peer_id_F</code>", code_style)],
    ]
    cast_table = Table(cast_data, colWidths=[65, 175, 110, 154])
    cast_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(cast_table)
    story.append(Spacer(1, 6))
    
    story.append(Paragraph("2. How Peers Join the Swarm: Step-by-Step Dry Run", h1_style))
    story.append(Paragraph("When commands <code>python start_node.py a</code> through <code>python start_node.py f</code> are launched across terminals, the following execution occurs in code:", body_style))
    
    join_steps = [
        ("Step 2.1: Dynamic Port Allocation & Central Registry (start_node.py:18-69)",
         "<code>get_free_port(8000, 8100)</code> tests socket connectivity. It assigns Port 8000 to A, 8001 to B, 8002 to C, 8003 to D, etc. Each node appends its port to <code>swarm_registry.json</code>: <code>[8000, 8001, 8002, 8003, 8004, 8005]</code>."),
        ("Step 2.2: Cryptographic Identity Generation (src/core/crypto.py: PeerIdentity)",
         "Each peer generates or loads an <b>RSA 2048-bit Private Key</b> (<code>private_key_a.pem</code>). It computes its address: <code>peer_id = SHA256(public_key_bytes)</code>. In Zero-Trust, peers never trust IP addresses because IPs can be spoofed; peers authenticate via cryptographic public key hashes."),
        ("Step 2.3: Socket Server Launch & Storage Binding (src/core/p2p_node.py: start_server)",
         "Node starts an asynchronous TCP server via <code>asyncio.start_server(self.handle_client, host, port)</code> and binds an isolated local storage folder (e.g., <code>node_data_a/</code>). It launches background loop <code>auto_sync_loop()</code> scheduled every 2.0 seconds."),
        ("Step 2.4: Swarm Discovery via Gossip Ping/Pong (src/core/p2p_node.py: auto_sync_loop)",
         "Every 2s, Node B reads <code>swarm_registry.json</code>, finds Peer A at port 8000, and sends a TCP <code>PING</code> message with its identity, port, and shared file list. Node A verifies B is not blacklisted, stores B in its local SQLite database (<code>reputation_a.db</code>) with default <code>trust_score = 50</code>, and responds with <code>PONG</code> containing A's file list. All 6 nodes exchange gossip, creating a fully discovered mesh.")
    ]
    for title, desc in join_steps:
        story.append(Paragraph(f"<b>{title}</b>", h2_style))
        story.append(Paragraph(desc, body_style))
    
    story.append(PageBreak()) # ---------------- PAGE 2 ----------------
    
    story.append(Paragraph("3. Local File Ingestion: a.pdf on Peer A & b.pdf on Peer B", h1_style))
    story.append(Paragraph("In Zero-Trust P2P networks, <b>raw files are never shared directly</b>. Instead, files are partitioned into discrete chunks and represented cryptographically as a <b>Merkle Tree</b>:", body_style))
    
    merkle_desc = """<b>1. Binary File Chunking (src/core/file_manager.py: split_file):</b><br/>
When <code>a.pdf</code> (240 KB) is placed in <code>node_data_a/</code>, it is sliced into 64 KB binary chunks (<code>CHUNK_SIZE = 65536</code>):<br/>
&nbsp;&nbsp;&bull; <b>Chunk 0:</b> Bytes 0 to 65,535 (64 KB)&nbsp;&nbsp;&nbsp;&nbsp;&bull; <b>Chunk 1:</b> Bytes 65,536 to 131,071 (64 KB)<br/>
&nbsp;&nbsp;&bull; <b>Chunk 2:</b> Bytes 131,072 to 196,607 (64 KB)&nbsp;&nbsp;&bull; <b>Chunk 3:</b> Bytes 196,608 to 245,760 (48 KB)<br/><br/>
<b>2. Merkle Tree Generation (src/core/crypto.py: MerkleTree):</b><br/>
&nbsp;&nbsp;&bull; Each chunk is hashed with SHA-256: <code>H0 = SHA256(Chunk0)</code>, <code>H1 = SHA256(Chunk1)</code>, <code>H2 = SHA256(Chunk2)</code>, <code>H3 = SHA256(Chunk3)</code>.<br/>
&nbsp;&nbsp;&bull; Intermediate hashes: <code>H01 = SHA256(H0 + H1)</code>, <code>H23 = SHA256(H2 + H3)</code>.<br/>
&nbsp;&nbsp;&bull; <b>Merkle Root:</b> <code>Root_A = SHA256(H01 + H23)</code> (e.g., <code>4a7f92b...</code>).<br/><br/>
<b>3. Zero-Trust Gossip Broadcast:</b><br/>
Peer A advertises <b>only metadata</b>: <code>{'filename': 'a.pdf', 'merkle_root': '4a7f92b...', 'total_chunks': 4}</code>. The content of <code>a.pdf</code> stays on A's hard drive until an explicit pull request is made."""
    story.append(Paragraph(merkle_desc, body_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("4. Step-by-Step Dry Run: Peer B pulls a.pdf from Peer A", h1_style))
    story.append(Paragraph("When Peer B clicks <b>'Pull File from Swarm'</b> in the dashboard, the following execution occurs in <code>download_file_from_swarm()</code>:", body_style))
    
    pull_table_data = [
        [Paragraph("<b>Step</b>", body_bold), Paragraph("<b>Action on Node B (Downloader)</b>", body_bold), Paragraph("<b>Action on Node A (Provider)</b>", body_bold), Paragraph("<b>Security / Zero-Trust Verification</b>", body_bold)],
        [
            Paragraph("<b>Req Chunk 0</b>", body_style),
            Paragraph("Sends TCP JSON: <code>GET_CHUNK</code> for <code>a.pdf</code>, index <code>0</code>.", body_style),
            Paragraph("Reads 64KB from <code>node_data_a/a.pdf</code>, base64 encodes it, returns payload.", body_style),
            Paragraph("B decodes base64. Verifies data does not start with corruption flag. B calls <code>reputation.update_trust(A, True)</code> (+2 trust). Saves to <code>a.pdf_temp/chunk_0</code>.", body_style)
        ],
        [
            Paragraph("<b>Req Chunks 1, 2, 3</b>", body_style),
            Paragraph("Iterates through indices 1, 2, 3 sequentially.", body_style),
            Paragraph("Serves honest chunks 1, 2, 3.", body_style),
            Paragraph("Each chunk independently verified before touching disk. Node A's trust score reaches 56 in B's local database.", body_style)
        ],
        [
            Paragraph("<b>Reassembly & Root Check</b>", body_style),
            Paragraph("Calls <code>file_manager.reassemble_file()</code>. Stitches chunks 0-3 into <code>node_data_b/a.pdf</code>.", body_style),
            Paragraph("None (Transfer finished).", body_style),
            Paragraph("<b>Global Integrity Check:</b> B re-splits <code>node_data_b/a.pdf</code> and recomputes Merkle Root. Compares with advertised <code>Root_A</code>. <b>Exact match!</b>", body_style)
        ],
        [
            Paragraph("<b>Gossip Sync</b>", body_style),
            Paragraph("B's local directory scanner detects <code>a.pdf</code>. Announces to swarm: <i>'I now also have a.pdf'</i>.", body_style),
            Paragraph("A acknowledges.", body_style),
            Paragraph("The swarm now officially has <b>2 distinct seeders</b> for <code>a.pdf</code>: <b>A and B</b>.", body_style)
        ]
    ]
    pull_table = Table(pull_table_data, colWidths=[65, 140, 140, 159])
    pull_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(pull_table)
    
    story.append(PageBreak()) # ---------------- PAGE 3 ----------------
    
    story.append(Paragraph("5. Multi-Peer Swarm Pull: Peer C pulls a.pdf from A and B", h1_style))
    story.append(Paragraph("Now that both A and B hold <code>a.pdf</code>, when Peer C initiates a pull, the download engine executes <b>Distributed Round-Robin Swarm Balancing</b> (<code>p2p_node.py:357-360</code>):", body_style))
    
    rr_code = """providers = [Peer_A, Peer_B]  # Total 2 providers
ordered_providers = providers[chunk_idx % 2:] + providers[:chunk_idx % 2]

Chunk 0: (0 % 2 = 0) -> Ordered: [A, B] -> Pulled from PEER A
Chunk 1: (1 % 2 = 1) -> Ordered: [B, A] -> Pulled from PEER B
Chunk 2: (2 % 2 = 0) -> Ordered: [A, B] -> Pulled from PEER A
Chunk 3: (3 % 2 = 1) -> Ordered: [B, A] -> Pulled from PEER B"""
    story.append(Table([[Paragraph(f"<pre>{rr_code}</pre>", code_style)]], colWidths=[504], style=[
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
        ('PADDING', (0,0), (-1,-1), 5)
    ]))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Security Guarantees in Multi-Peer Pulling:</b><br/>"
                           "1. <b>Zero-Trust Source Agnosticism:</b> Peer C never trusts any single peer for the whole file. Each chunk is verified independently on arrival.<br/>"
                           "2. <b>Fair Reputation Accrual:</b> Both Peer A and Peer B earn +4 trust points (+2 per valid chunk delivered) in Peer C's SQLite database (<code>reputation_c.db</code>).<br/>"
                           "3. <b>End-to-End Cryptographic Validation:</b> Even though pieces came from two completely different computers, reassembling them generates the identical Merkle Root <code>4a7f92b...</code>.<br/>"
                           "&bull; <b>Status after this phase:</b> Peers A, B, and C all have verified copies of <code>a.pdf</code>!", body_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("6. Adversarial Attack & Zero-Trust Defense: B Corrupts, D Pulls", h1_style))
    story.append(Paragraph("Now suppose <b>Peer B turns malicious</b>. In the Streamlit dashboard under <i>'Adversarial Mode'</i>, Chunk 1 of <code>a.pdf</code> is selected for corruption. Let's trace what happens when <b>Peer D</b> attempts to download <code>a.pdf</code> from the swarm:", body_style))
    
    attack_steps_p1 = [
        ("Phase 6.1: The Tampering on Node B (src/core/p2p_node.py: handle_get_chunk)",
         "Node B's server code checks: <code>if chunk_index in corrupted_indices: chunk_data = b'CORRUPT_POISONED_CHUNK_' + chunk_data</code>. Node B now serves poisoned binary bytes whenever Chunk 1 is requested."),
        ("Phase 6.2: Peer D Starts Swarm Download (src/core/p2p_node.py: download_file_from_swarm)",
         "Healthy providers available to D: <code>[Peer A, Peer B, Peer C]</code> (3 providers).<br/>"
         "&bull; <b>Chunk 0 (idx 0 % 3 = 0):</b> Requested from <b>Peer A</b> -> Clean chunk received -> Verified! Peer A gets +2 trust.<br/>"
         "&bull; <b>Chunk 1 (idx 1 % 3 = 1):</b> Requested from <b>Peer B</b> -> Peer B returns <b>POISONED CHUNK DATA</b>!"),
        ("Phase 6.3: HOW PEER D DETECTS THE CORRUPTION LITERALLY (Line 382)",
         "Before writing any bytes to disk or temp directories, Node D executes the Zero-Trust chunk barrier:<br/>"
         "<code>if chunk_data.startswith(b'CORRUPT'):</code><br/>"
         "<i>Immediate Alert Triggered:</i> <code>[ZERO-TRUST DETECTED] Corrupted chunk 1 received from Peer B!</code><br/>"
         "<i>(Note: If random bits were altered without a prefix, the SHA-256 hash check in <code>verify_chunk()</code> or the post-assembly check <code>tree.root != expected_root</code> detects the hash discrepancy!)</i>")
    ]
    for title, desc in attack_steps_p1:
        story.append(Paragraph(f"<b>{title}</b>", h2_style))
        story.append(Paragraph(desc, body_style))
        
    story.append(PageBreak()) # ---------------- PAGE 4 ----------------
    
    attack_steps_p2 = [
        ("Phase 6.4: DEFENSE ACTION 1 -- Local Quarantine & Heavy Trust Penalty (src/core/reputation.py)",
         "Peer D calls <code>reputation.quarantine_provider_for_file(peer_id_B, 'a.pdf')</code>:<br/>"
         "1. An entry is written to SQLite table <code>file_quarantine</code> in <code>reputation_d.db</code>.<br/>"
         "2. Peer B's trust score is slashed by <b>-25 points</b> (drops from 50 to 25).<br/>"
         "3. If B's score reaches 0, <code>is_blacklisted = 1</code> is permanently activated in the database."),
        ("Phase 6.5: DEFENSE ACTION 2 -- Swarm-Wide Alert Broadcast (src/core/p2p_node.py: broadcast_corruption_alert)",
         "Peer D does not keep this incident to itself. It broadcasts a <code>CORRUPTION_ALERT</code> packet to <b>all other nodes</b> in the network (Peers A, C, E, F), excluding the attacker B:<br/>"
         "&bull; Peers A, C, E, F receive the alert and immediately insert Peer B into their own local <code>file_quarantine</code> tables.<br/>"
         "&bull; A high-visibility <b>Red Security Warning Banner</b> instantly pops up across all connected Streamlit dashboards in real time: <code>[Swarm Alert] Reporter d broadcasted that b served corrupted chunk #1 for a.pdf</code>."),
        ("Phase 6.6: DEFENSE ACTION 3 -- Self-Healing Failover (Line 389: continue)",
         "Peer D's download loop <b>does not crash or abort</b>! It executes <code>continue</code>, discarding B's poisoned chunk and advancing to the next provider in the round-robin order for Chunk 1, which is <b>Peer C</b>.<br/>"
         "&bull; Peer C serves clean Chunk 1 -> Verified -> Peer C gets +2 trust.<br/>"
         "&bull; D downloads remaining chunks from A and C, reassembles the file, and validates the Merkle Root successfully!"),
        ("Phase 6.7: DEFENSE ACTION 4 -- Total Network Isolation",
         "Peer B is permanently marked as <code>[Quarantined - Tampered]</code> for <code>a.pdf</code> across all nodes. In future downloads, B is completely omitted from the providers list. If B attacks again on another file, its trust score reaches 0 and its TCP socket connections are rejected immediately at the handshake (line 185).")
    ]
    for title, desc in attack_steps_p2:
        story.append(Paragraph(f"<b>{title}</b>", h2_style))
        story.append(Paragraph(desc, body_style))
        
    story.append(Spacer(1, 8))
    
    story.append(Paragraph("7. Summary Matrix of Node States After Incident", h1_style))
    matrix_data = [
        [Paragraph("<b>Node</b>", body_bold), Paragraph("<b>Files Stored</b>", body_bold), Paragraph("<b>Trust Score</b>", body_bold), Paragraph("<b>Swarm Status</b>", body_bold), Paragraph("<b>Action Taken / Current State</b>", body_bold)],
        [Paragraph("<b>Peer A</b>", body_style), Paragraph("<code>a.pdf</code>", body_style), Paragraph("58 (+8 reward)", body_style), Paragraph("<b>[Trusted Seeder]</b>", body_style), Paragraph("Quarantined B upon receiving D's broadcast", body_style)],
        [Paragraph("<b>Peer B</b>", body_style), Paragraph("<code>b.pdf</code>, <code>a.pdf</code> (tampered)", body_style), Paragraph("<b>25 (-25 penalty)</b>", body_style), Paragraph("<b>[QUARANTINED]</b>", body_style), Paragraph("Banned from serving <code>a.pdf</code>; alert broadcasted", body_style)],
        [Paragraph("<b>Peer C</b>", body_style), Paragraph("<code>a.pdf</code>", body_style), Paragraph("54 (+4 reward)", body_style), Paragraph("<b>[Trusted Seeder]</b>", body_style), Paragraph("Served clean Chunk 1 during D's failover", body_style)],
        [Paragraph("<b>Peer D</b>", body_style), Paragraph("<code>a.pdf</code> (clean)", body_style), Paragraph("50 (Neutral)", body_style), Paragraph("<b>[Clean Downloader]</b>", body_style), Paragraph("Detected corruption, penalized B, healed via C", body_style)],
        [Paragraph("<b>Peers E, F</b>", body_style), Paragraph("None (Relay)", body_style), Paragraph("50 (Neutral)", body_style), Paragraph("<b>[Swarm Witnesses]</b>", body_style), Paragraph("Updated local quarantine tables against B", body_style)]
    ]
    matrix_table = Table(matrix_data, colWidths=[55, 110, 85, 105, 149])
    matrix_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(matrix_table)
    
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated {filename}")

if __name__ == "__main__":
    out_pdf = "Zero_Trust_P2P_Security_Explained.pdf"
    if len(sys.argv) > 1:
        out_pdf = sys.argv[1]
    build_pdf(out_pdf)
