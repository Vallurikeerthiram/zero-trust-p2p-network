import streamlit as st
import threading
import asyncio
import os
import sys
import json
import io
from streamlit_autorefresh import st_autorefresh

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from src.core.p2p_node import P2PNode
from src.discovery.stun_client import get_lan_ip
from src.core.swarm_hub import register_node_port, unregister_node_port, get_free_port

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

st.set_page_config(page_title="Zero-Trust P2P", layout="wide")

# Refresh the UI every 2.5 seconds dynamically
st_autorefresh(interval=2500, key="p2p_refresh")

PORT = int(os.environ.get("P2P_PORT", 8000))
NODE_NAME = os.environ.get("P2P_USERNAME") or os.environ.get("NODE_NAME", "")
ident = NODE_NAME if NODE_NAME else str(PORT)

HOST = os.environ.get("P2P_HOST", "127.0.0.1")
ADVERTISE_HOST = os.environ.get("P2P_ADVERTISE_HOST")
ENABLE_DISCOVERY = os.environ.get("P2P_ENABLE_DISCOVERY", os.environ.get("AUTO_DISCOVERY", "0")).lower() in ("1", "true", "yes")
TRACKER_URL = os.environ.get("P2P_TRACKER_URL") or os.environ.get("BOOTSTRAP_TRACKER_URL")
BEACON_PORT = int(os.environ.get("P2P_BEACON_PORT", 50050))
IS_HUB_MODE = os.environ.get("SWARM_HUB_MODE", "0").lower() in ("1", "true", "yes")
ST_SERVER_PORT = int(os.environ.get("STREAMLIT_PORT", "8500"))

DB_PATH = f"reputation_{ident}.db"
STORAGE_DIR = os.environ.get("STORAGE_DIR", f"node_data_{ident}")

@st.cache_resource
def get_p2p_node(host, port, db_path, storage_dir, name, advertise_host=None, enable_discovery=False, tracker_url=None, beacon_port=50050):
    node = P2PNode(
        host=host,
        port=port,
        db_path=db_path,
        storage_dir=storage_dir,
        node_name=name,
        advertise_host=advertise_host,
        enable_discovery=enable_discovery,
        tracker_url=tracker_url,
        beacon_port=beacon_port
    )
    def start_node_in_background():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(node.start_server())
    threading.Thread(target=start_node_in_background, daemon=True).start()
    return node

if IS_HUB_MODE:
    if "session_node" not in st.session_state:
        st.title("🛡️ Zero-Trust P2P Swarm Hub")
        st.markdown("##### Instant Encrypted File Sharing across Phones & Laptops")
        st.info("✨ **No installation required!** Enter your name below to create your cryptographic peer identity and join the swarm.")

        lan_ip = get_lan_ip()
        invite_url = f"http://{lan_ip}:{ST_SERVER_PORT}"

        col_j1, col_j2 = st.columns([3, 2])
        with col_j1:
            with st.form("hub_join_form"):
                user_input = st.text_input("Enter your Name / Handle:", placeholder="e.g. Rahul, Sneha, Alex")
                join_submitted = st.form_submit_button("🚀 Enter Network Now", type="primary", use_container_width=True)
                if join_submitted:
                    clean_name = user_input.strip() if user_input else f"Peer_{os.urandom(2).hex()}"
                    session_port = get_free_port(8020, 8950)
                    register_node_port(session_port)
                    s_storage = f"node_data_{clean_name}"
                    os.makedirs(s_storage, exist_ok=True)
                    s_db = f"reputation_{clean_name}.db"

                    s_node = P2PNode(
                        host=HOST,
                        port=session_port,
                        db_path=s_db,
                        storage_dir=s_storage,
                        node_name=clean_name,
                        advertise_host=ADVERTISE_HOST,
                        enable_discovery=ENABLE_DISCOVERY,
                        tracker_url=TRACKER_URL,
                        beacon_port=BEACON_PORT
                    )
                    def run_s_node():
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(s_node.start_server())
                    threading.Thread(target=run_s_node, daemon=True).start()

                    st.session_state["session_node"] = s_node
                    st.session_state["session_port"] = session_port
                    st.session_state["session_name"] = clean_name
                    st.session_state["session_storage"] = s_storage
                    st.rerun()

        with col_j2:
            if HAS_QRCODE:
                st.caption("📲 **Scan with Phone to Join:**")
                qr_img = qrcode.make(invite_url)
                buf = io.BytesIO()
                qr_img.save(buf, format="PNG")
                st.image(buf.getvalue(), width=220)
                st.code(invite_url, language="text")

        st.stop()
    else:
        node = st.session_state["session_node"]
        PORT = st.session_state["session_port"]
        NODE_NAME = st.session_state["session_name"]
        STORAGE_DIR = st.session_state["session_storage"]
else:
    node = get_p2p_node(
        HOST, PORT, DB_PATH, STORAGE_DIR, NODE_NAME,
        advertise_host=ADVERTISE_HOST,
        enable_discovery=ENABLE_DISCOVERY,
        tracker_url=TRACKER_URL,
        beacon_port=BEACON_PORT
    )

# Ensure local available_files strictly matches what is on disk locally
if os.path.exists(STORAGE_DIR):
    local_disk_files = set(os.listdir(STORAGE_DIR))
    for fname in list(node.available_files.keys()):
        if fname not in local_disk_files:
            del node.available_files[fname]

# Keep node aware of latest local files on refresh cycles
node.scan_local_directory()

title_suffix = f" (Name: {NODE_NAME})" if NODE_NAME else f" (Port: {PORT})"
st.title(f"Zero-Trust P2P Swarm Node{title_suffix}")
st.markdown(f"**My Peer ID:** `{node.peer_id}`")

# Security Alerts Banner
if node.security_alerts:
    with st.expander(f"🚨 Swarm Security Broadcasts ({len(node.security_alerts)} incident(s) reported)", expanded=True):
        for alert in reversed(node.security_alerts[-5:]):
            st.warning(
                f"🕒 `[{alert['timestamp']}]` **Reporter:** {alert['reporter']} broadcasted that "
                f"**{alert['bad_peer']}** (`{alert['bad_peer_id'][:8]}...`) served corrupted chunk "
                f"**#{alert['chunk_index']}** for `📄 {alert['filename']}`. *(Provider quarantined for this file)*"
            )

# Sidebar Identity Display (F27)
with st.sidebar:
    st.header("👤 My Identity")
    username_display = node.node_name if node.node_name else f"Node_{node.port}"
    st.markdown(f"**Username:** {username_display}")
    st.markdown(f"**Local Address:** `{node.host}:{node.port}`")
    adv_host = getattr(node, 'advertised_host', node.host)
    st.markdown(f"**Advertised Address:** `{adv_host}:{node.port}`")
    st.markdown(f"**Peer ID:** `{node.peer_id[:8]}...`")
    st.caption(f"Full Peer ID: `{node.peer_id}`")

    if IS_HUB_MODE and "session_node" in st.session_state:
        if st.button("🔴 Exit Network / Leave", use_container_width=True, type="secondary"):
            node.stop()
            unregister_node_port(PORT)
            del st.session_state["session_node"]
            st.toast("👋 You have left the network.")
            st.rerun()

    if HAS_QRCODE:
        with st.expander("📲 Invite Phone / Laptop", expanded=False):
            lan_ip = get_lan_ip()
            invite_url = f"http://{lan_ip}:{ST_SERVER_PORT}"
            st.markdown(f"**Share link on same Wi-Fi:**\n`{invite_url}`")
            qr_img = qrcode.make(invite_url)
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")
            st.image(buf.getvalue(), caption="Scan to join from phone or laptop", use_column_width=True)

st.divider()

col1, col2, col3 = st.columns(3)

with col1:
    st.header("🌐 1. Network")

    # Display flash status notification from manual connect action
    if "manual_connect_result" in st.session_state:
        status_type, msg = st.session_state.pop("manual_connect_result")
        if status_type == "success":
            st.success(msg)
        elif status_type == "warning":
            st.warning(msg)
        else:
            st.error(msg)

    # Manual Connect UI Form (F31)
    with st.expander("🔗 Connect to Peer (Manual)", expanded=True):
        with st.form("manual_connect_form", clear_on_submit=False):
            c_ip, c_port = st.columns([3, 2])
            with c_ip:
                target_ip = st.text_input(
                    "Peer IP / Host",
                    value="127.0.0.1",
                    help="Enter peer LAN or WAN IP address"
                )
            with c_port:
                target_port = st.number_input(
                    "Peer Port",
                    min_value=1,
                    max_value=65535,
                    value=5001,
                    step=1,
                    help="Target peer listening port"
                )
            connect_btn = st.form_submit_button("Connect to Peer", use_container_width=True)

            if connect_btn:
                clean_ip = target_ip.strip() if target_ip else ""
                clean_port = int(target_port)

                if not clean_ip:
                    st.warning("⚠️ Peer IP / Host cannot be empty.")
                else:
                    loop = getattr(node, 'loop', None)
                    success = False
                    message = ""
                    with st.spinner(f"Connecting to peer at {clean_ip}:{clean_port}..."):
                        try:
                            if loop is not None and loop.is_running():
                                future = asyncio.run_coroutine_threadsafe(
                                    node.connect_to_peer(clean_ip, clean_port),
                                    loop
                                )
                                success, message = future.result(timeout=10.0)
                            else:
                                success, message = node.connect_to_peer_sync(
                                    clean_ip, clean_port, timeout=10.0
                                )
                        except Exception as err:
                            success = False
                            message = f"Connection error: {err}"

                    if success:
                        st.session_state["manual_connect_result"] = ("success", f"✅ {message}")
                        st.toast(f"✅ {message}")
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")

    st.write("Peers discovered in the swarm:")
    
    active_peers = list(node.peers.items())  # [((host, port), (peer_id, peer_name)), ...]
    
    if not active_peers:
        st.info("Searching for peers... (They will appear here automatically)")
    else:
        for peer_key, peer_val in active_peers:
            if isinstance(peer_key, (tuple, list)) and len(peer_key) == 2:
                peer_host, peer_port = peer_key[0], peer_key[1]
            else:
                peer_host, peer_port = str(peer_key), 0

            if isinstance(peer_val, dict):
                peer_id = str(peer_val.get('peer_id') or peer_val.get('id') or "")
                raw_name = str(peer_val.get('username') or peer_val.get('node_name') or peer_val.get('name') or peer_val.get('sender_name') or "")
            elif isinstance(peer_val, (tuple, list)):
                peer_id = str(peer_val[0]) if len(peer_val) > 0 else ""
                raw_name = str(peer_val[1]) if len(peer_val) > 1 else ""
            else:
                peer_id = str(peer_val)
                raw_name = ""

            peer_name = raw_name if (raw_name and raw_name.strip() and raw_name != "Unknown") else f"Node_{peer_port}"
                
            trust_score = node.reputation.get_trust_score(peer_id)
            is_blacklisted = node.reputation.is_blacklisted(peer_id)
            quarantined_files = node.reputation.get_quarantined_files_for_peer(peer_id)
            
            if is_blacklisted:
                status = "🚨 BLACKLISTED"
            elif trust_score < 50:
                status = "⚠️ CAUTION (LOW TRUST)"
            else:
                status = "✅ TRUSTED"
            
            with st.container(border=True):
                st.markdown(f"**Peer:** {peer_name} (`{peer_id[:8]}...`)")
                st.markdown(f"**Endpoint:** `{peer_host}:{peer_port}`")
                st.markdown(f"**Trust Score:** {trust_score} | {status}")
                
                if quarantined_files:
                    st.error(f"🚫 Quarantined for: {', '.join(quarantined_files)}")
                
                if is_blacklisted or quarantined_files or trust_score < 50:
                    if st.button(f"🔓 Reset / Unblacklist {peer_name}", key=f"unbl_{peer_id[:8]}"):
                        node.reputation.unblacklist_peer(peer_id)
                        node.reputation.unquarantine_provider(peer_id)
                        st.toast(f"Reset status for {peer_name}!")
                        st.rerun()
                
                peer_files = node.peer_files.get(peer_id, {})
                if peer_files:
                    st.write("**Files Shared:**")
                    for pf in peer_files:
                        is_pf_quar = node.reputation.is_provider_quarantined(peer_id, pf)
                        if is_pf_quar:
                            st.markdown(f"- 📄 ~~{pf}~~ *(🚫 Quarantined)*")
                        else:
                            st.write(f"- 📄 {pf}")
                else:
                    st.write("*No files shared*")

with col2:
    st.header("📂 2. My Local Files")
    st.write("Files in your local storage directory:")
    
    local_files = []
    if os.path.exists(STORAGE_DIR):
        local_files = [f for f in os.listdir(STORAGE_DIR) if os.path.isfile(os.path.join(STORAGE_DIR, f))]
        
    if local_files:
        for f in local_files:
            file_path = os.path.join(STORAGE_DIR, f)
            file_size_bytes = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            file_size_kb = file_size_bytes / 1024
            
            total_chunks = node.available_files.get(f, {}).get(
                'total_chunks', 
                max(1, (file_size_bytes + 64 * 1024 - 1) // (64 * 1024))
            )
            
            with st.container(border=True):
                col_finfo, col_fdel = st.columns([3, 1])
                with col_finfo:
                    st.markdown(f"📄 **{f}**")
                    st.caption(f"Size: {file_size_kb:.1f} KB | Chunks: {total_chunks}")
                with col_fdel:
                    if st.button("🗑️ Delete", key=f"del_{f}"):
                        node.delete_local_file(f)
                        st.toast(f"Deleted {f} from local storage!")
                        st.rerun()
                    try:
                        with open(file_path, "rb") as fp_in:
                            st.download_button(
                                label="📥 Save",
                                data=fp_in.read(),
                                file_name=f,
                                key=f"save_device_{f}",
                                use_container_width=True
                            )
                    except Exception:
                        pass

                # Adversarial Chunk Tampering Control
                corrupted_chunks = node.get_corrupted_chunks(f)
                is_tampering = len(corrupted_chunks) > 0
                
                status_badge = f"🚨 TAMPERING (Chunks: {sorted(list(corrupted_chunks))})" if is_tampering else "Normal"
                with st.expander(f"😈 Adversarial Mode [{status_badge}]"):
                    st.markdown("*Simulate an attacker by serving corrupted/poisoned chunks to peers:*")
                    
                    selected_chunks = st.multiselect(
                        f"Select chunks of '{f}' to corrupt (1 or more):",
                        options=list(range(total_chunks)),
                        default=[c for c in corrupted_chunks if c < total_chunks],
                        key=f"corrupt_sel_{f}",
                        format_func=lambda idx: f"Chunk #{idx}"
                    )
                    
                    if set(selected_chunks) != corrupted_chunks:
                        node.set_corrupted_chunks(f, selected_chunks)
                        st.rerun()
                        
                    if selected_chunks:
                        st.error(f"🚨 ACTIVE: When peers request chunk(s) {selected_chunks}, corrupted data will be sent to test Zero-Trust detection!")
                    else:
                        st.success("✅ Clean: Chunks are served honestly.")
    else:
        st.info("No files in local directory. Place files here to share them.")
        
    st.write("---")
    uploaded_file = st.file_uploader("Upload to local storage")
    if uploaded_file is not None:
        upload_key = f"uploaded_{uploaded_file.name}_{uploaded_file.size}"
        if st.session_state.get("last_uploaded") != upload_key:
            st.session_state["last_uploaded"] = upload_key
            if not os.path.exists(STORAGE_DIR):
                os.makedirs(STORAGE_DIR)
            try:
                clean_filename = node.file_manager.validate_filename(uploaded_file.name)
                file_path = os.path.join(STORAGE_DIR, clean_filename)
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                # Gossip new file across swarm immediately (F19)
                node.broadcast_file_sync(file_path)
                st.success(f"Saved {clean_filename}! Gossiped to swarm.")
                node.scan_local_directory()
                st.rerun()
            except ValueError as e:
                st.error(f"Invalid upload filename: {e}")

with col3:
    st.header("⬇️ 3. Network Files")
    st.write("Files available to pull from the swarm:")

    # Display status notifications from previous actions
    for s_key in list(st.session_state.keys()):
        if s_key.startswith("download_status_"):
            status_type, msg = st.session_state.pop(s_key)
            if status_type == "success":
                st.success(msg)
            else:
                st.error(msg)
    
    # Use Merkle-root bound file grouping to prevent collision spoofing (F14)
    network_files_map = node.get_network_files()
    local_files_set = set(os.listdir(STORAGE_DIR)) if os.path.exists(STORAGE_DIR) else set()
    local_roots_set = {
        finfo.get('merkle_root') for finfo in node.available_files.values() if finfo.get('merkle_root')
    }
    
    # Filter out files already present locally with the same cryptographic Merkle root
    pullable_files = {
        k: v for k, v in network_files_map.items() if v['merkle_root'] not in local_roots_set
    }
    
    if not pullable_files:
        st.info("No new files available to pull.")
    else:
        for swarm_key, finfo in pullable_files.items():
            fname = finfo['filename']
            expected_root = finfo['merkle_root']
            total_chunks = finfo['total_chunks']
            providers = finfo['providers']
            
            with st.container(border=True):
                st.write(f"📄 **{fname}**")
                st.caption(f"Merkle Root: `{expected_root[:16]}...` | Total Chunks: {total_chunks}")
                
                # Separate into healthy providers and quarantined providers
                healthy_providers = []
                quarantined_providers = []
                
                for p in providers:
                    p_host, p_port, p_id, p_name = p[0], p[1], p[2], p[3]
                    if node.reputation.is_provider_quarantined(p_id, fname):
                        quarantined_providers.append(p)
                    else:
                        healthy_providers.append(p)
                
                if healthy_providers:
                    h_names = []
                    for p in healthy_providers:
                        p_display = p[3] if (len(p) > 3 and p[3] and str(p[3]).strip() and p[3] != "Unknown") else f"Node_{p[1]}"
                        h_names.append(f"{p_display} ({p[2][:8]})")
                    st.caption(f"✅ Available from: {', '.join(h_names)}")
                    
                if quarantined_providers:
                    q_names = []
                    for p in quarantined_providers:
                        p_display = p[3] if (len(p) > 3 and p[3] and str(p[3]).strip() and p[3] != "Unknown") else f"Node_{p[1]}"
                        q_names.append(f"{p_display} ({p[2][:8]})")
                    st.caption(f"🚫 Quarantined (Tampered): {', '.join(q_names)}")
                
                # Check if file is completely blocked because no healthy providers remain
                if not healthy_providers:
                    st.error("🚨 FILE COMPLETELY BLOCKED: All providers quarantined due to corrupted chunks.")
                else:
                    # Note if any provider has low trust score
                    low_trust_providers = [p for p in healthy_providers if node.reputation.get_trust_score(p[2]) < 50]
                    if low_trust_providers:
                        lt = low_trust_providers[0]
                        lt_name = lt[3] if (len(lt) > 3 and lt[3] and str(lt[3]).strip() and lt[3] != "Unknown") else f"Node_{lt[1]}"
                        st.info(f"⚠️ Caution: Provider {lt_name} has low trust score ({node.reputation.get_trust_score(lt[2])}). Strict Zero-Trust verification active.")
                        
                    btn_label = f"Pull File from Swarm ({len(healthy_providers)} healthy provider{'s' if len(healthy_providers)>1 else ''})"
                    if st.button(btn_label, key=f"dl_{swarm_key}"):
                        target_fname = fname
                        if target_fname in local_files_set:
                            base, ext = os.path.splitext(fname)
                            target_fname = f"{base}_{expected_root[:8]}{ext}"

                        # Thread-safe asyncio execution dispatched to node's background event loop (F20)
                        providers_list = [(p[0], p[1], p[2], p[3]) for p in healthy_providers]
                        loop = getattr(node, 'loop', None)
                        success = False
                        
                        with st.spinner(f"Zero-Trust verifying and pulling {target_fname} ({total_chunks} chunks)..."):
                            try:
                                if loop is not None and loop.is_running():
                                    future = asyncio.run_coroutine_threadsafe(
                                        node.download_file_from_swarm(
                                            target_fname, 
                                            providers_list, 
                                            expected_root, 
                                            total_chunks,
                                            file_id=expected_root
                                        ),
                                        loop
                                    )
                                    success = future.result(timeout=120.0)
                                else:
                                    temp_loop = asyncio.new_event_loop()
                                    try:
                                        asyncio.set_event_loop(temp_loop)
                                        success = temp_loop.run_until_complete(
                                            node.download_file_from_swarm(
                                                target_fname, 
                                                providers_list, 
                                                expected_root, 
                                                total_chunks,
                                                file_id=expected_root
                                            )
                                        )
                                    finally:
                                        temp_loop.close()
                            except Exception as err:
                                st.error(f"Transfer error: {err}")
                        
                        if success:
                            st.session_state[f"download_status_{target_fname}"] = ("success", f"✅ Successfully downloaded and verified {target_fname}!")
                            node.scan_local_directory()
                            st.rerun()
                        else:
                            st.session_state[f"download_status_{target_fname}"] = ("error", f"❌ Failed to download {target_fname} from swarm (verification or network error).")
                            st.rerun()
