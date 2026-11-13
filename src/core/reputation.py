import sqlite3
import os
import threading

class ReputationEngine:
    def __init__(self, db_path="reputation.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        """Returns a SQLite connection with 30s busy timeout and thread-safe locking."""
        return sqlite3.connect(self.db_path, timeout=30.0)

    def _init_db(self):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute('PRAGMA journal_mode=WAL;')
            except Exception:
                pass
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS peers (
                    peer_id TEXT PRIMARY KEY,
                    trust_score INTEGER DEFAULT 50,
                    is_blacklisted BOOLEAN DEFAULT 0
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_quarantine (
                    peer_id TEXT,
                    filename TEXT,
                    reason TEXT,
                    reporter_id TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (peer_id, filename)
                )
            ''')
            conn.commit()
            conn.close()

    def add_peer(self, peer_id):
        if not peer_id or not isinstance(peer_id, str) or not peer_id.strip():
            return
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO peers (peer_id, trust_score, is_blacklisted) VALUES (?, 50, 0)', (peer_id,))
            conn.commit()
            conn.close()

    def update_trust(self, peer_id, is_valid_chunk):
        """
        Update the trust score based on chunk validity.
        Reward: +2 (max 100)
        Penalty: -25 (min 0)
        Blacklist at 0.
        """
        if not peer_id or not isinstance(peer_id, str) or not peer_id.strip():
            return
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT trust_score, is_blacklisted FROM peers WHERE peer_id = ?', (peer_id,))
            row = cursor.fetchone()
            if not row:
                cursor.execute('INSERT INTO peers (peer_id, trust_score, is_blacklisted) VALUES (?, 50, 0)', (peer_id,))
                trust_score = 50
                is_blacklisted = 0
            else:
                trust_score, is_blacklisted = row

            if is_blacklisted:
                conn.close()
                return

            if is_valid_chunk:
                new_score = min(100, trust_score + 2)  # Reward honest behavior
                cursor.execute('UPDATE peers SET trust_score = ? WHERE peer_id = ?', (new_score, peer_id))
            else:
                # Heavy penalty (-25) per corrupted chunk incident
                new_score = max(0, trust_score - 25)
                new_blacklisted = 1 if new_score == 0 else 0
                cursor.execute('UPDATE peers SET trust_score = ?, is_blacklisted = ? WHERE peer_id = ?', (new_score, new_blacklisted, peer_id))

            conn.commit()
            conn.close()

    def quarantine_provider_for_file(self, peer_id, filename, reason="Corrupted chunk detected", reporter_id="local"):
        """Quarantine a provider specifically for a given file and penalize trust score (-25). Preserves blacklist state."""
        if not peer_id or not isinstance(peer_id, str) or not peer_id.strip():
            return 0
        if not filename or not isinstance(filename, str):
            return 0
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO peers (peer_id, trust_score, is_blacklisted) VALUES (?, 50, 0)', (peer_id,))
            cursor.execute('''
                INSERT OR REPLACE INTO file_quarantine (peer_id, filename, reason, reporter_id)
                VALUES (?, ?, ?, ?)
            ''', (peer_id, filename, reason, reporter_id))
            
            # Penalize peer's trust score (-25), preserving blacklist state
            cursor.execute('SELECT trust_score, is_blacklisted FROM peers WHERE peer_id = ?', (peer_id,))
            row = cursor.fetchone()
            if row:
                current_score, was_blacklisted = row[0], bool(row[1])
            else:
                current_score, was_blacklisted = 50, False

            new_score = max(0, current_score - 25)
            new_blacklisted = 1 if (new_score == 0 or was_blacklisted) else 0
            cursor.execute('UPDATE peers SET trust_score = ?, is_blacklisted = ? WHERE peer_id = ?', (new_score, new_blacklisted, peer_id))
            
            conn.commit()
            conn.close()
            return new_score

    def is_provider_quarantined(self, peer_id, filename):
        """Check if a specific peer is quarantined as a provider for a file."""
        if not peer_id or not filename:
            return False
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM file_quarantine WHERE peer_id = ? AND filename = ?', (peer_id, filename))
            row = cursor.fetchone()
            conn.close()
            return row is not None

    def get_quarantined_files_for_peer(self, peer_id):
        """Get all filenames for which this peer is quarantined."""
        if not peer_id:
            return []
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT filename FROM file_quarantine WHERE peer_id = ?', (peer_id,))
            rows = cursor.fetchall()
            conn.close()
            return [r[0] for r in rows]

    def unquarantine_provider(self, peer_id, filename=None):
        """Lift quarantine for a peer on a file (or all files)."""
        if not peer_id:
            return
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            if filename:
                cursor.execute('DELETE FROM file_quarantine WHERE peer_id = ? AND filename = ?', (peer_id, filename))
            else:
                cursor.execute('DELETE FROM file_quarantine WHERE peer_id = ?', (peer_id,))
            conn.commit()
            conn.close()

    def unblacklist_peer(self, peer_id):
        if not peer_id:
            return
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE peers SET trust_score = 50, is_blacklisted = 0 WHERE peer_id = ?', (peer_id,))
            conn.commit()
            conn.close()

    def is_blacklisted(self, peer_id):
        """
        Check if peer is blacklisted.
        Zero-trust fail-secure: missing, null, empty or invalid peer_id returns True (BLOCKED).
        """
        if not peer_id or not isinstance(peer_id, str) or not peer_id.strip():
            return True
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT is_blacklisted FROM peers WHERE peer_id = ?', (peer_id,))
            row = cursor.fetchone()
            conn.close()
            return bool(row[0]) if row else False

    def get_trust_score(self, peer_id):
        if not peer_id or not isinstance(peer_id, str) or not peer_id.strip():
            return 0
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT trust_score FROM peers WHERE peer_id = ?', (peer_id,))
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else 50
            
    def get_all_peers(self):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT peer_id, trust_score, is_blacklisted FROM peers')
            rows = cursor.fetchall()
            conn.close()
            return [{'peer_id': row[0], 'trust_score': row[1], 'is_blacklisted': bool(row[2])} for row in rows]
