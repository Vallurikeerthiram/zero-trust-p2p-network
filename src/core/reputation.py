import sqlite3
import os
import threading

class ReputationEngine:
    def __init__(self, db_path="reputation.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS peers (
                    peer_id TEXT PRIMARY KEY,
                    trust_score INTEGER DEFAULT 50,
                    is_blacklisted BOOLEAN DEFAULT 0
                )
            ''')
            conn.commit()
            conn.close()

    def add_peer(self, peer_id):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO peers (peer_id, trust_score, is_blacklisted) VALUES (?, 50, 0)', (peer_id,))
            conn.commit()
            conn.close()

    def update_trust(self, peer_id, is_valid_chunk):
        """
        Update the trust score based on chunk validity.
        If a chunk is valid, we increase trust slightly.
        If a chunk is invalid (content poisoning), we penalize heavily or blacklist immediately.
        """
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT trust_score, is_blacklisted FROM peers WHERE peer_id = ?', (peer_id,))
            row = cursor.fetchone()
            if not row:
                # Peer not found, add them first
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
                # Instant penalization and blacklist for corrupted chunks (Zero-Trust)
                cursor.execute('UPDATE peers SET trust_score = 0, is_blacklisted = 1 WHERE peer_id = ?', (peer_id,))

            conn.commit()
            conn.close()

    def is_blacklisted(self, peer_id):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT is_blacklisted FROM peers WHERE peer_id = ?', (peer_id,))
            row = cursor.fetchone()
            conn.close()
            return bool(row[0]) if row else False

    def get_trust_score(self, peer_id):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT trust_score FROM peers WHERE peer_id = ?', (peer_id,))
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else 50
            
    def get_all_peers(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT peer_id, trust_score, is_blacklisted FROM peers')
            rows = cursor.fetchall()
            conn.close()
            return [{'peer_id': row[0], 'trust_score': row[1], 'is_blacklisted': bool(row[2])} for row in rows]
