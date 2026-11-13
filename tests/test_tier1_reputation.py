import pytest
from src.core.reputation import ReputationEngine


class TestTier1Reputation:
    """Tier 1 - Feature Coverage: Reputation Management, Scoring, & File Quarantine."""

    def test_default_peer_reputation(self, reputation_engine):
        """New peers should be initialized with trust score 50 and not blacklisted."""
        peer_id = "test_peer_init_1"
        reputation_engine.add_peer(peer_id)

        assert reputation_engine.get_trust_score(peer_id) == 50
        assert reputation_engine.is_blacklisted(peer_id) is False

    def test_trust_score_reward_on_valid_chunk(self, reputation_engine):
        """Serving a valid chunk increases trust score by +2, capped at 100."""
        peer_id = "test_peer_reward_1"
        reputation_engine.add_peer(peer_id)

        reputation_engine.update_trust(peer_id, is_valid_chunk=True)
        assert reputation_engine.get_trust_score(peer_id) == 52

        reputation_engine.update_trust(peer_id, is_valid_chunk=True)
        assert reputation_engine.get_trust_score(peer_id) == 54

    def test_trust_score_penalty_on_corrupt_chunk(self, reputation_engine):
        """Serving a corrupted chunk penalizes trust score by -25."""
        peer_id = "test_peer_penalty_1"
        reputation_engine.add_peer(peer_id)

        reputation_engine.update_trust(peer_id, is_valid_chunk=False)
        assert reputation_engine.get_trust_score(peer_id) == 25
        assert reputation_engine.is_blacklisted(peer_id) is False

    def test_automatic_blacklisting_at_zero_score(self, reputation_engine):
        """Score hitting 0 triggers automatic blacklisting."""
        peer_id = "test_peer_blacklist_1"
        reputation_engine.add_peer(peer_id)

        # First penalty: 50 -> 25
        reputation_engine.update_trust(peer_id, is_valid_chunk=False)
        assert reputation_engine.get_trust_score(peer_id) == 25

        # Second penalty: 25 -> 0 (Blacklist)
        reputation_engine.update_trust(peer_id, is_valid_chunk=False)
        assert reputation_engine.get_trust_score(peer_id) == 0
        assert reputation_engine.is_blacklisted(peer_id) is True

    def test_blacklisted_peer_cannot_gain_trust(self, reputation_engine):
        """A blacklisted peer cannot receive positive reputation updates."""
        peer_id = "test_peer_locked_blacklist"
        reputation_engine.add_peer(peer_id)

        # Drop to 0
        reputation_engine.update_trust(peer_id, is_valid_chunk=False)
        reputation_engine.update_trust(peer_id, is_valid_chunk=False)
        assert reputation_engine.is_blacklisted(peer_id) is True

        # Attempt to gain reward
        reputation_engine.update_trust(peer_id, is_valid_chunk=True)
        assert reputation_engine.get_trust_score(peer_id) == 0
        assert reputation_engine.is_blacklisted(peer_id) is True

    def test_file_quarantine_mechanics(self, reputation_engine):
        """Quarantine a provider specifically for a file, applying -25 penalty."""
        peer_id = "test_peer_quarantine"
        filename = "poisoned_doc.pdf"

        reputation_engine.add_peer(peer_id)
        assert reputation_engine.get_trust_score(peer_id) == 50

        reputation_engine.quarantine_provider_for_file(
            peer_id, filename, reason="Corrupted chunk detected", reporter_id="auditor_node"
        )

        # Provider must be quarantined for this specific file
        assert reputation_engine.is_provider_quarantined(peer_id, filename) is True
        # Provider must NOT be quarantined for unrelated files
        assert reputation_engine.is_provider_quarantined(peer_id, "clean_file.txt") is False

        # Trust score penalized by -25
        assert reputation_engine.get_trust_score(peer_id) == 25

        # Check quarantined files query
        quarantined = reputation_engine.get_quarantined_files_for_peer(peer_id)
        assert filename in quarantined

        # Unquarantine
        reputation_engine.unquarantine_provider(peer_id, filename)
        assert reputation_engine.is_provider_quarantined(peer_id, filename) is False

    def test_unblacklist_peer(self, reputation_engine):
        """unblacklist_peer restores peer to score 50 and active status."""
        peer_id = "test_peer_reset"
        reputation_engine.add_peer(peer_id)
        reputation_engine.update_trust(peer_id, is_valid_chunk=False)
        reputation_engine.update_trust(peer_id, is_valid_chunk=False)
        assert reputation_engine.is_blacklisted(peer_id) is True

        reputation_engine.unblacklist_peer(peer_id)
        assert reputation_engine.is_blacklisted(peer_id) is False
        assert reputation_engine.get_trust_score(peer_id) == 50
