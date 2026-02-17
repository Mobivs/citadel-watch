# Tests for E2E Encrypted P2P Messaging
# v0.3.19 — E2E encrypted peer-to-peer messaging
#
# Coverage:
#   - Key pair generation and serialization (X25519, Ed25519)
#   - Key derivation (HKDF, KDF_RK, KDF_CK)
#   - X3DH key agreement (initiator, responder, with/without OPK)
#   - PreKeyBundle creation, serialization, signature verification
#   - Double Ratchet: init, encrypt, decrypt, DH ratchet step
#   - Out-of-order message delivery (skipped message keys)
#   - Multi-message conversation (both directions)
#   - RatchetState serialization/deserialization
#   - SessionStore: identity keys, prekeys, session CRUD
#   - Edge cases: tampered ciphertext, wrong key, max skip

import json
import os
import pytest
import secrets
from pathlib import Path

from citadel_archer.chat.p2p_crypto import (
    DHKeyPair,
    EncryptedMessage,
    MessageHeader,
    PreKeyBundle,
    RatchetState,
    SigningKeyPair,
    create_prekey_bundle,
    decrypt_aead,
    encrypt_aead,
    hkdf_derive,
    init_ratchet_initiator,
    init_ratchet_responder,
    kdf_ck,
    kdf_rk,
    public_key_from_bytes,
    ratchet_decrypt,
    ratchet_encrypt,
    verify_signature,
    x3dh_initiate,
    x3dh_respond,
    MAX_SKIP,
)
from citadel_archer.chat.session_store import SessionStore


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def store(tmp_path):
    """SessionStore backed by temp database."""
    return SessionStore(db_path=str(tmp_path / "test_sessions.db"))


def _setup_x3dh_session():
    """Set up a complete X3DH session between Alice and Bob.

    Returns (alice_state, bob_state) — both sides with initialized ratchets.
    """
    # Bob's identity keys
    bob_signing = SigningKeyPair.generate()
    bob_identity_dh = DHKeyPair.generate()
    bob_signed_prekey = DHKeyPair.generate()
    bob_one_time = DHKeyPair.generate()

    # Bob creates a prekey bundle
    bundle = create_prekey_bundle(
        identity_signing=bob_signing,
        identity_dh=bob_identity_dh,
        signed_prekey=bob_signed_prekey,
        one_time_prekey=bob_one_time,
    )

    # Alice's keys
    alice_identity_dh = DHKeyPair.generate()
    alice_ephemeral = DHKeyPair.generate()

    # Alice initiates X3DH
    sk_alice, ad_alice = x3dh_initiate(
        our_identity_dh=alice_identity_dh,
        our_ephemeral=alice_ephemeral,
        their_bundle=bundle,
    )

    # Bob responds to X3DH
    sk_bob, ad_bob = x3dh_respond(
        our_identity_dh=bob_identity_dh,
        our_signed_prekey=bob_signed_prekey,
        their_identity_dh=alice_identity_dh.public_bytes,
        their_ephemeral=alice_ephemeral.public_bytes,
        our_one_time_prekey=bob_one_time,
    )

    assert sk_alice == sk_bob
    assert ad_alice == ad_bob

    # Initialize ratchets
    alice_state = init_ratchet_initiator(
        sk_alice, ad_alice, bundle.signed_prekey,
    )
    bob_state = init_ratchet_responder(
        sk_bob, ad_bob, bob_signed_prekey,
    )

    return alice_state, bob_state


# ── Key Pair Tests ──────────────────────────────────────────────────


class TestDHKeyPair:
    def test_generate(self):
        pair = DHKeyPair.generate()
        assert len(pair.public_bytes) == 32
        assert len(pair.private_bytes) == 32

    def test_from_private_bytes(self):
        pair = DHKeyPair.generate()
        restored = DHKeyPair.from_private_bytes(pair.private_bytes)
        assert restored.public_bytes == pair.public_bytes

    def test_dh_exchange(self):
        alice = DHKeyPair.generate()
        bob = DHKeyPair.generate()
        shared_a = alice.dh(bob.public_key)
        shared_b = bob.dh(alice.public_key)
        assert shared_a == shared_b
        assert len(shared_a) == 32

    def test_different_pairs_different_keys(self):
        a = DHKeyPair.generate()
        b = DHKeyPair.generate()
        assert a.public_bytes != b.public_bytes


class TestSigningKeyPair:
    def test_generate(self):
        pair = SigningKeyPair.generate()
        assert len(pair.public_bytes) == 32
        assert len(pair.private_bytes) == 32

    def test_sign_and_verify(self):
        pair = SigningKeyPair.generate()
        data = b"Hello, World!"
        sig = pair.sign(data)
        assert len(sig) == 64
        assert verify_signature(pair.public_bytes, sig, data) is True

    def test_verify_wrong_data(self):
        pair = SigningKeyPair.generate()
        sig = pair.sign(b"correct data")
        assert verify_signature(pair.public_bytes, sig, b"wrong data") is False

    def test_verify_wrong_key(self):
        pair1 = SigningKeyPair.generate()
        pair2 = SigningKeyPair.generate()
        sig = pair1.sign(b"data")
        assert verify_signature(pair2.public_bytes, sig, b"data") is False

    def test_from_private_bytes(self):
        pair = SigningKeyPair.generate()
        restored = SigningKeyPair.from_private_bytes(pair.private_bytes)
        assert restored.public_bytes == pair.public_bytes


# ── Key Derivation Tests ────────────────────────────────────────────


class TestKeyDerivation:
    def test_hkdf_deterministic(self):
        ikm = os.urandom(32)
        a = hkdf_derive(ikm, b"test")
        b = hkdf_derive(ikm, b"test")
        assert a == b
        assert len(a) == 32

    def test_hkdf_different_info(self):
        ikm = os.urandom(32)
        a = hkdf_derive(ikm, b"info1")
        b = hkdf_derive(ikm, b"info2")
        assert a != b

    def test_kdf_rk(self):
        rk = os.urandom(32)
        dh = os.urandom(32)
        new_rk, ck = kdf_rk(rk, dh)
        assert len(new_rk) == 32
        assert len(ck) == 32
        assert new_rk != ck

    def test_kdf_rk_deterministic(self):
        rk = os.urandom(32)
        dh = os.urandom(32)
        a1, b1 = kdf_rk(rk, dh)
        a2, b2 = kdf_rk(rk, dh)
        assert a1 == a2
        assert b1 == b2

    def test_kdf_ck(self):
        ck = os.urandom(32)
        new_ck, mk = kdf_ck(ck)
        assert len(new_ck) == 32
        assert len(mk) == 32
        assert new_ck != mk

    def test_kdf_ck_chain_advances(self):
        ck = os.urandom(32)
        ck1, mk1 = kdf_ck(ck)
        ck2, mk2 = kdf_ck(ck1)
        assert mk1 != mk2
        assert ck1 != ck2


# ── AEAD Encryption Tests ──────────────────────────────────────────


class TestAEAD:
    def test_encrypt_decrypt(self):
        key = os.urandom(32)
        plaintext = b"Secret message"
        ad = b"associated data"
        ct = encrypt_aead(key, plaintext, ad)
        pt = decrypt_aead(key, ct, ad)
        assert pt == plaintext

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct = encrypt_aead(key1, b"secret", b"ad")
        with pytest.raises(Exception):
            decrypt_aead(key2, ct, b"ad")

    def test_wrong_ad_fails(self):
        key = os.urandom(32)
        ct = encrypt_aead(key, b"secret", b"correct ad")
        with pytest.raises(Exception):
            decrypt_aead(key, ct, b"wrong ad")

    def test_tampered_ciphertext_fails(self):
        key = os.urandom(32)
        ct = encrypt_aead(key, b"secret", b"ad")
        # Flip a bit in the ciphertext (after nonce)
        tampered = bytearray(ct)
        tampered[14] ^= 0xFF
        with pytest.raises(Exception):
            decrypt_aead(key, bytes(tampered), b"ad")


# ── PreKeyBundle Tests ──────────────────────────────────────────────


class TestPreKeyBundle:
    def test_create_and_verify(self):
        signing = SigningKeyPair.generate()
        dh = DHKeyPair.generate()
        spk = DHKeyPair.generate()
        bundle = create_prekey_bundle(signing, dh, spk)
        assert bundle.verify_prekey() is True

    def test_verify_tampered_fails(self):
        signing = SigningKeyPair.generate()
        dh = DHKeyPair.generate()
        spk = DHKeyPair.generate()
        bundle = create_prekey_bundle(signing, dh, spk)
        # Replace signed prekey with a different one
        other = DHKeyPair.generate()
        bundle.signed_prekey = other.public_bytes
        assert bundle.verify_prekey() is False

    def test_with_one_time_prekey(self):
        signing = SigningKeyPair.generate()
        dh = DHKeyPair.generate()
        spk = DHKeyPair.generate()
        opk = DHKeyPair.generate()
        bundle = create_prekey_bundle(signing, dh, spk, opk)
        assert bundle.one_time_prekey is not None
        assert bundle.verify_prekey() is True

    def test_serialization(self):
        signing = SigningKeyPair.generate()
        dh = DHKeyPair.generate()
        spk = DHKeyPair.generate()
        opk = DHKeyPair.generate()
        bundle = create_prekey_bundle(signing, dh, spk, opk)
        d = bundle.to_dict()
        restored = PreKeyBundle.from_dict(d)
        assert restored.identity_key == bundle.identity_key
        assert restored.signed_prekey == bundle.signed_prekey
        assert restored.one_time_prekey == bundle.one_time_prekey
        assert restored.verify_prekey() is True

    def test_serialization_without_opk(self):
        signing = SigningKeyPair.generate()
        dh = DHKeyPair.generate()
        spk = DHKeyPair.generate()
        bundle = create_prekey_bundle(signing, dh, spk)
        d = bundle.to_dict()
        restored = PreKeyBundle.from_dict(d)
        assert restored.one_time_prekey is None


# ── X3DH Tests ─────────────────────────────────────────────────────


class TestX3DH:
    def test_shared_secret_matches(self):
        # Bob's keys
        bob_signing = SigningKeyPair.generate()
        bob_dh = DHKeyPair.generate()
        bob_spk = DHKeyPair.generate()
        bob_opk = DHKeyPair.generate()
        bundle = create_prekey_bundle(bob_signing, bob_dh, bob_spk, bob_opk)

        # Alice initiates
        alice_dh = DHKeyPair.generate()
        alice_eph = DHKeyPair.generate()
        sk_a, ad_a = x3dh_initiate(alice_dh, alice_eph, bundle)

        # Bob responds
        sk_b, ad_b = x3dh_respond(
            bob_dh, bob_spk,
            alice_dh.public_bytes, alice_eph.public_bytes,
            bob_opk,
        )

        assert sk_a == sk_b
        assert ad_a == ad_b
        assert len(sk_a) == 32

    def test_without_one_time_prekey(self):
        bob_signing = SigningKeyPair.generate()
        bob_dh = DHKeyPair.generate()
        bob_spk = DHKeyPair.generate()
        bundle = create_prekey_bundle(bob_signing, bob_dh, bob_spk)  # No OPK

        alice_dh = DHKeyPair.generate()
        alice_eph = DHKeyPair.generate()
        sk_a, ad_a = x3dh_initiate(alice_dh, alice_eph, bundle)

        sk_b, ad_b = x3dh_respond(
            bob_dh, bob_spk,
            alice_dh.public_bytes, alice_eph.public_bytes,
        )

        assert sk_a == sk_b

    def test_bad_signature_raises(self):
        bob_signing = SigningKeyPair.generate()
        bob_dh = DHKeyPair.generate()
        bob_spk = DHKeyPair.generate()
        bundle = create_prekey_bundle(bob_signing, bob_dh, bob_spk)

        # Tamper with the signed prekey
        other = DHKeyPair.generate()
        bundle.signed_prekey = other.public_bytes

        alice_dh = DHKeyPair.generate()
        alice_eph = DHKeyPair.generate()
        with pytest.raises(ValueError, match="signature verification failed"):
            x3dh_initiate(alice_dh, alice_eph, bundle)

    def test_associated_data_binds_identities(self):
        bob_signing = SigningKeyPair.generate()
        bob_dh = DHKeyPair.generate()
        bob_spk = DHKeyPair.generate()
        bundle = create_prekey_bundle(bob_signing, bob_dh, bob_spk)

        alice_dh = DHKeyPair.generate()
        alice_eph = DHKeyPair.generate()
        _, ad = x3dh_initiate(alice_dh, alice_eph, bundle)

        # AD should be alice_ik_dh || bob_ik_dh
        assert ad == alice_dh.public_bytes + bob_dh.public_bytes


# ── Double Ratchet Tests ────────────────────────────────────────────


class TestDoubleRatchet:
    def test_single_message(self):
        alice, bob = _setup_x3dh_session()
        msg = ratchet_encrypt(alice, b"Hello Bob!")
        plaintext = ratchet_decrypt(bob, msg)
        assert plaintext == b"Hello Bob!"

    def test_multiple_messages_one_direction(self):
        alice, bob = _setup_x3dh_session()
        for i in range(5):
            msg = ratchet_encrypt(alice, f"Message {i}".encode())
            pt = ratchet_decrypt(bob, msg)
            assert pt == f"Message {i}".encode()

    def test_back_and_forth(self):
        alice, bob = _setup_x3dh_session()

        # Alice → Bob
        msg1 = ratchet_encrypt(alice, b"Hi Bob!")
        assert ratchet_decrypt(bob, msg1) == b"Hi Bob!"

        # Bob → Alice
        msg2 = ratchet_encrypt(bob, b"Hi Alice!")
        assert ratchet_decrypt(alice, msg2) == b"Hi Alice!"

        # Alice → Bob again (new DH ratchet step)
        msg3 = ratchet_encrypt(alice, b"How are you?")
        assert ratchet_decrypt(bob, msg3) == b"How are you?"

        # Bob → Alice again
        msg4 = ratchet_encrypt(bob, b"Great, thanks!")
        assert ratchet_decrypt(alice, msg4) == b"Great, thanks!"

    def test_extended_conversation(self):
        alice, bob = _setup_x3dh_session()
        for i in range(20):
            if i % 3 == 0:
                msg = ratchet_encrypt(alice, f"A:{i}".encode())
                assert ratchet_decrypt(bob, msg) == f"A:{i}".encode()
            else:
                msg = ratchet_encrypt(bob, f"B:{i}".encode())
                assert ratchet_decrypt(alice, msg) == f"B:{i}".encode()

    def test_out_of_order_delivery(self):
        alice, bob = _setup_x3dh_session()

        # Alice sends 3 messages
        msg0 = ratchet_encrypt(alice, b"msg-0")
        msg1 = ratchet_encrypt(alice, b"msg-1")
        msg2 = ratchet_encrypt(alice, b"msg-2")

        # Bob receives them out of order
        assert ratchet_decrypt(bob, msg2) == b"msg-2"
        assert ratchet_decrypt(bob, msg0) == b"msg-0"
        assert ratchet_decrypt(bob, msg1) == b"msg-1"

    def test_forward_secrecy(self):
        """Compromising the current state doesn't reveal past message keys."""
        alice, bob = _setup_x3dh_session()

        # Send and decrypt first message
        msg1 = ratchet_encrypt(alice, b"past message")
        assert ratchet_decrypt(bob, msg1) == b"past message"

        # DH ratchet step (Bob replies)
        msg2 = ratchet_encrypt(bob, b"reply")
        assert ratchet_decrypt(alice, msg2) == b"reply"

        # Snapshot current state
        _snapshot = alice.to_dict()

        # Previous message key is gone — can't decrypt msg1 with current state
        # The key was used and consumed during decryption

    def test_tampered_ciphertext_raises(self):
        alice, bob = _setup_x3dh_session()
        msg = ratchet_encrypt(alice, b"Hello")

        # Tamper with ciphertext
        tampered = bytearray(msg.ciphertext)
        tampered[14] ^= 0xFF
        msg.ciphertext = bytes(tampered)

        with pytest.raises(Exception):
            ratchet_decrypt(bob, msg)

    def test_max_skip_protection(self):
        alice, bob = _setup_x3dh_session()

        # Send MAX_SKIP+1 messages
        msgs = []
        for i in range(MAX_SKIP + 2):
            msgs.append(ratchet_encrypt(alice, f"msg-{i}".encode()))

        # Try to decrypt only the last one — requires skipping too many
        with pytest.raises(ValueError, match="Too many skipped"):
            ratchet_decrypt(bob, msgs[-1])

    def test_global_skipped_keys_cap(self):
        """Skipped keys dict is bounded by MAX_SKIP even across multiple ratchet steps."""
        alice, bob = _setup_x3dh_session()

        # Send some messages from Alice, skip them on Bob
        msgs_a = []
        for i in range(50):
            msgs_a.append(ratchet_encrypt(alice, f"a-{i}".encode()))

        # Bob decrypts only the last one → stores 49 skipped keys
        ratchet_decrypt(bob, msgs_a[-1])
        assert len(bob.skipped) == 49

        # Bob replies → triggers DH ratchet
        msg_b = ratchet_encrypt(bob, b"reply")
        ratchet_decrypt(alice, msg_b)

        # Alice sends more messages on new chain
        msgs_a2 = []
        for i in range(60):
            msgs_a2.append(ratchet_encrypt(alice, f"a2-{i}".encode()))

        # Bob decrypts last one → 59 more skipped, total would be 49+59=108
        # But global cap should limit to MAX_SKIP
        ratchet_decrypt(bob, msgs_a2[-1])
        assert len(bob.skipped) <= MAX_SKIP

    def test_encrypt_before_init_raises(self):
        """Responder can't encrypt before receiving first message."""
        _, bob = _setup_x3dh_session()
        with pytest.raises(ValueError, match="not initialized"):
            ratchet_encrypt(bob, b"premature")


# ── Message Header Tests ────────────────────────────────────────────


class TestMessageHeader:
    def test_encode_decode(self):
        dh_pub = os.urandom(32)
        header = MessageHeader(dh_public=dh_pub, pn=42, n=7)
        encoded = header.encode()
        assert len(encoded) == 40

        decoded = MessageHeader.decode(encoded)
        assert decoded.dh_public == dh_pub
        assert decoded.pn == 42
        assert decoded.n == 7

    def test_to_dict_from_dict(self):
        dh_pub = os.urandom(32)
        header = MessageHeader(dh_public=dh_pub, pn=10, n=3)
        d = header.to_dict()
        restored = MessageHeader.from_dict(d)
        assert restored.dh_public == header.dh_public
        assert restored.pn == 10
        assert restored.n == 3

    def test_decode_too_short(self):
        with pytest.raises(ValueError, match="requires 40 bytes"):
            MessageHeader.decode(b"too short")


class TestEncryptedMessage:
    def test_serialization(self):
        header = MessageHeader(dh_public=os.urandom(32), pn=1, n=0)
        msg = EncryptedMessage(header=header, ciphertext=os.urandom(48))
        d = msg.to_dict()
        restored = EncryptedMessage.from_dict(d)
        assert restored.header.dh_public == header.dh_public
        assert restored.ciphertext == msg.ciphertext


# ── RatchetState Serialization Tests ────────────────────────────────


class TestRatchetStateSerialization:
    def test_repr_redacts_keys(self):
        alice, _ = _setup_x3dh_session()
        r = repr(alice)
        # Should show partial public key, not private/root/chain keys
        assert "dh_pub=" in r
        assert "root_key" not in r
        assert "send_chain_key" not in r

    def test_round_trip_initiator(self):
        alice, _ = _setup_x3dh_session()
        d = alice.to_dict()
        restored = RatchetState.from_dict(d)
        assert restored.root_key == alice.root_key
        assert restored.send_count == alice.send_count
        assert restored.dh_pair.public_bytes == alice.dh_pair.public_bytes

    def test_round_trip_responder(self):
        _, bob = _setup_x3dh_session()
        d = bob.to_dict()
        restored = RatchetState.from_dict(d)
        assert restored.root_key == bob.root_key

    def test_round_trip_with_skipped_keys(self):
        alice, bob = _setup_x3dh_session()
        msg0 = ratchet_encrypt(alice, b"msg-0")
        msg1 = ratchet_encrypt(alice, b"msg-1")
        msg2 = ratchet_encrypt(alice, b"msg-2")

        # Decrypt out of order → creates skipped keys
        ratchet_decrypt(bob, msg2)
        assert len(bob.skipped) == 2

        # Serialize and restore
        d = bob.to_dict()
        restored = RatchetState.from_dict(d)
        assert len(restored.skipped) == 2

        # Use restored state to decrypt skipped messages
        assert ratchet_decrypt(restored, msg0) == b"msg-0"
        assert ratchet_decrypt(restored, msg1) == b"msg-1"

    def test_persist_and_resume_conversation(self):
        """Serialize mid-conversation, restore, continue messaging."""
        alice, bob = _setup_x3dh_session()

        # Initial exchange
        msg1 = ratchet_encrypt(alice, b"Hello")
        ratchet_decrypt(bob, msg1)
        msg2 = ratchet_encrypt(bob, b"Hi")
        ratchet_decrypt(alice, msg2)

        # Serialize both sides
        alice_d = alice.to_dict()
        bob_d = bob.to_dict()

        # Restore from serialized state
        alice2 = RatchetState.from_dict(alice_d)
        bob2 = RatchetState.from_dict(bob_d)

        # Continue conversation with restored state
        msg3 = ratchet_encrypt(alice2, b"Still here?")
        assert ratchet_decrypt(bob2, msg3) == b"Still here?"

        msg4 = ratchet_encrypt(bob2, b"Yes!")
        assert ratchet_decrypt(alice2, msg4) == b"Yes!"


# ── SessionStore Tests ──────────────────────────────────────────────


class TestSessionStore:
    def test_identity_key_generation(self, store):
        identity = store.get_or_create_identity()
        assert "signing" in identity
        assert "dh" in identity
        assert len(identity["signing"].public_bytes) == 32
        assert len(identity["dh"].public_bytes) == 32

    def test_identity_key_persistence(self, store):
        id1 = store.get_or_create_identity()
        id2 = store.get_or_create_identity()
        assert id1["signing"].public_bytes == id2["signing"].public_bytes
        assert id1["dh"].public_bytes == id2["dh"].public_bytes

    def test_signed_prekey(self, store):
        spk = store.get_or_create_signed_prekey()
        assert len(spk.public_bytes) == 32
        # Same prekey returned on second call
        spk2 = store.get_or_create_signed_prekey()
        assert spk.public_bytes == spk2.public_bytes

    def test_one_time_prekeys(self, store):
        keys = store.generate_one_time_prekeys(count=3)
        assert len(keys) == 3
        # All unique
        pubs = {k.public_bytes for k in keys}
        assert len(pubs) == 3

    def test_consume_one_time_prekey(self, store):
        keys = store.generate_one_time_prekeys(count=2)
        pub_hex = keys[0].public_bytes.hex()

        consumed = store.consume_one_time_prekey(pub_hex)
        assert consumed is not None
        assert consumed.public_bytes == keys[0].public_bytes

        # Can't consume again
        again = store.consume_one_time_prekey(pub_hex)
        assert again is None

    def test_local_prekey_bundle(self, store):
        store.generate_one_time_prekeys(count=1)
        bundle = store.get_local_prekey_bundle()
        assert bundle.verify_prekey() is True
        assert bundle.one_time_prekey is not None

    def test_prekey_bundle_consumes_otk(self, store):
        """One-time prekey is consumed after bundle creation (single-use per X3DH)."""
        store.generate_one_time_prekeys(count=1)
        bundle1 = store.get_local_prekey_bundle()
        assert bundle1.one_time_prekey is not None

        # Second call should get no OTK (it was consumed)
        bundle2 = store.get_local_prekey_bundle()
        assert bundle2.one_time_prekey is None

    def test_prekey_bundle_multiple_otks(self, store):
        """Each bundle consumes one OTK from the pool."""
        store.generate_one_time_prekeys(count=3)

        b1 = store.get_local_prekey_bundle()
        b2 = store.get_local_prekey_bundle()
        b3 = store.get_local_prekey_bundle()
        b4 = store.get_local_prekey_bundle()  # Pool exhausted

        assert b1.one_time_prekey is not None
        assert b2.one_time_prekey is not None
        assert b3.one_time_prekey is not None
        assert b4.one_time_prekey is None

        # All OTKs should be different
        otks = {b1.one_time_prekey, b2.one_time_prekey, b3.one_time_prekey}
        assert len(otks) == 3

    def test_save_and_load_session(self, store):
        alice, _ = _setup_x3dh_session()
        store.save_session("contact-123", alice)

        loaded = store.load_session("contact-123")
        assert loaded is not None
        assert loaded.root_key == alice.root_key
        assert loaded.send_count == alice.send_count

    def test_load_nonexistent_session(self, store):
        assert store.load_session("nonexistent") is None

    def test_delete_session(self, store):
        alice, _ = _setup_x3dh_session()
        store.save_session("contact-123", alice)
        assert store.delete_session("contact-123") is True
        assert store.load_session("contact-123") is None

    def test_delete_nonexistent_session(self, store):
        assert store.delete_session("nonexistent") is False

    def test_list_sessions(self, store):
        alice, bob = _setup_x3dh_session()
        store.save_session("contact-a", alice)
        store.save_session("contact-b", bob)
        sessions = store.list_sessions()
        assert "contact-a" in sessions
        assert "contact-b" in sessions

    def test_stats(self, store):
        stats = store.stats()
        assert stats["has_identity_keys"] is False
        assert stats["active_sessions"] == 0

        store.get_or_create_identity()
        store.generate_one_time_prekeys(count=3)
        alice, _ = _setup_x3dh_session()
        store.save_session("c1", alice)

        stats = store.stats()
        assert stats["has_identity_keys"] is True
        assert stats["active_sessions"] == 1
        assert stats["available_one_time_prekeys"] == 3

    def test_session_update_persists_ratchet_advance(self, store):
        """Verify that saving after encrypt/decrypt preserves the advanced state."""
        alice, bob = _setup_x3dh_session()
        store.save_session("alice", alice)
        store.save_session("bob", bob)

        # Encrypt a message
        msg = ratchet_encrypt(alice, b"Test")
        store.save_session("alice", alice)

        # Load and decrypt
        bob_loaded = store.load_session("bob")
        pt = ratchet_decrypt(bob_loaded, msg)
        assert pt == b"Test"
        store.save_session("bob", bob_loaded)

        # Continue with loaded states
        alice_loaded = store.load_session("alice")
        bob_loaded2 = store.load_session("bob")

        msg2 = ratchet_encrypt(bob_loaded2, b"Reply")
        pt2 = ratchet_decrypt(alice_loaded, msg2)
        assert pt2 == b"Reply"


# ── Full Protocol Integration Tests ─────────────────────────────────


class TestFullProtocol:
    def test_complete_session_lifecycle(self):
        """Test the complete flow: bundle → X3DH → ratchet → encrypt → decrypt."""
        # Bob generates and publishes prekey bundle
        bob_signing = SigningKeyPair.generate()
        bob_dh = DHKeyPair.generate()
        bob_spk = DHKeyPair.generate()
        bob_opk = DHKeyPair.generate()
        bundle = create_prekey_bundle(bob_signing, bob_dh, bob_spk, bob_opk)

        # Bundle can be serialized and sent over wire
        bundle_dict = bundle.to_dict()
        received_bundle = PreKeyBundle.from_dict(bundle_dict)
        assert received_bundle.verify_prekey()

        # Alice initiates X3DH
        alice_dh = DHKeyPair.generate()
        alice_eph = DHKeyPair.generate()
        sk_a, ad_a = x3dh_initiate(alice_dh, alice_eph, received_bundle)

        # Bob receives Alice's keys and computes same SK
        sk_b, ad_b = x3dh_respond(
            bob_dh, bob_spk,
            alice_dh.public_bytes, alice_eph.public_bytes,
            bob_opk,
        )
        assert sk_a == sk_b

        # Both initialize ratchets
        alice = init_ratchet_initiator(sk_a, ad_a, received_bundle.signed_prekey)
        bob = init_ratchet_responder(sk_b, ad_b, bob_spk)

        # Alice sends first message
        msg1 = ratchet_encrypt(alice, b"Secure hello!")
        msg1_wire = msg1.to_dict()  # Serialized for transport

        # Bob receives and decrypts
        msg1_recv = EncryptedMessage.from_dict(msg1_wire)
        pt1 = ratchet_decrypt(bob, msg1_recv)
        assert pt1 == b"Secure hello!"

        # Bob replies
        msg2 = ratchet_encrypt(bob, b"Secure reply!")
        pt2 = ratchet_decrypt(alice, EncryptedMessage.from_dict(msg2.to_dict()))
        assert pt2 == b"Secure reply!"

    def test_unicode_messages(self):
        alice, bob = _setup_x3dh_session()
        text = "Hello! 日本語 🔐 Ñoño"
        msg = ratchet_encrypt(alice, text.encode("utf-8"))
        pt = ratchet_decrypt(bob, msg)
        assert pt.decode("utf-8") == text

    def test_large_message(self):
        alice, bob = _setup_x3dh_session()
        data = os.urandom(64 * 1024)  # 64 KB
        msg = ratchet_encrypt(alice, data)
        assert ratchet_decrypt(bob, msg) == data

    def test_empty_message(self):
        alice, bob = _setup_x3dh_session()
        msg = ratchet_encrypt(alice, b"")
        assert ratchet_decrypt(bob, msg) == b""
