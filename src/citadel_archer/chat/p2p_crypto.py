# PRD: E2E Encrypted P2P Messaging — Crypto Layer
# Reference: docs/PRD.md v0.3.18, Phase 4
#
# Implements Signal-like protocol for peer-to-peer encrypted messaging:
#   - X3DH (Extended Triple Diffie-Hellman) for session establishment
#   - Double Ratchet for forward-secret message encryption
#   - AES-256-GCM for authenticated encryption
#   - HKDF-SHA256 for key derivation
#   - HMAC-SHA256 for symmetric ratchet advancement
#
# References:
#   - https://signal.org/docs/specifications/x3dh/
#   - https://signal.org/docs/specifications/doubleratchet/
#
# Security:
#   - Forward secrecy: compromising current keys cannot decrypt past messages
#   - Future secrecy: DH ratchet step heals from key compromise
#   - Out-of-order delivery: skipped message keys stored (capped at MAX_SKIP)
#   - Associated data binds ciphertext to session identity
#
# Design:
#   - Pure functions where possible (testable, no hidden state)
#   - RatchetState is a plain dataclass (serializable for persistence)
#   - All key material in bytes (hex encoding only at serialization boundary)

import hashlib
import hmac
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

# Domain separation strings for HKDF (prevents cross-protocol key reuse)
X3DH_INFO = b"CitadelArcher_X3DH_v1"
RATCHET_INFO = b"CitadelArcher_Ratchet_v1"

# Maximum skipped message keys to store per session (DoS protection)
MAX_SKIP = 100

# AES-256-GCM nonce size (96 bits per NIST recommendation)
NONCE_SIZE = 12


# ── X25519 Key Pairs ────────────────────────────────────────────────


@dataclass
class DHKeyPair:
    """X25519 Diffie-Hellman key pair for key exchange."""
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    @classmethod
    def generate(cls) -> "DHKeyPair":
        """Generate a new random X25519 key pair."""
        private = x25519.X25519PrivateKey.generate()
        return cls(private_key=private, public_key=private.public_key())

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "DHKeyPair":
        """Reconstruct key pair from 32-byte private key."""
        private = x25519.X25519PrivateKey.from_private_bytes(data)
        return cls(private_key=private, public_key=private.public_key())

    def dh(self, their_public: x25519.X25519PublicKey) -> bytes:
        """Perform X25519 Diffie-Hellman exchange. Returns 32-byte shared secret."""
        return self.private_key.exchange(their_public)

    @property
    def public_bytes(self) -> bytes:
        """32-byte raw public key."""
        return self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    @property
    def private_bytes(self) -> bytes:
        """32-byte raw private key."""
        return self.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )


def public_key_from_bytes(data: bytes) -> x25519.X25519PublicKey:
    """Deserialize an X25519 public key from 32 raw bytes."""
    return x25519.X25519PublicKey.from_public_bytes(data)


# ── Ed25519 Signing ──────────────────────────────────────────────────


@dataclass
class SigningKeyPair:
    """Ed25519 key pair for message signing and identity verification."""
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey

    @classmethod
    def generate(cls) -> "SigningKeyPair":
        private = ed25519.Ed25519PrivateKey.generate()
        return cls(private_key=private, public_key=private.public_key())

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "SigningKeyPair":
        private = ed25519.Ed25519PrivateKey.from_private_bytes(data)
        return cls(private_key=private, public_key=private.public_key())

    def sign(self, data: bytes) -> bytes:
        """Sign data with Ed25519. Returns 64-byte signature."""
        return self.private_key.sign(data)

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    @property
    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )


def verify_signature(
    public_key_bytes: bytes, signature: bytes, data: bytes,
) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, data)
        return True
    except Exception:
        return False


# ── Key Derivation ───────────────────────────────────────────────────


def hkdf_derive(
    input_key_material: bytes, info: bytes, length: int = 32,
) -> bytes:
    """Derive key material using HKDF-SHA256 with zero salt.

    The all-zeros salt is intentional per Signal protocol convention.
    Domain separation is achieved via the ``info`` parameter, not the salt.
    Do NOT change salt to random — both sides must derive the same key.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"\x00" * 32,  # Signal protocol uses all-zeros salt
        info=info,
    ).derive(input_key_material)


def kdf_rk(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    """Root key KDF: (root_key, dh_output) → (new_root_key, chain_key).

    Uses HKDF-SHA256 with root_key as salt and DH output as input.
    Produces 64 bytes split into two 32-byte keys.
    """
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=RATCHET_INFO,
    ).derive(dh_output)
    return derived[:32], derived[32:]


def kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """Chain key KDF: chain_key → (new_chain_key, message_key).

    Uses HMAC-SHA256 with different constants to derive two independent keys.
    Constant 0x01 → new chain key, 0x02 → message key.
    """
    new_ck = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    mk = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return new_ck, mk


# ── X3DH Key Agreement ──────────────────────────────────────────────


@dataclass
class PreKeyBundle:
    """Public prekey bundle for X3DH session initiation.

    Published by the responder (Bob) so the initiator (Alice) can
    establish a session without Bob being online.
    """
    identity_key: bytes       # Ed25519 public key (32 bytes)
    identity_dh_key: bytes    # X25519 public key for DH (32 bytes)
    signed_prekey: bytes      # X25519 signed prekey (32 bytes)
    prekey_signature: bytes   # Ed25519 signature over signed_prekey (64 bytes)
    one_time_prekey: Optional[bytes] = None  # Optional X25519 one-time prekey

    def to_dict(self) -> Dict[str, str]:
        d = {
            "identity_key": self.identity_key.hex(),
            "identity_dh_key": self.identity_dh_key.hex(),
            "signed_prekey": self.signed_prekey.hex(),
            "prekey_signature": self.prekey_signature.hex(),
        }
        if self.one_time_prekey:
            d["one_time_prekey"] = self.one_time_prekey.hex()
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, str]) -> "PreKeyBundle":
        return cls(
            identity_key=bytes.fromhex(d["identity_key"]),
            identity_dh_key=bytes.fromhex(d["identity_dh_key"]),
            signed_prekey=bytes.fromhex(d["signed_prekey"]),
            prekey_signature=bytes.fromhex(d["prekey_signature"]),
            one_time_prekey=(
                bytes.fromhex(d["one_time_prekey"])
                if d.get("one_time_prekey") else None
            ),
        )

    def verify_prekey(self) -> bool:
        """Verify that the signed prekey was signed by the identity key."""
        return verify_signature(
            self.identity_key, self.prekey_signature, self.signed_prekey,
        )


def create_prekey_bundle(
    identity_signing: SigningKeyPair,
    identity_dh: DHKeyPair,
    signed_prekey: DHKeyPair,
    one_time_prekey: Optional[DHKeyPair] = None,
) -> PreKeyBundle:
    """Create a signed prekey bundle for X3DH.

    The signed prekey is signed by the Ed25519 identity key,
    allowing the initiator to verify authenticity.
    """
    signature = identity_signing.sign(signed_prekey.public_bytes)
    return PreKeyBundle(
        identity_key=identity_signing.public_bytes,
        identity_dh_key=identity_dh.public_bytes,
        signed_prekey=signed_prekey.public_bytes,
        prekey_signature=signature,
        one_time_prekey=(
            one_time_prekey.public_bytes if one_time_prekey else None
        ),
    )


def x3dh_initiate(
    our_identity_dh: DHKeyPair,
    our_ephemeral: DHKeyPair,
    their_bundle: PreKeyBundle,
) -> Tuple[bytes, bytes]:
    """Initiate X3DH session (Alice's side).

    Computes shared secret from four (or three) DH exchanges:
      DH1 = DH(IKa, SPKb)       — Identity ↔ Signed prekey
      DH2 = DH(EKa, IKb)        — Ephemeral ↔ Identity
      DH3 = DH(EKa, SPKb)       — Ephemeral ↔ Signed prekey
      DH4 = DH(EKa, OPKb)       — Ephemeral ↔ One-time prekey [optional]
      SK  = KDF(DH1 ‖ DH2 ‖ DH3 [‖ DH4])

    Args:
        our_identity_dh: Our X25519 identity DH key pair.
        our_ephemeral: Freshly generated ephemeral X25519 key pair.
        their_bundle: Peer's published prekey bundle.

    Returns:
        (shared_secret, associated_data) — 32-byte SK and AD for AEAD.

    Raises:
        ValueError: If prekey bundle signature verification fails.
    """
    if not their_bundle.verify_prekey():
        raise ValueError("Prekey bundle signature verification failed")

    their_spk = public_key_from_bytes(their_bundle.signed_prekey)
    their_ik = public_key_from_bytes(their_bundle.identity_dh_key)

    dh1 = our_identity_dh.dh(their_spk)
    dh2 = our_ephemeral.dh(their_ik)
    dh3 = our_ephemeral.dh(their_spk)

    dh_concat = dh1 + dh2 + dh3

    if their_bundle.one_time_prekey:
        their_opk = public_key_from_bytes(their_bundle.one_time_prekey)
        dh4 = our_ephemeral.dh(their_opk)
        dh_concat += dh4

    sk = hkdf_derive(dh_concat, X3DH_INFO)

    # AD = initiator identity ‖ responder identity (binds session to both parties)
    ad = our_identity_dh.public_bytes + their_bundle.identity_dh_key

    return sk, ad


def x3dh_respond(
    our_identity_dh: DHKeyPair,
    our_signed_prekey: DHKeyPair,
    their_identity_dh: bytes,
    their_ephemeral: bytes,
    our_one_time_prekey: Optional[DHKeyPair] = None,
) -> Tuple[bytes, bytes]:
    """Respond to X3DH session (Bob's side).

    Computes the same shared secret as the initiator using the
    complementary DH operations.

    Args:
        our_identity_dh: Our X25519 identity DH key pair.
        our_signed_prekey: Our X25519 signed prekey pair.
        their_identity_dh: Initiator's X25519 identity DH public key (32 bytes).
        their_ephemeral: Initiator's ephemeral X25519 public key (32 bytes).
        our_one_time_prekey: One-time prekey pair used by initiator (if any).

    Returns:
        (shared_secret, associated_data) — same values as initiator computed.
    """
    their_ik = public_key_from_bytes(their_identity_dh)
    their_ek = public_key_from_bytes(their_ephemeral)

    dh1 = our_signed_prekey.dh(their_ik)
    dh2 = our_identity_dh.dh(their_ek)
    dh3 = our_signed_prekey.dh(their_ek)

    dh_concat = dh1 + dh2 + dh3

    if our_one_time_prekey:
        dh4 = our_one_time_prekey.dh(their_ek)
        dh_concat += dh4

    sk = hkdf_derive(dh_concat, X3DH_INFO)
    ad = their_identity_dh + our_identity_dh.public_bytes

    return sk, ad


# ── Message Encryption (AEAD) ────────────────────────────────────────


@dataclass
class MessageHeader:
    """Double Ratchet message header (sent in plaintext alongside ciphertext)."""
    dh_public: bytes   # Sender's current DH ratchet public key (32 bytes)
    pn: int            # Number of messages in previous sending chain
    n: int             # Message number in current sending chain

    def encode(self) -> bytes:
        """Serialize to 40 bytes: 32-byte key + 4-byte pn + 4-byte n."""
        return self.dh_public + struct.pack(">II", self.pn, self.n)

    @classmethod
    def decode(cls, data: bytes) -> "MessageHeader":
        if len(data) < 40:
            raise ValueError(
                f"MessageHeader requires 40 bytes, got {len(data)}"
            )
        dh_public = data[:32]
        pn, n = struct.unpack(">II", data[32:40])
        return cls(dh_public=dh_public, pn=pn, n=n)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dh_public": self.dh_public.hex(),
            "pn": self.pn,
            "n": self.n,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MessageHeader":
        return cls(
            dh_public=bytes.fromhex(d["dh_public"]),
            pn=d["pn"],
            n=d["n"],
        )


@dataclass
class EncryptedMessage:
    """An E2E encrypted message container."""
    header: MessageHeader
    ciphertext: bytes  # nonce ‖ AES-256-GCM ciphertext

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header.to_dict(),
            "ciphertext": self.ciphertext.hex(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EncryptedMessage":
        return cls(
            header=MessageHeader.from_dict(d["header"]),
            ciphertext=bytes.fromhex(d["ciphertext"]),
        )


def encrypt_aead(key: bytes, plaintext: bytes, ad: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce ‖ ciphertext ‖ tag."""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, ad)
    return nonce + ct


def decrypt_aead(key: bytes, data: bytes, ad: bytes) -> bytes:
    """Decrypt AES-256-GCM. Input is nonce ‖ ciphertext ‖ tag."""
    nonce = data[:NONCE_SIZE]
    ct = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, ad)


# ── Double Ratchet State ─────────────────────────────────────────────


@dataclass
class RatchetState:
    """Full state for one side of a Double Ratchet session.

    Serializable via to_dict()/from_dict() for SQLite persistence.
    """
    dh_pair: DHKeyPair              # Our current DH ratchet key pair
    dh_remote: Optional[bytes]      # Their current DH ratchet public key (32 bytes)
    root_key: bytes                 # Current root key (32 bytes)
    send_chain_key: Optional[bytes] = None  # Current sending chain key
    recv_chain_key: Optional[bytes] = None  # Current receiving chain key
    send_count: int = 0             # Messages sent in current sending chain
    recv_count: int = 0             # Messages received in current receiving chain
    prev_send_count: int = 0        # Send count when last DH ratchet step occurred
    ad: bytes = b""                 # Associated data from X3DH
    skipped: Dict[str, bytes] = field(default_factory=dict)

    def __repr__(self) -> str:
        """Redact key material to prevent accidental logging of secrets."""
        return (
            f"RatchetState(dh_pub={self.dh_pair.public_bytes.hex()[:16]}..., "
            f"send_count={self.send_count}, recv_count={self.recv_count}, "
            f"skipped={len(self.skipped)} keys)"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize full state for persistence."""
        return {
            "dh_private": self.dh_pair.private_bytes.hex(),
            "dh_remote": self.dh_remote.hex() if self.dh_remote else None,
            "root_key": self.root_key.hex(),
            "send_chain_key": (
                self.send_chain_key.hex() if self.send_chain_key else None
            ),
            "recv_chain_key": (
                self.recv_chain_key.hex() if self.recv_chain_key else None
            ),
            "send_count": self.send_count,
            "recv_count": self.recv_count,
            "prev_send_count": self.prev_send_count,
            "ad": self.ad.hex(),
            "skipped": {k: v.hex() for k, v in self.skipped.items()},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RatchetState":
        """Reconstruct state from persisted dict."""
        dh_pair = DHKeyPair.from_private_bytes(bytes.fromhex(d["dh_private"]))
        return cls(
            dh_pair=dh_pair,
            dh_remote=(
                bytes.fromhex(d["dh_remote"]) if d.get("dh_remote") else None
            ),
            root_key=bytes.fromhex(d["root_key"]),
            send_chain_key=(
                bytes.fromhex(d["send_chain_key"])
                if d.get("send_chain_key") else None
            ),
            recv_chain_key=(
                bytes.fromhex(d["recv_chain_key"])
                if d.get("recv_chain_key") else None
            ),
            send_count=d.get("send_count", 0),
            recv_count=d.get("recv_count", 0),
            prev_send_count=d.get("prev_send_count", 0),
            ad=bytes.fromhex(d.get("ad", "")),
            skipped={
                k: bytes.fromhex(v)
                for k, v in d.get("skipped", {}).items()
            },
        )


# ── Double Ratchet Operations ────────────────────────────────────────


def init_ratchet_initiator(
    shared_secret: bytes,
    ad: bytes,
    their_signed_prekey: bytes,
) -> RatchetState:
    """Initialize ratchet as session initiator (Alice).

    After X3DH produces a shared secret, Alice performs the first
    DH ratchet step using Bob's signed prekey as the initial remote DH key.
    """
    dh_pair = DHKeyPair.generate()
    their_spk = public_key_from_bytes(their_signed_prekey)
    dh_output = dh_pair.private_key.exchange(their_spk)
    root_key, send_chain_key = kdf_rk(shared_secret, dh_output)

    return RatchetState(
        dh_pair=dh_pair,
        dh_remote=their_signed_prekey,
        root_key=root_key,
        send_chain_key=send_chain_key,
        ad=ad,
    )


def init_ratchet_responder(
    shared_secret: bytes,
    ad: bytes,
    signed_prekey_pair: DHKeyPair,
) -> RatchetState:
    """Initialize ratchet as session responder (Bob).

    Bob starts with his signed prekey pair. The first DH ratchet step
    occurs when he receives Alice's first message (containing her DH public key).
    """
    return RatchetState(
        dh_pair=signed_prekey_pair,
        dh_remote=None,
        root_key=shared_secret,
        ad=ad,
    )


def ratchet_encrypt(state: RatchetState, plaintext: bytes) -> EncryptedMessage:
    """Encrypt a message using the Double Ratchet.

    Advances the sending chain to derive a fresh message key.
    Each message gets a unique key (forward secrecy within chain).
    """
    if state.send_chain_key is None:
        raise ValueError("Session not initialized for sending")

    state.send_chain_key, mk = kdf_ck(state.send_chain_key)

    header = MessageHeader(
        dh_public=state.dh_pair.public_bytes,
        pn=state.prev_send_count,
        n=state.send_count,
    )
    state.send_count += 1

    # AD = session AD (identity keys) + message header
    ad = state.ad + header.encode()
    ciphertext = encrypt_aead(mk, plaintext, ad)

    return EncryptedMessage(header=header, ciphertext=ciphertext)


def ratchet_decrypt(state: RatchetState, msg: EncryptedMessage) -> bytes:
    """Decrypt a message using the Double Ratchet.

    Handles:
    1. Skipped message keys (out-of-order delivery)
    2. DH ratchet step (new DH public key from sender)
    3. Symmetric ratchet step (advance receiving chain)
    """
    # 1. Check for previously skipped message keys
    skip_key = f"{msg.header.dh_public.hex()}:{msg.header.n}"
    if skip_key in state.skipped:
        mk = state.skipped.pop(skip_key)
        ad = state.ad + msg.header.encode()
        return decrypt_aead(mk, msg.ciphertext, ad)

    # 2. DH ratchet step if sender has a new DH public key
    if state.dh_remote is None or msg.header.dh_public != state.dh_remote:
        # Store skipped keys from current receiving chain
        if state.recv_chain_key is not None:
            _skip_message_keys(state, msg.header.pn)
        # Perform DH ratchet
        _dh_ratchet(state, msg.header.dh_public)

    # 3. Skip to correct message number in current chain
    _skip_message_keys(state, msg.header.n)

    # 4. Derive message key and decrypt
    state.recv_chain_key, mk = kdf_ck(state.recv_chain_key)
    state.recv_count += 1

    ad = state.ad + msg.header.encode()
    return decrypt_aead(mk, msg.ciphertext, ad)


def _dh_ratchet(state: RatchetState, their_public: bytes) -> None:
    """Perform a DH ratchet step.

    1. Save current send count as prev_send_count
    2. Reset counters
    3. Derive new receiving chain from DH(our_current, their_new)
    4. Generate new DH key pair
    5. Derive new sending chain from DH(our_new, their_new)
    """
    state.prev_send_count = state.send_count
    state.send_count = 0
    state.recv_count = 0
    state.dh_remote = their_public

    their_pk = public_key_from_bytes(their_public)

    # Derive receiving chain key
    dh_output = state.dh_pair.private_key.exchange(their_pk)
    state.root_key, state.recv_chain_key = kdf_rk(state.root_key, dh_output)

    # Generate new DH pair and derive sending chain key
    state.dh_pair = DHKeyPair.generate()
    dh_output = state.dh_pair.private_key.exchange(their_pk)
    state.root_key, state.send_chain_key = kdf_rk(state.root_key, dh_output)


def _skip_message_keys(state: RatchetState, until: int) -> None:
    """Store skipped message keys for out-of-order message decryption.

    Raises ValueError if too many messages are skipped (DoS protection).
    Enforces both per-call and global cap on stored skipped keys.
    """
    if state.recv_chain_key is None:
        return

    if until - state.recv_count > MAX_SKIP:
        raise ValueError(
            f"Too many skipped messages ({until - state.recv_count} > {MAX_SKIP})"
        )

    while state.recv_count < until:
        state.recv_chain_key, mk = kdf_ck(state.recv_chain_key)
        skip_key = f"{state.dh_remote.hex()}:{state.recv_count}"
        state.skipped[skip_key] = mk
        state.recv_count += 1

    # Global cap: evict oldest skipped keys (relies on Python 3.7+ insertion order)
    while len(state.skipped) > MAX_SKIP:
        oldest_key = next(iter(state.skipped))
        del state.skipped[oldest_key]
