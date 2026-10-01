#!/usr/bin/env python3
"""
upi_pqc_dropin.py

A drop-in replacement for a legacy `encrypt_credential(pin, public_key)` /
`decrypt_credential(ciphertext, private_key)` pair. Negotiates between a
hybrid X25519 + ML-KEM-768 path and a classical RSA-2048-OAEP fallback,
and never lets a fallback happen silently.

WIRE FORMAT
-----------
    [1 B method][1 B flags][4 B kem_ct length][kem_ct][12 B nonce][aead output]

  method (1 byte):
      0x01 = RSA_2048_OAEP
      0x02 = HYBRID_X25519_MLKEM768

  flags (1 byte):
      bit 0 (FALLBACK_SIGNAL) = set when the sender had to fall back to RSA
      bits 1-7 reserved, must be 0

  kem_ct length (4 bytes, big-endian unsigned int):
      length of the KEM ciphertext that follows. Always 256 for RSA,
      always 1120 for hybrid -- an explicit length field still lets a
      FUTURE third method use a different size without a parser change.

  kem_ct:
      RSA path   -> the 256-byte RSA-OAEP ciphertext wrapping the AES key
      hybrid path -> 1088-byte ML-KEM-768 ciphertext, then the 32-byte
                     X25519 ephemeral public value, concatenated with NO
                     delimiter (fixed-length slicing only -- see note below)

  nonce (12 bytes):
      fresh random value per transaction, required by AES-GCM

  aead output:
      AES-256-GCM(plaintext_credential) with the 16-byte authentication
      tag appended, associated_data = method || flags

WHY NO DELIMITER BETWEEN THE TWO HYBRID CIPHERTEXT HALVES
-----------------------------------------------------------
An earlier draft of this code joined the ML-KEM ciphertext and the X25519
share with a b"||" separator and split on it. Because the X25519 share is
32 random bytes, it has a small but real chance of containing that exact
byte sequence, which would make the split land in the wrong place and
silently corrupt parsing. Both halves have a FIXED, KNOWN length (1088 and
32 bytes respectively), so they are sliced at fixed offsets instead --
this is also what draft-ietf-tls-ecdhe-mlkem does for X25519MLKEM768.

ANTI-DOWNGRADE DETECTION (the FALLBACK_SIGNAL flag)
------------------------------------------------------
Logging a fallback only tells you about it after the fact -- it does not
stop an attacker from forcing one. This wire format adds a cheap,
RFC 7507-style check: the sender marks every fallback message with the
FALLBACK_SIGNAL bit. If a RECEIVER who itself supports hybrid sees a
message with that bit set, nothing on the receiver's end should have
required a downgrade -- so either the sender genuinely doesn't support
hybrid (fine), or something on the wire forced a downgrade that shouldn't
have happened. This module gives the caller a hook (`on_suspicious_fallback`)
to decide what to do (reject, alert, flag for review) -- it deliberately
does not decide that policy itself, since "reject outright" vs
"accept but alert" is a product/risk decision, not a protocol one. Note
this is a heuristic, not a cryptographic proof of tampering; combining it
with the local registry/pinning checks is still a good idea.
"""

from __future__ import annotations
import os
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------
# Wire-format constants
# --------------------------------------------------------------------------
class Method(IntEnum):
    RSA_2048_OAEP = 0x01
    HYBRID_X25519_MLKEM768 = 0x02


FLAG_FALLBACK_SIGNAL = 0x01

RSA_CIPHERTEXT_LEN = 256
MLKEM768_CIPHERTEXT_LEN = 1088
X25519_SHARE_LEN = 32
HYBRID_CIPHERTEXT_LEN = MLKEM768_CIPHERTEXT_LEN + X25519_SHARE_LEN  # 1120

NONCE_LEN = 12

EXPECTED_LEN_FOR_METHOD = {
    Method.RSA_2048_OAEP: RSA_CIPHERTEXT_LEN,
    Method.HYBRID_X25519_MLKEM768: HYBRID_CIPHERTEXT_LEN,
}


class WireFormatError(ValueError):
    """Raised on any structurally invalid or inconsistent message."""


class SuspiciousFallback(Exception):
    """
    Raised (or passed to a callback) when a message claims a fallback that
    the receiver's own capabilities give no reason to expect. This is a
    heuristic downgrade-attack indicator, not proof of an attack -- see
    module docstring.
    """
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------
# KEM backends
# --------------------------------------------------------------------------
class ClassicalRSAKEM:
    """RSA-2048-OAEP, KEM-shaped: encapsulate picks a random secret and
    wraps it; this models today's real-world RSA key-wrap pattern."""

    def keygen(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pub_bytes, priv

    def encapsulate(self, pub_bytes: bytes):
        pub = load_der_public_key(pub_bytes)
        secret = os.urandom(32)
        ct = pub.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        assert len(ct) == RSA_CIPHERTEXT_LEN
        return ct, secret

    def decapsulate(self, priv, ct: bytes) -> bytes:
        return priv.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )


class ClassicalECDHKEM:
    """X25519, wrapped in a KEM-shaped interface (the 'ciphertext' is just
    the ephemeral public key)."""

    def keygen(self):
        priv = x25519.X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub_bytes, priv

    def encapsulate(self, pub_bytes: bytes):
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        peer_pub = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
        shared = eph_priv.exchange(peer_pub)
        assert len(eph_pub_bytes) == X25519_SHARE_LEN
        return eph_pub_bytes, shared

    def decapsulate(self, priv, ct: bytes) -> bytes:
        eph_pub = x25519.X25519PublicKey.from_public_bytes(ct)
        return priv.exchange(eph_pub)


class MLKEM768Backend:
    """
    Real ML-KEM-768 via liboqs-python. Requires `pip install liboqs-python`
    with the liboqs C library built -- not available in a sandbox with no
    network access. Raises immediately and clearly if unavailable, rather
    than silently falling back to a mock, so benchmark results are never
    mislabeled as real PQC numbers when they aren't.
    """
    def __init__(self):
        try:
            import oqs
            self._oqs = oqs
        except ImportError as e:
            raise RuntimeError(
                "liboqs-python is required for the real ML-KEM-768 backend. "
                "Install with `pip install liboqs-python` on a machine with "
                "liboqs built (see github.com/open-quantum-safe/liboqs-python)."
            ) from e

    def keygen(self):
        kem = self._oqs.KeyEncapsulation("ML-KEM-768")
        pub = kem.generate_keypair()
        return pub, kem

    def encapsulate(self, pub_bytes: bytes):
        kem = self._oqs.KeyEncapsulation("ML-KEM-768")
        ct, shared = kem.encap_secret(pub_bytes)
        assert len(ct) == MLKEM768_CIPHERTEXT_LEN
        return ct, shared

    def decapsulate(self, kem_obj, ct: bytes) -> bytes:
        return kem_obj.decap_secret(ct)


@dataclass
class HybridKeyPair:
    classical_pub: bytes
    classical_priv: object
    pqc_pub: bytes
    pqc_priv: object


class HybridKEM:
    """
    Combines a classical KEM and a PQC KEM the way standardized hybrid TLS
    groups do (e.g. X25519MLKEM768): run both independently, concatenate
    the PQC secret first then the classical secret (matching the FIPS
    positioning convention X25519MLKEM768 uses), and derive the final key
    via HKDF. Secure if EITHER component KEM remains unbroken.
    """
    def __init__(self, classical_backend, pqc_backend):
        self.classical = classical_backend
        self.pqc = pqc_backend

    def keygen(self) -> HybridKeyPair:
        c_pub, c_priv = self.classical.keygen()
        p_pub, p_priv = self.pqc.keygen()
        return HybridKeyPair(c_pub, c_priv, p_pub, p_priv)

    def encapsulate(self, keypair: HybridKeyPair) -> tuple[bytes, bytes]:
        pqc_ct, pqc_secret = self.pqc.encapsulate(keypair.pqc_pub)
        classical_ct, classical_secret = self.classical.encapsulate(keypair.classical_pub)
        # Fixed-length concatenation, NOT delimiter-joined -- see module docstring.
        combined_ct = pqc_ct + classical_ct
        final_secret = self._combine(pqc_secret, classical_secret)
        return combined_ct, final_secret

    def decapsulate(self, keypair: HybridKeyPair, combined_ct: bytes) -> bytes:
        if len(combined_ct) != HYBRID_CIPHERTEXT_LEN:
            raise WireFormatError(
                f"hybrid ciphertext must be {HYBRID_CIPHERTEXT_LEN} bytes, "
                f"got {len(combined_ct)}"
            )
        pqc_ct = combined_ct[:MLKEM768_CIPHERTEXT_LEN]
        classical_ct = combined_ct[MLKEM768_CIPHERTEXT_LEN:]
        pqc_secret = self.pqc.decapsulate(keypair.pqc_priv, pqc_ct)
        classical_secret = self.classical.decapsulate(keypair.classical_priv, classical_ct)
        return self._combine(pqc_secret, classical_secret)

    @staticmethod
    def _combine(pqc_secret: bytes, classical_secret: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"upi-hybrid-pqc-credential-block-v1",
        )
        return hkdf.derive(pqc_secret + classical_secret)


# --------------------------------------------------------------------------
# Recipient key bundle
# --------------------------------------------------------------------------
@dataclass
class RecipientKeys:
    rsa_pub: bytes
    rsa_priv: object
    supports_hybrid: bool
    hybrid_keypair: Optional[HybridKeyPair] = None


def generate_recipient_keys(supports_hybrid: bool = True) -> RecipientKeys:
    """Provision key material for one recipient (e.g. one bank)."""
    rsa_pub, rsa_priv = ClassicalRSAKEM().keygen()
    hybrid_keypair = None
    if supports_hybrid:
        hybrid_keypair = HybridKEM(ClassicalECDHKEM(), MLKEM768Backend()).keygen()
    return RecipientKeys(rsa_pub, rsa_priv, supports_hybrid, hybrid_keypair)


# --------------------------------------------------------------------------
# Public API: drop-in encrypt / decrypt
# --------------------------------------------------------------------------
def encrypt_credential(
    plaintext_credential: bytes,
    sender_supports_hybrid: bool,
    recipient_keys: RecipientKeys,
    on_fallback: Optional[Callable[[str], None]] = None,
) -> bytes:
    """
    Drop-in replacement for a legacy `encrypt_credential(pin, pub_key)`.
    Returns the complete wire-format message as bytes.
    """
    use_hybrid = sender_supports_hybrid and recipient_keys.supports_hybrid
    flags = 0

    if not use_hybrid:
        flags |= FLAG_FALLBACK_SIGNAL
        if on_fallback:
            reason = (
                "sender does not support hybrid PQC"
                if not sender_supports_hybrid
                else "recipient does not support hybrid PQC"
            )
            on_fallback(reason)

    if use_hybrid:
        hybrid = HybridKEM(ClassicalECDHKEM(), MLKEM768Backend())
        kem_ct, shared_secret = hybrid.encapsulate(recipient_keys.hybrid_keypair)
        method = Method.HYBRID_X25519_MLKEM768
    else:
        kem_ct, shared_secret = ClassicalRSAKEM().encapsulate(recipient_keys.rsa_pub)
        method = Method.RSA_2048_OAEP

    nonce = os.urandom(NONCE_LEN)
    aad = bytes([method, flags])
    aead_ct = AESGCM(shared_secret).encrypt(nonce, plaintext_credential, associated_data=aad)

    return (
        bytes([method, flags])
        + struct.pack(">I", len(kem_ct))
        + kem_ct
        + nonce
        + aead_ct
    )


def decrypt_credential(
    wire_bytes: bytes,
    keys: RecipientKeys,
    on_suspicious_fallback: Optional[Callable[["SuspiciousFallback"], None]] = None,
) -> bytes:
    """
    Drop-in replacement for a legacy `decrypt_credential(ciphertext, priv_key)`.
    Raises WireFormatError on any structurally invalid message.
    Calls on_suspicious_fallback (if given) -- without blocking decryption --
    when a fallback is seen that the receiver's own capabilities give no
    reason to expect. The caller decides whether that should abort the
    transaction, alert, or just get flagged for review.
    """
    if len(wire_bytes) < 6:
        raise WireFormatError("message too short to contain a header")

    method_byte, flags = wire_bytes[0], wire_bytes[1]
    try:
        method = Method(method_byte)
    except ValueError:
        raise WireFormatError(f"unknown method tag: {method_byte:#x}")

    if flags & ~FLAG_FALLBACK_SIGNAL:
        raise WireFormatError(f"unexpected reserved flag bits set: {flags:#x}")

    kem_ct_len = struct.unpack(">I", wire_bytes[2:6])[0]
    expected_len = EXPECTED_LEN_FOR_METHOD[method]
    if kem_ct_len != expected_len:
        raise WireFormatError(
            f"method {method.name} must have a {expected_len}-byte KEM "
            f"ciphertext, but the message declares {kem_ct_len}"
        )

    offset = 6
    if len(wire_bytes) < offset + kem_ct_len + NONCE_LEN:
        raise WireFormatError("message too short for declared KEM ciphertext + nonce")

    kem_ct = wire_bytes[offset: offset + kem_ct_len]
    offset += kem_ct_len
    nonce = wire_bytes[offset: offset + NONCE_LEN]
    offset += NONCE_LEN
    aead_ct = wire_bytes[offset:]

    is_fallback = bool(flags & FLAG_FALLBACK_SIGNAL)
    if is_fallback and keys.supports_hybrid and on_suspicious_fallback:
        # We support hybrid; nothing on our end should have required a
        # downgrade. This alone doesn't prove tampering -- the sender may
        # simply not support hybrid -- but it's worth surfacing.
        on_suspicious_fallback(SuspiciousFallback(
            "received a fallback-flagged message, but this recipient "
            "supports hybrid PQC -- verify the sender's actual capability "
            "out of band if this is unexpected"
        ))

    if method == Method.HYBRID_X25519_MLKEM768:
        if not keys.supports_hybrid or keys.hybrid_keypair is None:
            raise WireFormatError("received a hybrid message but no hybrid keys are provisioned")
        hybrid = HybridKEM(ClassicalECDHKEM(), MLKEM768Backend())
        shared_secret = hybrid.decapsulate(keys.hybrid_keypair, kem_ct)
    else:
        shared_secret = ClassicalRSAKEM().decapsulate(keys.rsa_priv, kem_ct)

    aad = bytes([method, flags])
    return AESGCM(shared_secret).decrypt(nonce, aead_ct, associated_data=aad)
