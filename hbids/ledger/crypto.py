"""ECDSA (NIST P-256, SHA-256) identities and canonical message signing."""
from __future__ import annotations

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Identity:
    def __init__(self, name: str, key: ec.EllipticCurvePrivateKey | None = None):
        self.name = name
        self.key = key or ec.generate_private_key(ec.SECP256R1())

    def public_pem(self) -> str:
        return self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def private_pem(self) -> str:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()).decode()

    @classmethod
    def from_private_pem(cls, name: str, pem: str) -> "Identity":
        return cls(name, serialization.load_pem_private_key(pem.encode(), None))

    def sign(self, obj) -> str:
        return self.key.sign(canonical(obj), ec.ECDSA(hashes.SHA256())).hex()


class Registry:
    """Membership list fixed in the genesis block: name -> public key."""
    def __init__(self, pems: dict[str, str]):
        self.keys = {n: serialization.load_pem_public_key(p.encode()) for n, p in pems.items()}

    def verify(self, signer: str, obj, sig_hex: str) -> bool:
        k = self.keys.get(signer)
        if k is None:
            return False
        try:
            k.verify(bytes.fromhex(sig_hex), canonical(obj), ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return sha256(b"")
    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()
