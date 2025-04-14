from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac, hashes
import os

# Ed25519 (для підпису)
def generate_signature_keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign(data: bytes, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(data)

def verify_signature(data: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False

def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

def load_signature_public_key(data: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(data)

# X25519 (для DH обміну)
def generate_dh_keypair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def diffie_hellman(private_key: X25519PrivateKey, peer_public_key: X25519PublicKey) -> bytes:
    shared = private_key.exchange(peer_public_key)
    return shared

def load_dh_public_key(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


# HKDF (для виводу root key з DH secret)

def hkdf(shared_secret: bytes, salt: bytes = None) -> tuple[bytes, bytes]:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"double-ratchet"
    )
    okm = hkdf.derive(shared_secret)
    return okm[:32], okm[32:]  # (root_key, chain_key)


# ChaCha20-Poly1305 AEAD шифрування
def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = aead.encrypt(nonce, plaintext, None)
    return ciphertext, nonce

def decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, None)


# ---------------- Double Ratchet ----------------

def ratchet_dh_send(prev_root_key: bytes, our_dh_priv: X25519PrivateKey,
                    their_dh_pub: X25519PublicKey, initial: bool = False) -> tuple[bytes, bytes]:
    shared_secret = diffie_hellman(our_dh_priv, their_dh_pub)
    salt = None if initial else prev_root_key
    root_key, chain_key = hkdf(shared_secret, salt=salt)
    return root_key, chain_key


def ratchet_dh_recv(prev_root_key: bytes, our_dh_priv: X25519PrivateKey,
                    their_dh_pub: X25519PublicKey, initial: bool = False) -> tuple[bytes, bytes]:
    shared_secret = diffie_hellman(our_dh_priv, their_dh_pub)
    salt = None if initial else prev_root_key
    root_key, chain_key = hkdf(shared_secret, salt=salt)
    return root_key, chain_key


def derive_chain_key(chain_key: bytes) -> bytes:
    return hkdf(b'\x01', salt=chain_key)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def derive_message_key(chain_key: bytes) -> tuple[bytes, bytes]:
    msg_key = hmac_sha256(chain_key, b'\x01')
    next_chain_key = hmac_sha256(chain_key, b'\x02')
    return msg_key, next_chain_key

