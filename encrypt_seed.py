import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def derive_key_from_phrase(phrase: str) -> bytes:
    """Derive a 32-byte AES key from a user phrase using SHA-256."""
    return hashlib.sha256(phrase.encode('utf-8')).digest()


def pad(data: bytes) -> bytes:
    """Apply PKCS7 padding."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    pad_len = data[-1]
    return data[:-pad_len]


def encrypt_seed(user_phrase: str, seed_phrase: str) -> str:
    """Encrypt the seed phrase using AES-256-CBC derived from a user phrase."""
    key = derive_key_from_phrase(user_phrase)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(seed_phrase.encode('utf-8')))

    return base64.b64encode(iv + encrypted).decode('utf-8')


def decrypt_seed(user_phrase: str, encrypted_base64: str) -> str:
    """Decrypt previously encrypted seed using the same phrase."""
    key = derive_key_from_phrase(user_phrase)
    raw = base64.b64decode(encrypted_base64)
    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext))

    return decrypted.decode('utf-8')


if __name__ == "__main__":
    print("Enter your personal phrase:")
    user_phrase = input().strip()

    print("Enter your 12-word seed phrase:")
    seed_phrase = input().strip()

    encrypted = encrypt_seed(user_phrase, seed_phrase)

    print("\n--- Final encrypted key (store this) ---")
    print(encrypted)
    print("----------------------------------------")

    # Optional: verification demonstration
    print("\nDecrypted seed (for demo purposes):")
    print(decrypt_seed(user_phrase, encrypted))
