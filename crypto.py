import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# Configurações de segurança
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256 bits para AES

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Gera uma chave criptográfica segura de 256 bits usando Argon2id."""
    return hash_secret_raw(
        secret=master_password.encode('utf-8'),
        salt=salt,
        time_cost=2,
        memory_cost=65536,  # 64 MB
        parallelism=1,
        hash_len=KEY_SIZE,
        type=Type.I  # <-- ALTERADO AQUI (Type.I representa o Argon2id na API de baixo nível do argon2-cffi)
    )

def encrypt_data(data: dict, master_password: str, salt: bytes) -> bytes:
    """Criptografa um dicionário Python usando AES-256-GCM."""
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    
    json_bytes = json.dumps(data).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, json_bytes, None)
    
    return nonce + ciphertext

def decrypt_data(encrypted_blob: bytes, master_password: str, salt: bytes) -> dict:
    """Descriptografa o cofre usando a senha mestra."""
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    
    nonce = encrypted_blob[:NONCE_SIZE]
    ciphertext = encrypted_blob[NONCE_SIZE:]
    
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_bytes.decode('utf-8'))
    except Exception:
        raise ValueError("Senha Mestra incorreta ou arquivo corrompido!")