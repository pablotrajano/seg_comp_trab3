# verification.py
import base64
import hashlib
from signature import sha3_256_hash, xor_bytes, mgf1

def parse_signature(b64_sig):
    return int.from_bytes(base64.b64decode(b64_sig), "big")

def rsa_pss_verify(message, b64_sig, public_key, em_len):
    sig_int = parse_signature(b64_sig)
    em = pow(sig_int, public_key[1], public_key[0]).to_bytes(em_len, "big")
    h_len = 32

    if em[-1] != 0xbc:
        return False
    h = em[-h_len-1:-1]
    masked_db = em[:em_len - h_len - 1]
    db = xor_bytes(masked_db, mgf1(h, len(masked_db), h_len))

    try:
        sep_index = db.index(b"\x01")
    except ValueError:
        return False

    if any(b != 0 for b in db[:sep_index]):
        return False

    salt = db[sep_index+1:]
    m_hash = sha3_256_hash(message)
    m_prime = b"\x00" * 8 + m_hash + salt
    return h == hashlib.sha3_256(m_prime).digest()
