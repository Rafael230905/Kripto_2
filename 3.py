from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def format_hex_blocks(data: bytes, block_size: int = AES.block_size) -> str:
    """Formats bytes into space-separated hex blocks of block_size."""
    return " ".join(
        data[i : i + block_size].hex() for i in range(0, len(data), block_size)
    )


def encrypt_ecb(padded_data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(padded_data)


def encrypt_cbc(padded_data: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Prepend the IV to the ciphertext so the recipient can decrypt the message
    return iv + cipher.encrypt(padded_data)


def decrypt_cbc(payload: bytes, key: bytes) -> bytes:
    iv = payload[: AES.block_size]
    ciphertext = payload[AES.block_size :]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


if __name__ == "__main__":
    # In production environments, use: key = get_random_bytes(16)
    key = b"1234567890abcdef"
    plaintext = b"AAAAAAAABBBBBBBBAAAAAAAABBBBBBBB"
    padded_pt = pad(plaintext, AES.block_size)

    # Execute twice to test deterministic vs. randomized behavior across runs
    ecb_run1 = encrypt_ecb(padded_pt, key)
    ecb_run2 = encrypt_ecb(padded_pt, key)

    cbc_payload1 = encrypt_cbc(padded_pt, key)
    cbc_payload2 = encrypt_cbc(padded_pt, key)

    print("=== ECB (Repeated blocks & identical output across executions) ===")
    print("Run 1 :", format_hex_blocks(ecb_run1))
    print("Run 2 :", format_hex_blocks(ecb_run2))

    print("\n=== CBC (Randomized blocks & unique output per execution) ===")
    print("Run 1 :", format_hex_blocks(cbc_payload1[AES.block_size :]))
    print("Run 2 :", format_hex_blocks(cbc_payload2[AES.block_size :]))

    # Verify CBC decryption using the IV extracted from the first 16 bytes
    recovered = decrypt_cbc(cbc_payload1, key)
    assert recovered == plaintext
    print("\nCBC Decryption successful:", recovered.decode())