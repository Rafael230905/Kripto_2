from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def split_blocks(data: bytes, block_size: int = AES.block_size) -> list[bytes]:
    """Splits byte data into chunks of size block_size."""
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def demo_aes_ecb_vs_cbc(plaintext: bytes, key: bytes) -> None:
    padded_pt = pad(plaintext, AES.block_size)
    pt_blocks = split_blocks(padded_pt)

    # 1. ECB Mode (Insecure - Deterministic)
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    ct_ecb = cipher_ecb.encrypt(padded_pt)
    ecb_blocks = split_blocks(ct_ecb)

    # 2. CBC Mode (Secure - Uses a random IV to conceal patterns)
    iv = get_random_bytes(AES.block_size)
    cipher_cbc = AES.new(key, AES.MODE_CBC, iv=iv)
    ct_cbc = cipher_cbc.encrypt(padded_pt)
    cbc_blocks = split_blocks(ct_cbc)

    print("=== Block-by-Block Comparison (ECB vs CBC) ===")
    for i, (p, ecb, cbc) in enumerate(zip(pt_blocks, ecb_blocks, cbc_blocks), 1):
        print(f"Block {i}:")
        print(f"  Plaintext (padded) : {p.hex()}  ({p})")
        print(f"  Ciphertext ECB     : {ecb.hex()}")
        print(f"  Ciphertext CBC     : {cbc.hex()}")

    print("\n=== Pattern Leakage Detection (Block 1 vs Block 2) ===")
    print(f"ECB (Block 1 == Block 2): {ecb_blocks[0] == ecb_blocks[1]}  -> Pattern leaked!")
    print(f"CBC (Block 1 == Block 2): {cbc_blocks[0] == cbc_blocks[1]} -> Pattern concealed")

    # 3. Decryption Verification
    decipher_ecb = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(decipher_ecb.decrypt(ct_ecb), AES.block_size)
    assert decrypted == plaintext, "Decryption result does not match original plaintext!"
    print(f"\nDecryption successful: {decrypted.decode()}")


if __name__ == "__main__":
    # In production environments, always generate keys via: key = get_random_bytes(16)
    secret_key = b"1234567890abcdef"
    sample_text = b"AAAAAAAABBBBBBBBAAAAAAAABBBBBBBB"
    demo_aes_ecb_vs_cbc(sample_text, secret_key)