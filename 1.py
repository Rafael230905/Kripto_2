def pad_message(message: str, block_size: int, pad_char: str = "_") -> str:
    """Adds padding so the message length is always a multiple of block_size."""
    remainder = len(message) % block_size
    pad_len = block_size - remainder if remainder != 0 else block_size
    return message + (pad_char * pad_len)


def unpad_message(padded_message: str, pad_char: str = "_") -> str:
    """Removes padding characters after decryption."""
    return padded_message.rstrip(pad_char)


def toy_block_encrypt(block: str, key: int) -> str:
    """Reverses the block and shifts characters using a key (fixed block size)."""
    reversed_block = block[::-1]
    return "".join(chr((ord(ch) + key) % 126) for ch in reversed_block)


def toy_block_decrypt(block: str, key: int) -> str:
    """Restores a ciphertext block back to its original plaintext."""
    unshifted = "".join(chr((ord(ch) - key) % 126) for ch in block)
    return unshifted[::-1]


def ecb_encrypt_demo(
    message: str, key: int = 3, block_size: int = 4
) -> tuple[list[str], list[str]]:
    padded = pad_message(message, block_size)
    blocks = [padded[i : i + block_size] for i in range(0, len(padded), block_size)]
    ciphertext_blocks = [toy_block_encrypt(block, key) for block in blocks]
    return blocks, ciphertext_blocks


def ecb_decrypt_demo(ciphertext_blocks: list[str], key: int = 3) -> str:
    decrypted_blocks = [toy_block_decrypt(c, key) for c in ciphertext_blocks]
    return unpad_message("".join(decrypted_blocks))


if __name__ == "__main__":
    secret_key = 3
    message = "AAAAAAAABBBBBBBBAAAAAAAABBBBBBBB"
    p_blocks, c_blocks = ecb_encrypt_demo(message, key=secret_key, block_size=4)

    print("=== ECB Encryption Analysis ===")
    seen_ciphertexts: dict[str, int] = {}

    for i, (p, c) in enumerate(zip(p_blocks, c_blocks), 1):
        warning = ""
        if c in seen_ciphertexts:
            warning = f"  <-- PATTERN LEAKED (identical to Block {seen_ciphertexts[c]})"
        else:
            seen_ciphertexts[c] = i

        print(f"Block {i:02d} | Plain: {p!r} -> Cipher: {c!r}{warning}")

    recovered = ecb_decrypt_demo(c_blocks, key=secret_key)
    print(f"\nDecrypted Result: {recovered}")