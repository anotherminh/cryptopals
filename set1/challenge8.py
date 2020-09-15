def count_repeating_block(ciphertext, blocksize=16):
    blocks = [ciphertext[i:i+blocksize] for i in range(0, len(ciphertext), blocksize)]
    print(blocks)
    dedup = set(blocks)
    # If size is not the same, then there is a duplicate block
    return len(blocks) - len(dedup)


# 204 ciphertexts
# AES-128, 128 bits = 16 bytes per block
# The key could be 128, 192, or 256 bits
def detect_aes():
    hex_file = open('challenge8.txt', 'r')
    aes_encrypted = []
    for line in hex_file:
        if count_repeating_block(bytes.fromhex(line.strip())) > 0:
            aes_encrypted.append(line)
    return aes_encrypted

print(detect_aes())
