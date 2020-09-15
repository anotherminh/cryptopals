from challenge3 import single_byte_xor_decrypt
from challenge5 import repeating_key_xor
import base64

def hamming_dist(a_bytes, b_bytes):
    diff = [abyte ^ bbyte for (abyte, bbyte) in zip(a_bytes, b_bytes)]
    diff_bits_count = 0
    for byte in diff:
        byte_int = int(byte)
        while byte_int > 0:
            if byte_int & 1 == 1:
                diff_bits_count += 1
            byte_int >>= 1
    return diff_bits_count

def decode_b64_file():
    f = open("challenge6.txt", 'r').read()
    return base64.b64decode(f)

def transpose_bytesarr(chunks):
    transposed = []
    block_size = len(chunks[0])
    for i in range(block_size):
        transposed.append([])
        for block in chunks:
            if i < len(block):
                transposed[i].append(block[i])
    return transposed

def decrypt_repeating_xor():
    possible_key_sizes = range(2, 41)
    max_guesses = 3
    decoded = bytearray(decode_b64_file())

    # Figure out what is the likely key size
    # We calculate the average hamming distances between ALL chunks of the given keysize
    # Just one pass through, not testing all possible combinations of the chunks
    # Then we take the top N key sizes, sorted by lowest avg hamming distance
    # Why does this work?
    # Something about the key being the same -- so if we divide up the chunks by the correct key size,
    # Those chunks will have the least # of different bits, compared to if we divided up the chunks by the incorrect keysize?
    avg_distances = []
    for keysize in possible_key_sizes:
        distances = []
        chunks = [decoded[i:i+keysize] for i in range(0, len(decoded), keysize)]
        chunks.reverse()
        while len(chunks) > 1:
            k1 = chunks.pop()
            k2 = chunks.pop()
            normalized_dist = hamming_dist(k1, k2)/keysize
            distances.append(normalized_dist)
        avg_distances.append([keysize, sum(distances)/len(distances)])
    avg_distances.sort(key=lambda result: result[1])
    best_sizes=avg_distances[:max_guesses]

    key_guesses = {}
    for keysize, dist in best_sizes:
        # Break up the file into blocks of keysize length start_idx = 0, then transpose
        chunks = [decoded[i:i+keysize] for i in range(0, len(decoded), keysize)]
        transposed = transpose_bytesarr(chunks)
        possible_keys = []
        # Solve as if single-byte XOR
        for t in transposed:
            result = single_byte_xor_decrypt(t, 2, False)
            byte_keys = []
            for guess, score, byte_key in result:
                byte_keys.append(byte_key)
            possible_keys.append(byte_keys)
        possible_keys_chrs = []
        for klist in transpose_bytesarr(possible_keys):
            possible_keys_chrs.append([chr(k) for k in klist])

        key_guesses[keysize] = ["".join(k) for k in possible_keys_chrs]

    newFile = open("challenge6_decrypted.txt", "wb")
    for keysize, keys in key_guesses.items():
        for k in keys:
            newFile.write(f"Decrypted with key: {k}\n".encode('ascii'))
            newFile.write(repeating_key_xor(k, decoded))
            newFile.write('-----------------End of file-----------------\n'.encode('ascii'))

# print(f'hamming distance: {hamming_dist(bytearray("this is a test", "ascii"), bytearray("wokka wokka!!!", "ascii"))}')
# print(f'hamming distance: {hamming_dist(bytearray("karolin", "ascii"), bytearray("kathrin", "ascii"))}')
# print(f'hamming distance: {hamming_dist(bytearray("jake", "ascii"), bytearray("fire", "ascii"))}')

decrypt_repeating_xor()
