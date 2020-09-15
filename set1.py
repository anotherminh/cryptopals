import math
import string
import base64
import numpy as np

print("===Challenge 1===")
def hex_to_base64(str):
    return base64.b64encode(bytearray.fromhex(str))

expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
actual = hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
print(expected == actual.decode('utf-8'))

print("===Challenge 2===")
def fixed_xor(s1):
    fixed = bytearray.fromhex('686974207468652062756c6c277320657965')
    bin_s1 = bytearray.fromhex(s1)
    if len(bin_s1) == len(fixed):
        xored = bytearray([b ^ x for (b, x) in zip(bin_s1, fixed)]).hex()
        return xored
    else:
        return "Input has incorrect lenght"

actual = fixed_xor('1c0111001f010100061a024b53535009181c')
expected = '746865206b696420646f6e277420706c6179'
print(expected == actual)

print("===Challenge 3===")
def singlebyte_xor(single_byte, b2):
    return bytearray([single_byte ^ b for b in b2])

ascii_letters = set(string.ascii_letters)
ascii_letters.add(' ')
def ascii_score(chars):
    count = 0
    for c in chars:
        if c in ascii_letters:
            count += 1
    return count

ETAOIN = ' ETAOINSHRDLCUMWFGYPBVKJXQZ'

def get_letter_freq(str):
    letter_count = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'E': 0, 'F': 0, 'G': 0, 'H': 0, 'I': 0, 'J': 0, 'K': 0, 'L': 0, 'M': 0, 'N': 0, 'O': 0, 'P': 0, 'Q': 0, 'R': 0, 'S': 0, 'T': 0, 'U': 0, 'V': 0, 'W': 0, 'X': 0, 'Y': 0, 'Z': 0, ' ': 0}
    for c in str:
        if c.upper() in letter_count:
            letter_count[c.upper()] += 1
    return letter_count

def get_freq_order(str):
    letter_freq = get_letter_freq(str)
    letter_freq_list = [[k, letter_freq[k]] for k in letter_freq.keys()]
    letter_freq_list.sort(reverse=True,key=lambda x: x[1])
    return ''.join([l[0] for l in letter_freq_list])

print(get_freq_order('hello there my friend'))

def english_freq_score(str):
    freq_order = get_freq_order(str)
    match_score = 0
    for commonLetter in ETAOIN[:6]:
        if commonLetter in freq_order[:6]:
            match_score += 1
    for uncommonLetter in ETAOIN[-6:]:
        if uncommonLetter in freq_order[-6:]:
            match_score += 1
    return match_score

# returns the bytearray of the N best guesses + their ascii letter count
def single_byte_xor_decrypt(encrypted, max_guesses=1, letters_only=False):
    best_guesses = [[None, 0, None]]
    # try with all possible bytes
    # for b in range(255):
    byte_set = [ord(c) for c in string.ascii_letters] if letters_only else range(255)
    for b in byte_set:
        r = singlebyte_xor(b, encrypted)
        try:
            score = ascii_score([chr(c) for c in r])
            if score > best_guesses[-1][1]:
                best_guesses.append([r, score, b])
                best_guesses.sort(reverse=True, key=lambda x: x[1])
                if len(best_guesses) > max_guesses: best_guesses.pop()
        except UnicodeDecodeError:
            continue

    # return [guess[0].decode() for guess in best_guesses]
    return best_guesses

encrypted = bytearray.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
print(single_byte_xor_decrypt(encrypted))

print("===Challenge 4===")
def detect_single_byte_xor():
    file = open("challenge4.txt", "r")
    best_score = 0
    best_guess = None
    line_number = None
    decoded = []
    for line_number, line in enumerate(file):
        guess, score = single_byte_xor_decrypt(bytearray.fromhex(line.strip()))
        if score >= best_score:
            best_score = score
            best_guess = guess
            line_number = line_number
    return f'{line_number}: {best_guess.decode()}'

# print(detect_single_byte_xor())

print("===Challenge 5===")
def repeating_key_xor(key, content):
    kidx = 0
    is_byte_arr = isinstance(content, (bytes, bytearray))
    c_bytes = content if is_byte_arr else bytearray(content, 'ascii')
    encrypted = bytearray()
    for c in c_bytes:
        encrypted.append(c ^ ord(key[kidx % len(key)]))
        kidx += 1
    return encrypted

test = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = 'ICE'
expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
# print(repeating_key_xor(key, test) == expected)

print("===Challenge 6===")
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

print(f'hamming distance: {hamming_dist(bytearray("this is a test", "ascii"), bytearray("wokka wokka!!!", "ascii"))}')
print(f'hamming distance: {hamming_dist(bytearray("karolin", "ascii"), bytearray("kathrin", "ascii"))}')
print(f'hamming distance: {hamming_dist(bytearray("jake", "ascii"), bytearray("fire", "ascii"))}')

def decode_b64_file():
    # decoded = bytearray()
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
    print(f'best_sizes: {best_sizes}')

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
            newFile.write(bytearray(f'Decrypted with key: "{k}":\n', 'ascii'))
            newFile.write(repeating_key_xor(k, decoded))
            newFile.write(bytearray('-----------------End of file-----------------\n', 'ascii'))


decrypt_repeating_xor()

