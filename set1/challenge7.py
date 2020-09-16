from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

from pyfinite import ffield, genericmatrix
import numpy as np

def aes_decrypt_file(key, filepath):
    encrypted = base64.b64decode(open(filepath, 'rb').read())
    return aes_decrypt(key, encrypted)

def aes_decrypt(key, encrypted_bytes):
    decryptor = Cipher(algorithms.AES(key.encode()), modes.ECB()).decryptor()
    decrypted = decryptor.update(encrypted_bytes)
    print(decrypted)
    return decrypted

# aes_decrypt_file('YELLOW SUBMARINE', 'challenge7.txt')
# AES specification
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
# Nice walkthrough: https://www.adamberent.com/wp-content/uploads/2019/02/AESbyExample.pdf

def circular_left_shift(n, shift_by, max_bits=8):
    mask = 0
    for i in range(max_bits):
        mask = mask << 1 | 1
    combined = ((n << shift_by) | (n >> (max_bits - shift_by)))
    return combined & mask

f = ffield.FField(8, 283, 0)
def sbox(s):
    b = f.Inverse(s)
    return b ^ circular_left_shift(b, 1) \
             ^ circular_left_shift(b, 2) \
             ^ circular_left_shift(b, 3) \
             ^ circular_left_shift(b, 4) \
             ^ int('0x63', 16)

def new_state():
    return [[None for x in range(4)] for y in range(4)]

# Takes a 16-byte input and maps it to a 4x4 state matrix
def input_to_state(inp):
    state = new_state()
    for r in range(len(state)):
        for c in range(len(state[0])):
            state[r][c] = inp[r + 4 * c]
    return state

def byte_sub(state):
    next_state = []
    for row in state:
        new_row = []
        for byte in row:
            new_row.append(sbox(byte)) # TODO: replace with a SBox lookup table
        next_state.append(new_row)
    return next_state

# print(byte_sub(input_to_state('YELLOW SUBMARINE'.encode('ascii'))))

def shift_row(state):
    return [(state[ridx][ridx:] + state[ridx][0:ridx]) for ridx in range(len(state))]

# print(shift_row([[1, 2, 3, 4], [1, 2, 3, 4]]))

# a = genericmatrix.GenericMatrix((4, 4))
# a.SetRow(0, [2, 3, 1, 1])
# a.SetRow(0, [1, 2, 3, 1])
# a.SetRow(0, [1, 1, 2, 3])
# a.SetRow(0, [3, 1, 1, 2])
a = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
def mix_columns(state):
    # transpose it so we can easily iterate over columns
    state_cols = np.transpose(state)
    new_cols = []
    for col in state_cols:
        new_col = mix_single_col(col)
        new_cols.append(new_col)
    # transpose it back
    return np.transpose(new_cols)

def mix_single_col(col):
    new_col = []
    for i in range(len(a)):
        res = f.Multiply(col[0], a[i][0]) \
                ^ f.Multiply(col[1], a[i][1]) \
                ^ f.Multiply(col[2], a[i][2]) \
                ^ f.Multiply(col[3], a[i][3])
        new_col.append(res)
    return new_col

# D4 BF 5D 30 => 4 66 81 E5
# print(mix_single_col([int('d4', 16), int('bf', 16), int('5d', 16), int('30', 16)]))
# print(mix_columns([[int('00', 16), 2, 3, 4], [2, 3, 4, 5], [5, 6, 7, 8], [8, 9, 1, 0]]))

rcon = [int(hexstr, 16) for hexstr in ['01', '02', '04', '08', '10', '20', '40', '80', '1B', '36']]

def add_round_key(expanded_key, state, offset=0):
    state_cols = np.transpose(state)
    out_state = []
    for col_idx in range(len(state_cols)):
        xored_col = [k ^ s for (k, s) in zip(expanded_key[col_idx], state_cols[col_idx])]
        out_state.append(xored_col)
    o = np.transpose(out_state)
    return o

def expand_key(key):
    key_bytes = key.encode('ascii')
    key_cols = [(key_bytes[i:i+4]) for i in range(0, len(key_bytes), 4)]
    # We want key_cols to have 44 words/entries, 4 * 44 = 176 bytes
    # We use 4 words each round and there are 10 rounds, plus an initial round
    rounds = 10
    round_count = 0
    iteration_size = 4 # How often we want to run ALL of the key expand functions
    while len(key_cols) < ((rounds + 1) * 4):
        word = key_cols[-1]
        # Only do some of this if it's every 4th round
        if round_count % iteration_size == 0:
            word = [sbox(b) for b in (word[1:] + word[0:1])]
            first_byte = word[0] ^ rcon[round_count//(len(key)//4) - 1]
            word = [first_byte] + word[1:]
            round_count += 1
        word = [w^k for (w, k) in zip(word, key_cols[-iteration_size])]
        key_cols.append(word)
    return key_cols

# print(len(expand_key('YELLOW SUBMARINE')))
# expanded_key = expand_key('YELLOW SUBMARINE')
# print(add_round_key(expanded_key, input_to_state('HELLO THERE DAWG'.encode('ascii'))))

# encrypts one 16-byte block
def encrypt_one_block(key, content):
    state = input_to_state(content.encode('ascii'))
    expanded_key = expand_key(key)
    state = add_round_key(expanded_key, state, 0)

    rounds = 10
    for round in range(rounds - 1):
        key_offset = (round + 1) * 4
        state = byte_sub(state)
        state = shift_row(state)
        state = mix_columns(state)
        state = add_round_key(expanded_key, state, key_offset)

    state = byte_sub(state)
    state = shift_row(state)
    final = add_round_key(expanded_key, state, 40)
    flattened = []
    for sublist in final:
        for item in sublist:
            flattened.append(item)
    return bytes(flattened)

encrypted = encrypt_one_block('YELLOW SUBMARINE', 'HELLO THERE DAWG')
print(aes_decrypt('YELLOW SUBMARINE', encrypted)) # Doesn't work :(
