import string

def singlebyte_xor(single_byte, b2):
    return bytearray([single_byte ^ b for b in b2])

ETAOIN = ' ETAOINSHRDLCUMWFGYPBVKJXQZ'

ascii_letters = set(string.ascii_letters)
ascii_letters.add(' ')
def ascii_score(chars):
    count = 0
    for c in chars:
        if c in ascii_letters:
            count += 1
    return count

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
            # score = english_freq_score([chr(c) for c in r])
            if score > best_guesses[-1][1]:
                best_guesses.append([r, score, b])
                best_guesses.sort(reverse=True, key=lambda x: x[1])
                if len(best_guesses) > max_guesses: best_guesses.pop()
        except UnicodeDecodeError:
            continue

    # return [guess[0].decode() for guess in best_guesses]
    return best_guesses

# encrypted = bytearray.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
# print(single_byte_xor_decrypt(encrypted))
