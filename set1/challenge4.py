from challenge3 import single_byte_xor_decrypt

def detect_single_byte_xor():
    file = open("challenge4.txt", "r")
    best_score = 0
    best_guess = None
    line_number = None
    decoded = []
    for line_number, line in enumerate(file):
        guess, score, _ = single_byte_xor_decrypt(bytearray.fromhex(line.strip()))[0]
        if score >= best_score:
            best_score = score
            best_guess = guess
            line_number = line_number
    return f'{line_number}: {best_guess.decode()}'

print(detect_single_byte_xor())
