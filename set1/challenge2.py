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
