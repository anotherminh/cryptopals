def pkcs7_pad(str, blocksize):
    bytes_to_pad = str if isinstance(str, (bytearray)) else bytearray(str, encoding='ascii')
    bytes_missing = blocksize - len(bytes_to_pad)
    print(bytes_missing)
    if bytes_missing > 0:
        added = 0
        while added < bytes_missing:
            print(bytes([bytes_missing]))
            bytes_to_pad.extend(bytes([bytes_missing]))
            added += 1
    return bytes_to_pad

print(pkcs7_pad("YELLOW SUBMARINE", 20))
