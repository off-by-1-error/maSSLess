import struct, time, secrets

def p32(*args):
    return b"".join(struct.pack("!I", x) for x in args)
def u32(x):
    return struct.unpack("!I", x)[0]
def p16(*args):
    return b"".join(struct.pack("!H", x) for x in args)
def u16(x):
    return struct.unpack("!H", x)[0]
def p8(*args):
    return b"".join(struct.pack("!B", x) for x in args)
def u8(x):
    return struct.unpack("!B", x)[0]
def p24(x):
    if x >= 0x1000000:
        raise Exception("argument to p24 (0x%x) exceeds maximum of 0xffffff"%x)
    return struct.pack("!I", x)[1:]
def u24(x):
    if len(x) != 3:
        raise Exception("argument to u24 must be 3 bytes (was %d bytes)"%len(x))
    return struct.unpack("!I", b"\0"+x)[0]
def bytes_to_long(x):
    return int.from_bytes(x, "big")
def long_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, "big")

def getTimestamp():
    return int(time.time())

def getRandomBytes(n):
    return secrets.token_bytes(n)

def xor(a, b):
    if len(a) != len(b):
        raise Exception("trying to xor different length strings")
    return b"".join(bytes(a[i]^b[i]) for i in range(len(a)))
