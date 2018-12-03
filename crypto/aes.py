import sys
import secrets
import copy
from util import *

sbox = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]


sbox_inv = [[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
            [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
            [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
            [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
            [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
            [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
            [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
            [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
            [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
            [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
            [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
            [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
            [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
            [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
            [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]

def print_state(state):
    for i in range(0, len(state)):
        print(hex(state[i][0]),hex(state[i][1]),hex(state[i][2]),hex(state[i][3]))




#------ AES HELPER FUNCTIONS ------


#assumes 0 <= n <= 255
def sub(n):
    return sbox[(n & 0xf0) >> 4][n & 0x0f]      #sbox[high bits][low bits]


#substitute every byte in the state using the s-box
def subBytes(state):
    for i in range(0, len(state)):
        for j in range(0, len(state[i])):
            state[i][j] = sub(state[i][j])


#assumes 0 <= n <= 255
def invSub(n):
    return sbox_inv[(n & 0xf0) >> 4][n & 0x0f]



def invSubBytes(state):
    for i in range(0, len(state)):
        for j in range(0, len(state[i])):
            state[i][j] = invSub(state[i][j])


#does a left circular shift on the elements of row
#ex. shift([0, 1, 2, 3]) -> [1, 2, 3, 0]
def shift(row):
    temp = row[0]
    for i in range(0, len(row) - 1):
        row[i] = row[i+1]

    row[len(row)-1] = temp


#applies the left circular shift n times, where n is the index of the row
def shiftRows(state):
    for i in range(0, len(state)):
        for j in range(0, i):
            shift(state[i])


#does a right circular shift on the elements of row
#ex. shift([0, 1, 2, 3]) -> [3, 0, 1, 2]
def invShift(row):
    temp = row[len(row)-1]
    for i in range(len(row)-1, 0, -1):
        row[i] = row[i-1]

    row[0] = temp


#applies the right circular shift n times, where n is the index of the row
def invShiftRows(state):
    for i in range(0, len(state)):
        for j in range(0, i):
            invShift(state[i])
    


#mixColumns multiplies each column of the state [b3, b2, b1, b0], represented as
#b3*x^3 + b2*x^2 + b1*x + b0, by the constant polynomial 3x^3 + x^2 + x + 2 modulo x^4 + 1.
#all these polynomials have coefficients in GF(2^8)
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix(col):

    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ xtime(col[0] ^ col[1])
    col[1] ^= t ^ xtime(col[1] ^ col[2])
    col[2] ^= t ^ xtime(col[2] ^ col[3])
    col[3] ^= t ^ xtime(col[3] ^ u)



def mixColumns(state):
    
    for i in range(0, 4):
        col = [state[0][i], state[1][i], state[2][i], state[3][i]]
        mix(col)
        state[0][i] = col[0]
        state[1][i] = col[1]
        state[2][i] = col[2]
        state[3][i] = col[3]


#sets up the inverse polynomial in the state, so that when mixColumns is called again, the
#original polynomial is obtained
def invMixColumns(state):
    for i in range(4):
        u = xtime(xtime(state[0][i] ^ state[2][i]))
        v = xtime(xtime(state[1][i] ^ state[3][i]))
        state[0][i] ^= u
        state[1][i] ^= v
        state[2][i] ^= u
        state[3][i] ^= v

    mixColumns(state)



#XORs each byte of the state with each corresponding byte of the subkey
def addRoundKey(state, subkey):
    for i in range(0, len(state)):
        for j in range(0, len(state[i])):
            state[i][j] = state[i][j] ^ subkey[j][i]


#------ KEY SCHEDULER ------

#puts each byte in the given word through the s-box
def subWord(word):
    for i in range(0, 4):
        word[i] = sub(word[i])


#does a left circular shift on the bytes in the word
def rotWord(word):
    shift(word)
    

#based directly on the pseudocode from FIPS-197 section 5.2
def keyExpansion(main_key, nk): #-- TODO: verify correctness for nk != 4
    temp = []
    i = 0
    rcon = [0x0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    keys = []

    while i < nk:
        keys.append([main_key[4*i], main_key[4*i + 1], main_key[4*i + 2], main_key[4*i + 3]])
        i += 1
    
    i = nk

    while i < (4 * ((nk+6) + 1)):
        temp = keys[i-1].copy()

        if (i % nk) == 0:
            rotWord(temp)
            subWord(temp)
            temp[0] = temp[0] ^ rcon[i//nk]
        elif (nk > 6 and i % nk == 4):
            temp = subWord(temp)
        else:
            pass

        for j in range(0, len(temp)):
            temp[j] = keys[i-4][j] ^ temp[j]

        keys.append(temp.copy())

        i += 1

    return keys



#---------------    CIPHERS    ---------------

#based on FIPS-197 section 5.1
#this encrypts a single 16-byte block of data
#state is assumed to be a 4x4 array of bytes, keys is 44x4 array of bytes
def aes(state, keys):
    nb = 4
    nr = 10


    addRoundKey(state, keys[0:nb])


    for i in range(1, nr):
        subBytes(state)
        shiftRows(state)
        mixColumns(state)
        addRoundKey(state, keys[i*nb: (i+1)*nb])

    subBytes(state)
    shiftRows(state)
    addRoundKey(state, keys[nr*nb:(nr+1)*nb])
    return 0


#based on FIPS-197 section 5.3
#this decrypts a single 16-byte block of data
#parameters are the same as in aes()
def invAes(state, keys):
    nb = 4
    nr = 10

    addRoundKey(state, keys[nr*nb:(nr+1)*nb])

    for i in range(nr-1, 0, -1):
        invShiftRows(state)
        invSubBytes(state)
        addRoundKey(state, keys[i*nb: (i+1)*nb])
        invMixColumns(state)

    invShiftRows(state)
    invSubBytes(state)
    addRoundKey(state, keys[0:nb])


#------------ FILE I/O ------------ 




#takes an array of bytes of unknown size b, and formats it into the state array
def make_state(b):

    if len(b) == 16:
        state = [[b[0], b[4], b[8], b[12]],
                 [b[1], b[5], b[9], b[13]],
                 [b[2], b[6], b[10], b[14]],
                 [b[3], b[7], b[11], b[15]]]

    else:
        state = [[0, 0, 0, 0],
                 [0, 0, 0, 0],
                 [0, 0, 0, 0],
                 [0, 0, 0, 0]]


        #handles the case where b does not contain 16 bytes
        for i in range(0, 15):
            try:
                state[i//4][i%4] = b[(i*4)%15]
            except:
                pass

    return state


#reads plaintext bytes from file
def get_bytes(filename):
    plaintext = []

    f = open(filename, "rb")

    try:
        bytes_read = f.read(16)
        while bytes_read:
            plaintext.append(make_state(bytes_read))
            bytes_read = f.read(16)
    finally:
        f.close()

    return plaintext


#reads bytes from keyfile
def get_key(filename):
    f = open(filename, "rb")

    try:
        bytes_read = f.read(16)
        if len(bytes_read) < 16:
            print("file not large enough!")
            exit()
    finally:
        f.close()

    #print(bytes_read)
    return bytes_read


#writes the text, formatted as an array of 4x4 states, to the output file
def write_to_output(filename, text):
    f = open(filename, "wb")

    for i in range(0, len(text)):
        for j in range(0, len(text[i])):
            for k in range(0, len(text[i][j])):
                if i == len(text)-1 and text[i][k][j] == 0:
                    pass
                else:
                    f.write(bytes([text[i][k][j]]))

    f.close()


def get_iv(iv):
    for i in range(0, 4):
        temp = [0] * 4

        for i in range(0, len(temp)):
            temp[i] = bytes("5", "utf8")[0] #secrets.randbits(8)

        iv.append(temp)

#---------- DON'T USE THIS!!! ---------------------------
def aes_ecb(plaintext_filename, key_filename, output_filename, n):
    input_text = get_bytes(plaintext_filename)
    key_bytes = get_key(key_filename)
    keys = keyExpansion(key_bytes, 4)


    if n == 0:
        for i in range(0, len(input_text)):
            aes(input_text[i], keys)

    if n == 1:
        for i in range(0, len(input_text)):
            invAes(input_text[i], keys)

    write_to_output(output_filename, input_text)


def aes_cbc(plaintext_filename, key_filename, output_filename, n):
    iv = []
    get_iv(iv)

    input_text = get_bytes(plaintext_filename)
    key_bytes = get_key(key_filename)
    keys = keyExpansion(key_bytes, 4)

    if n == 0:
        addRoundKey(input_text[0], iv)
        aes(input_text[0], keys)

        for i in range(1, len(input_text)):
            addRoundKey(input_text[i], input_text[i-1])
            aes(input_text[i], keys)


        input_text = [iv] + input_text


        write_to_output(output_filename, input_text)

    if n == 1:

        last_block = copy.deepcopy(input_text[0])

        for i in range(1, len(input_text)):
            current_block = copy.deepcopy(input_text[i])

            invAes(input_text[i], keys)
            addRoundKey(input_text[i], last_block)

            last_block = copy.deepcopy(current_block)

        write_to_output(output_filename, input_text[1:])
            
def flatten(states):
    result = []
    for i in range(0, len(states)):
        for j in range(0, len(states[i])):
            for k in range(0, len(states[i][j])):
                #if i == len(states)-1 and states[i][k][j] == 0:
                #    pass
                #else:
                result.append(states[i][k][j])

    return result

def ark(state, subkey):
    for i in range(0, len(state)):
        for j in range(0, len(state[i])):
            state[i][j] = state[i][j] ^ subkey[i][j]

def format_iv(iv):
    f = [[iv[0], iv[4], iv[8], iv[12]],
         [iv[1], iv[5], iv[9], iv[13]],
         [iv[2], iv[6], iv[10], iv[14]],
         [iv[3], iv[7], iv[11], iv[15]]]

    return f
        
def aes_cbc_encrypt(key, data, iv_):
    iv = format_iv(iv_)
    temp = copy.deepcopy(data)
    states = []
    keys = keyExpansion(key, 4)

    while len(temp) > 0:
        states.append(make_state(temp[:16]))
        temp = temp[16:]
        
    ark(states[0], iv) 
    aes(states[0], keys)

    for i in range(1, len(states)):
        ark(states[i], states[i-1])
        aes(states[i], keys)

    s = bytes(flatten(states))

    return s

def aes_cbc_decrypt(key, data, iv):
    temp = copy.deepcopy(data)
    states = []
    keys = keyExpansion(key, 4)

    while len(temp) > 0:
        states.append(make_state(temp[:16]))
        temp = temp[16:]

    last_block = format_iv(iv) #copy.deepcopy(states[0])

    for i in range(0, len(states)):
        current_block = copy.deepcopy(states[i])
        invAes(states[i], keys)
        ark(states[i], last_block)
        last_block = copy.deepcopy(current_block)

    s = bytes(flatten(states))
    #s = s + bytes([0])

    return s
    


