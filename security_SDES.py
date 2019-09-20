'''
Computer Systems Security 
SDES Encryption/Decryption
Daniel Quintana Menjivar
Inspired by: https://codereview.stackexchange.com/questions/108057/simplified-des-encryption
'''

key = '1010000110'
plainText = '10000110'

#  fixed permutation keys
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
P4 = (2, 4, 3, 1)

IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_inverse = (4, 1, 3, 5, 7, 2, 8, 6)

EP = (4, 1, 2, 3, 2, 3, 4, 1)

S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
     ]

S1 = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
     ]

def permutate(original, key): # original thing to permutate, with what key
    result = ''
    for i in key:
        result += original[i - 1]
    return result

def leftHalf(bits): # function returns left side
    return bits[:len(bits) // 2]

def rightHalf(bits): # function returns left side
    return bits[len(bits) // 2:]

def shift(bits): #  performs the shifting
    rotatedLeftHalf = leftHalf(bits)[1:] + leftHalf(bits)[0] # rotate left half
    rotatedRightHalf = rightHalf(bits)[1:] + rightHalf(bits)[0] # rotate right half
    return rotatedLeftHalf + rotatedRightHalf
    
def key1():
    return permutate(shift(permutate(key, P10)), P8)

def key2():
    return permutate(shift(shift(shift(permutate(key, P10)))), P8)

def exor(bits, key):
    result = ''
    for bit, keyBit in zip(bits, key):
        result += str(((int(bit) + int(keyBit)) % 2))
    return result

def sbox(inputBits, sbox):
    row = int(inputBits[0] + inputBits[3], 2)
    column = int (inputBits[1] + inputBits[2], 2)
    return '{0:02b}'.format(sbox[row][column])


def fk(bits, key):
    L = leftHalf(bits)
    R = rightHalf(bits)
    bits = permutate(R, EP)
    bits = exor(bits, key)
    bits = sbox(leftHalf(bits), S0) + sbox(rightHalf(bits), S1)
    bits = permutate(bits, P4)
    return exor(bits, L)

def encrypt(plainText):
    print("Encrypting the message \'%s\' using SDES." % plainText)
    bits = permutate(plainText, IP)
    temp = fk(bits, key1())
    bits = rightHalf(bits) + temp
    bits = fk(bits, key2())
    cipherText = permutate(bits + temp, IP_inverse)
    print("The encrypted message (i.e. cipher text) is \'%s\'" % cipherText)
    return cipherText

def decrypt(cipherText):
    print("Decrypting the message \'%s\' using SDES." % cipherText)
    bits = permutate(cipherText, IP)
    temp = fk(bits, key2())
    bits = rightHalf(bits) + temp
    bits = fk(bits, key1())
    plainText = permutate(bits + temp, IP_inverse)
    print("The decrypted message (i.e. the original plain text) is \'%s\'" % plainText)
    return plainText


cipherText = encrypt(plainText)
plainText = decrypt(cipherText)

