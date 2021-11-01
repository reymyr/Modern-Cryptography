from sympy import randprime, mod_inverse
from math import gcd
import random

def generateKey():
    random_prime=[randprime(1,2147483647), randprime(1,2147483647)]
    n = random_prime[0] * random_prime[1]
    while(n>9223372036854775807):
        random_prime=[randprime(1,2147483647), randprime(1,2147483647)]
        n = random_prime[0] * random_prime[1]
    print(random_prime)
    totient_n = (random_prime[0]-1)*(random_prime[1]-1)
    e = random.choice(range(1,9223372036854775807))
    while(gcd(e, totient_n)!=1):
        e = random.choice(range(1,9223372036854775807))
    d = mod_inverse(e, totient_n)
    public = [e, n]
    private = [d, n]
    print(public, private)
    return [public, private]

def blockPlainTextToAscii(text):
    block_text = list(text.encode('ascii'))
    for i in range(len(block_text)):
        block_text[i] = str(block_text[i]).zfill(19)
    return block_text

def blockCipherTextToAscii(text):
    block_text = [text[i:i+19] for i in range(0, len(text), 19)]
    return block_text

def encryptRSA(text, public_key):
    plains_ascii = blockPlainTextToAscii(text)
    print(plains_ascii)
    result_ascii = []
    for i in range(len(plains_ascii)):
        plain = int(plains_ascii[i])
        cipher = pow(plain, public_key[0], public_key[1])
        cipher = str(cipher).zfill(19)
        result_ascii.append(cipher)
    result_ascii = "".join(result_ascii)
    return result_ascii

def decryptRSA(text, private_key):
    ciphers_ascii = blockCipherTextToAscii(text)
    print(ciphers_ascii)
    plain_ascii = []
    for i in range(len(ciphers_ascii)):
        cipher = int(ciphers_ascii[i])
        plain = pow(cipher, private_key[0], private_key[1])
        plain = chr(int(str(plain).lstrip('0')))
        plain_ascii.append(plain)
    plain_ascii = "".join(plain_ascii)
    return plain_ascii

key = generateKey()
public = key[0]
private = key[1]
text = input("Masukkan plaintext: ")
encryptText = encryptRSA(text, public)
print("Encrypted text: ", encryptText)
decryptText = decryptRSA(encryptText, private)
print("Decrypted text: ", decryptText)

