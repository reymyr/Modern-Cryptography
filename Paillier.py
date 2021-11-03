from typing import List
from sympy import randprime, mod_inverse
from math import gcd
import random

class Paillier:

    @staticmethod
    def generateKey() -> List[List[int]]:
        random_prime=[randprime(1,215), randprime(1,215)]
        n = random_prime[0] * random_prime[1]
        n2 = (random_prime[0]-1)*(random_prime[1]-1)
        while(gcd(n, n2) != 1):
            random_prime=[randprime(1,215), randprime(1,215)]
            n = random_prime[0] * random_prime[1]
            n2 = (random_prime[0]-1)*(random_prime[1]-1)
        
        l = ((random_prime[0]-1)*(random_prime[1]-1))//gcd((random_prime[0]-1),(random_prime[1]-1))
        g = random.randint(1, pow(n, 2)-1)
        mu = mod_inverse((pow(g, l, pow(n,2))-1)//n, n)

        public = [g,n]
        private = [l, mu]
        return [public, private]

    @staticmethod
    def blockPlainTextToAscii(text:str) -> List[str]:
        block_text = list(text.encode('ascii'))
        return block_text

    @staticmethod
    def blockCipherTextToAscii(text:str) -> List[str]:
        block_text = [text[i:i+10] for i in range(0, len(text), 10)]
        return block_text

    @staticmethod
    def encrypt(text:str, public_key:List[int]) -> str:
        plains_ascii = Paillier.blockPlainTextToAscii(text)
        result_ascii = []
        r = random.randint(0, public_key[0]-1)
        while(gcd(r, public_key[1]) != 1):
            r = random.randint(0, public_key[0]-1)
        for i in range(len(plains_ascii)):
            plain = plains_ascii[i]
            plain = pow(public_key[0], plain)*pow(r, public_key[1])
            cipher = plain % pow(public_key[1],2)
            cipher = str(cipher).zfill(10)
            result_ascii.append(cipher)
        result_ascii = "".join(result_ascii)
        return result_ascii

    @staticmethod
    def decrypt(text:str, public_key:List[int], private_key:List[int]) -> str:
        ciphers_ascii = Paillier.blockCipherTextToAscii(text)
        plain_ascii = []
        for i in range(len(ciphers_ascii)):
            cipher = int(ciphers_ascii[i])
            plain = (((pow(cipher, private_key[0], pow(public_key[1], 2))-1)//public_key[1])*private_key[1])%public_key[1]
            plain = chr(plain)
            plain_ascii.append(plain)
        plain_ascii = "".join(plain_ascii)
        return plain_ascii

if __name__ == '__main__':
    key = Paillier.generateKey()
    public = key[0]
    private = key[1]
    print("public", public)
    print("private", private)
    text = input("Masukkan plaintext: ")
    encryptText = Paillier.encrypt(text, public)
    print("Encrypted text: ", encryptText)
    decryptText = Paillier.decrypt(encryptText, public, private)
    print("Decrypted text: ", decryptText)

