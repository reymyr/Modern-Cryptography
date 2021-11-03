import random
import sympy
from typing import Tuple, List

def strToAsciiList(message: str) -> List[int]:
  ascii = list(message.encode('ascii'))
  return ascii

def asciiListToStr(ascii: List[int]) -> str:
  print(ascii)
  message = ''.join([chr(x) for x in ascii])
  return message
class ElGamal:
  @staticmethod
  def generateKeys() -> Tuple[Tuple[int, int, int], Tuple[int, int]]: 
    p = sympy.randprime(256, 2147483647)

    g = random.randint(1, p-1)
    x = random.randrange(1, p-1)

    y = pow(g, x, p)

    return (y, g, p), (x, p)

  @staticmethod
  def encrypt(message: str, pubKey: Tuple[int, int, int]) -> List[Tuple[int, int]]:
    processedMessage = strToAsciiList(message)

    res = []

    for block in processedMessage:
      k = random.randint(1, pubKey[2] - 2)
      a = pow(pubKey[1], k, pubKey[2])
      b = (int(block) * pow(pubKey[0], k, pubKey[2])) % pubKey[2]
      res.append((a, b))

    return res

  @staticmethod
  def decrypt(message: List[Tuple[int, int]], privKey: Tuple[int, int]) -> str:
    resArray = []

    for block in message:
      axInv = pow(int(block[0]), (privKey[1] - 1 - privKey[0]), privKey[1])

      m = (block[1] * axInv) % privKey[1]

      resArray.append(int(m))

    return asciiListToStr(resArray)

if __name__ == '__main__':
  keys = ElGamal.generateKeys()
  print("Keys (public, private):", keys)
  text = "TText test 1 2 3 ?!()"
  print("Text:", text)
  enc = ElGamal.encrypt(text, keys[0])
  print("Encrypted:", enc)
  dec = ElGamal.decrypt(enc, keys[1])
  print("Decrypted:", dec)