import random
import sympy
from typing import Tuple, List

class ElGamal:
  @staticmethod
  def generateKeys() -> Tuple[Tuple[int, int, int], Tuple[int, int]]: 
    p = sympy.randprime(256, 2147483647)

    g: int = random.randint(1, p-1)
    x: int = random.randrange(1, p-1)

    y: int = pow(g, x, p)

    return (y, g, p), (x, p)

  @staticmethod
  def encrypt(message: str, pubKey: Tuple[int, int, int]) -> List[Tuple[int, int]]:
    processedMessage = ElGamal.strToAsciiList(message)

    k: int = random.randint(1, pubKey[2] - 2)

    res = []

    for block in processedMessage:
      a: int = pow(pubKey[1], k, pubKey[2])
      b: int = (int(block) * pow(pubKey[0], k, pubKey[2])) % pubKey[2]
      res.append((a, b))

    return res

  @staticmethod
  def decrypt(message: List[Tuple[int, int]], privKey: Tuple[int, int]) -> str:
    resArray = []

    for block in message:
      axInv = pow(block[0], (privKey[1] - 1 - privKey[0]), privKey[1])

      m = (block[1] * axInv) % privKey[1]

      resArray.append(int(m))

    return ElGamal.asciiListToStr(resArray)

  @staticmethod
  def strToAsciiList(message: str) -> List[int]:
    ascii = list(message.encode('ascii'))
    return ascii

  @staticmethod
  def asciiListToStr(ascii: List[int]) -> str:
    message = ''.join([chr(x) for x in ascii])
    return message

if __name__ == '__main__':
  keys = ElGamal.generateKeys()
  print("Keys (public, private):", keys)
  enc = ElGamal.encrypt("Text test 1 2 3 ?!()", keys[0])
  print("Encrypted:", enc)
  dec = ElGamal.decrypt(enc, keys[1])
  print("Decrypted:", dec)