from operator import indexOf
import random
import sympy

class EllipticCurve():
  def __init__(self, a, b, p):
    self.a = a
    self.b = b
    self.p = p
    
    self.points = []
    x = 0
    point = self.getPointAtX(x)
    while len(self.points) < 256:
      while point is None:
        x += 1
        point = self.getPointAtX(x)
      self.points.append(point)
      x += 1
      point = self.getPointAtX(x)
  
  def getPointAtX(self, x):
    y2 = (pow(x, 3, self.p) + (self.a * x + self.b)) % self.p

    for j in range(1, self.p):
      if pow(j, 2, self.p) == y2:
        return (x, j)
    return None

  def addPoint(self, p1, p2):
    if p1[0] == 0 and p1[1] == -1:
      return p2
    elif p2[0] == 0 and p2[1] == -1:
      return p1
    elif p1[0] == p2[0] and p1[1] != p2[1]:
      return (0, -1)
    elif p1[0] == p2[0] and p1[1] == p2[1]:
      m = ((3 * p1[0] * p1[0] + self.a) * pow(2 * p1[1], -1, self.p)) % self.p
    else:
      m = ((p1[1] - p2[1]) * pow((p1[0] - p2[0]), -1, self.p)) % self.p
    
    xr = (m * m - p1[0] - p2[0]) % self.p
    yr = (m * (p1[0] - xr % self.p) - p1[1]) % self.p

    return (xr, yr)

  def multiplyPoint(self, k, p):
    res = p
    for i in range(k-1):
      res = self.addPoint(res, p)
    return res
  
  def negatePoint(self, p):
    return (p[0], (-1 * p[1]) % self.p)

def strToPointList(message, ec):
  ascii = list(message.encode('ascii'))

  res = []
  for m in ascii:
    point = ec.points[m]
    
    res.append(point)

  return res

def pointListToStr(points, ec):
  message = ''.join([chr(indexOf(ec.points, p)) for p in points])

  return message

class ECC:
  def __init__(self):
    p = sympy.randprime(256, 100000)

    a: int = random.randint(-10000, p-1)
    b: int = random.randint(-10000, p-1)

    while (4 * pow(a, 3) + 27 * pow(b, 2) == 0):
      a: int = random.randint(-10000, p-1)
      b: int = random.randint(-10000, p-1)
    
    ec = EllipticCurve(a, b, p)

    self.ec = ec
    x = random.randint(1, p-1)

    B = ec.getPointAtX(x)

    while B is None:
      x = random.randint(1, p-1)
      B = ec.getPointAtX(x)

    self.B = B

  def generateKeys(self): 
    p = sympy.randprime(256, 100000)

    a: int = random.randint(-10000, p-1)
    b: int = random.randint(-10000, p-1)

    while (4 * pow(a, 3) + 27 * pow(b, 2) == 0):
      a: int = random.randint(-10000, p-1)
      b: int = random.randint(-10000, p-1)
    
    ec = EllipticCurve(a, b, p)
 
    self.ec = ec

    x = random.randint(1, self.ec.p-1)
    B = self.ec.getPointAtX(x)

    while B is None:
      x = random.randint(1, self.ec.p-1)
      B = self.ec.getPointAtX(x)

    self.B = B

    return self.ec.a, self.ec.multiplyPoint(self.ec.a, self.B)

  def encrypt(self, message, pubKey):
    processedMessage = strToPointList(message, self.ec)

    res = []

    for point in processedMessage:

      k = random.randint(1, self.ec.p - 1)
      a = self.ec.multiplyPoint(k, self.B)
      b = self.ec.addPoint(point, self.ec.multiplyPoint(k, pubKey))
      res.append((a, b))

    return res

  def decrypt(self, message, privKey):
    resArray = []

    for points in message:
      bkB = self.ec.multiplyPoint(privKey, points[0])

      m = self.ec.addPoint(points[1], self.ec.negatePoint(bkB))

      resArray.append(m)

    return pointListToStr(resArray, self.ec)

if __name__ == '__main__':
  ecc = ECC()
  keys = ecc.generateKeys()
  print("keys:", keys)
  text = "TEst 123"

  enc = ecc.encrypt(text, keys[1])
  print("enc",enc)
  dec = ecc.decrypt(enc, keys[0])
  print("dec",dec)