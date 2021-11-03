from flask import Flask, render_template, request, send_file
from rsa import RSA
from Paillier import Paillier
from ElGamal import ElGamal
from ECC import ECC
import io
import re
import ast

app = Flask(__name__)

ecc = ECC()

def display5LetterGroup(text):
    result = re.findall('.{1,5}', text)
    result = ' '.join(result)
    return result

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/rsa/generate", methods=['POST','GET'])
def rsaGenerate():
    if request.method == 'POST':
        key = RSA.generateKey()
        public_key = key[0]
        private_key = key[1]
        return render_template("rsa.html", mode="Generate", public = public_key, private = private_key)
    else:
        return render_template("rsa.html", mode="Generate")

@app.route("/rsa/encrypt", methods=['POST','GET'])
def rsaEncrypt():
    if request.method == 'POST':
        e = int(request.form['text1'])
        n = int(request.form['text2'])
        text = request.form['text3']
        result = RSA.encrypt(text, [e, n])
        return render_template("rsa.html", mode="Encrypt", e=e, n=n, plaintext=text, result=result)
    else:
        return render_template("rsa.html", mode="Encrypt")

@app.route("/rsa/decrypt", methods=['POST','GET'])
def rsaDecrypt():
    if request.method == 'POST':
        d = int(request.form['text1'])
        n = int(request.form['text2'])
        text = request.form['text3']
        result = RSA.decrypt(text, [d, n])
        return render_template("rsa.html", mode="Decrypt", d=d, n=n, ciphertext=text, result=result)
    else:
        return render_template("rsa.html", mode="Decrypt")

@app.route("/paillier/generate", methods=['POST','GET'])
def paillierGenerate():
    if request.method == 'POST':
        key = Paillier.generateKey()
        public_key = key[0]
        private_key = key[1]
        return render_template("paillier.html", mode="Generate", public = public_key, private = private_key)
    else:
        return render_template("paillier.html", mode="Generate")

@app.route("/paillier/encrypt", methods=['POST','GET'])
def paillierEncrypt():
    if request.method == 'POST':
        g = int(request.form['text1'])
        n = int(request.form['text2'])
        text = request.form['text3']
        result = Paillier.encrypt(text, [g, n])
        return render_template("paillier.html", mode="Encrypt", g=g, n=n, plaintext=text, result=result)
    else:
        return render_template("paillier.html", mode="Encrypt")

@app.route("/paillier/decrypt", methods=['POST','GET'])
def paillierDecrypt():
    if request.method == 'POST':
        g = int(request.form['text1'])
        n = int(request.form['text2'])
        lambdaa = int(request.form['text3'])
        mu = int(request.form['text4'])
        text = request.form['text5']
        result = Paillier.decrypt(text, [g, n], [lambdaa, mu])
        return render_template("paillier.html", mode="Decrypt", g=g, n=n, lambdaa=lambdaa, mu=mu, ciphertext=text, result=result)
    else:
        return render_template("paillier.html", mode="Decrypt")

@app.route("/elgamal/generate", methods=['POST','GET'])
def elGamalGenerate():
    if request.method == 'POST':
        key = ElGamal.generateKeys()
        public_key = key[0]
        private_key = key[1]
        return render_template("elgamal.html", mode="Generate", public = public_key, private = private_key)
    else:
        return render_template("elgamal.html", mode="Generate")

@app.route("/elgamal/encrypt", methods=['POST','GET'])
def elGamalEncrypt():
    if request.method == 'POST':
        y = int(request.form['y'])
        g = int(request.form['g'])
        p = int(request.form['p'])
        text = request.form['text']
        result = ElGamal.encrypt(text, (y, g, p))
        return render_template("elgamal.html", mode="Encrypt", y=y, g=g, p=p, plaintext=text, result=result)
    else:
        return render_template("elgamal.html", mode="Encrypt")

@app.route("/elgamal/decrypt", methods=['POST','GET'])
def elGamalDecrypt():
    if request.method == 'POST':
        x = int(request.form['x'])
        p = int(request.form['p'])
        text = ast.literal_eval(request.form['text'])
        result = ElGamal.decrypt(text, (x, p))
        return render_template("elgamal.html", mode="Decrypt", x=x, p=p, ciphertext=text, result=result)
    else:
        return render_template("elgamal.html", mode="Decrypt")

@app.route("/ecc/generate", methods=['POST','GET'])
def eccGenerate():
    if request.method == 'POST':
        key = ecc.generateKeys()
        public_key = key[1]
        private_key = key[0]
        return render_template("ecc.html", mode="Generate", public = public_key, private = private_key)
    else:
        return render_template("ecc.html", mode="Generate")

@app.route("/ecc/encrypt", methods=['POST','GET'])
def eccEncrypt():
    if request.method == 'POST':
        x = int(request.form['x'])
        y = int(request.form['y'])
        text = request.form['text']
        try:
            result = (ecc.encrypt(text, (x, y)))
            return render_template("ecc.html", mode="Encrypt", x=x, y=y, plaintext=text, result=result)
        except Exception:
            return render_template("ecc.html", mode="Decrypt", x=x, y=y, ciphertext=text, error="Error in encrypting text")
    else:
        return render_template("ecc.html", mode="Encrypt")

@app.route("/ecc/decrypt", methods=['POST','GET'])
def eccDecrypt():
    if request.method == 'POST':
        a = int(request.form['a'])
        text = ast.literal_eval(request.form['text'])
        try:
            result = ecc.decrypt(text, a)
            return render_template("ecc.html", mode="Decrypt", a=a, ciphertext=text, result=result)
        except Exception:
            return render_template("ecc.html", mode="Decrypt", a=a, ciphertext=text, error="Error in decrypting text")
    else:
        return render_template("ecc.html", mode="Decrypt")

@app.route("/saveresult", methods=['POST'])
def saveResult():
    result = request.form['result']
    return send_file(io.BytesIO(result.encode()), mimetype="text/plain",as_attachment=True, attachment_filename="result.txt")

@app.route("/savepublickey", methods=['POST'])
def savePublicKey():
    result = request.form['public']
    return send_file(io.BytesIO(result.encode()), mimetype="text/plain",as_attachment=True, attachment_filename="example_public_key.pub")

@app.route("/saveprivatekey", methods=['POST'])
def savePrivateKey():
    result = request.form['private']
    return send_file(io.BytesIO(result.encode()), mimetype="text/plain",as_attachment=True, attachment_filename="example_private_key.pri")

if __name__ == "__main__":
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=True,threaded=True)
