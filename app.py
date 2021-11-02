from flask import Flask, render_template, request, send_file
from RSA import RSA
from Paillier import Paillier
import io
import re

app = Flask(__name__)

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
