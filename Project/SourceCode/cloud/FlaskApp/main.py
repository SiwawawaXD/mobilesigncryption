import subprocess
print(subprocess.getoutput("pip list"))

from flask import Flask
from db import get, messageinput, signup, sendm, sendm2, getPK, vieW, Read, Read2, getsignPK, Creategroup, Getgroupprik, vieW2, Getgrouppubk, vieW2, read3, messageinput2


app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/select")
def view():
    return get()

@app.route("/prehash", methods=['POST'])
def hash():
    return messageinput()

@app.route("/signup", methods=['POST'])
def signup1():
    return signup()

@app.route("/sendmessage", methods=['POST'])
def send():
    return sendm()

@app.route("/sendmessage2", methods=['POST'])
def send2():
    return sendm2()

@app.route("/getpk", methods=['POST'])
def getpk():
    return getPK()

@app.route("/getsignpk", methods=['POST'])
def getsignpk():
    return getsignPK()

@app.route("/view", methods=['POST'])
def View():
    return vieW()

@app.route("/view2", methods=['POST'])
def View2():
    return vieW2()

@app.route("/read", methods=['POST'])
def read():
    return Read()

@app.route("/read2", methods=['POST'])
def read2():
    return Read2()

@app.route("/creategroup", methods=['POST'])
def creategroup():
    return Creategroup()
            
@app.route("/getgroupprik", methods=['POST'])
def getgroupprik():
    return Getgroupprik()

@app.route("/getgrouppubk", methods=['POST'])
def getgrouppubk():
    return Getgrouppubk()

@app.route("/verifysig", methods=['POST'])
def verifysig():
    return read3()

@app.route("/messageinput2", methods=['POST'])
def Messageinput2():
    return messageinput2()

if __name__ == '__main__':
    app.run()