# db.py
import os
import pymysql
from flask import jsonify, request
import nacl.signing
import nacl.hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from google.cloud import storage
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from datetime import datetime
import requests  
import base64

load_dotenv() 
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
storage_client = storage.Client()

db_user = os.environ.get('CLOUD_SQL_USERNAME')
db_password = os.environ.get('CLOUD_SQL_PASSWORD')
db_name = os.environ.get('CLOUD_SQL_DATABASE_NAME')
db_connection_name = os.environ.get('CLOUD_SQL_CONNECTION_NAME')


def open_connection():
    unix_socket = '/cloudsql/{}'.format(db_connection_name)
    try:
        if os.environ.get('GAE_ENV') == 'standard':
            conn = pymysql.connect(user=db_user,
                                   password=db_password,
                                   unix_socket=unix_socket,
                                   db=db_name,
                                   cursorclass=pymysql.cursors.DictCursor
                                   )
    except pymysql.MySQLError as e:
        return e
    return conn


def get():
    conn = open_connection()
    with conn.cursor() as cursor:
        result = cursor.execute('SELECT * FROM PubK;')
        keys = cursor.fetchall()
        if result > 0:
            got_songs = jsonify(keys)
        else:
            got_songs = 'No Key in DB'
        return got_songs

def messageinput():
    data = request.get_json()

    PEmessage = data['PEmessage']
    #PEmessage = data.get("message", "")
    if not PEmessage:
        return jsonify({"error": "message failed"}), 400

    print(type(PEmessage))
    hashed_message = nacl.hash.sha512(PEmessage.encode(), encoder=nacl.encoding.RawEncoder)
    #hashed_message = nacl.hash.sha512(PEmessage, encoder=nacl.encoding.RawEncoder)
    digest_hex = hashed_message.hex()
    print("MD :"+digest_hex)
    return jsonify({"MD": digest_hex})

def messageinput2():
    data = request.get_json()

    PEmessage = data['PEmessage']
    Gname = data['Gname']
    signature = data["signature"]
    #PEmessage = data.get("message", "")
    if not PEmessage:
        return jsonify({"error": "message failed"}), 400
    conn = open_connection()
    with conn.cursor() as cursor2:
        result = cursor2.execute('SELECT public_keys FROM groupPK WHERE name = %s', (Gname))
        row2 = cursor2.fetchone()
        #print(PEmessage)
        print(row2['public_keys'])
        group_keys = json.loads(row2['public_keys'])
        for i, key_entry in enumerate(group_keys):
            pk_hex = key_entry["PK"]
            #print(pk_hex)
            try:
                public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
                print("pk", public_key)
                public_key.verify(bytes.fromhex(signature), PEmessage.encode("utf-8")) 

                return jsonify({
                    "verify": "Group signature valid✅"
                })

            except InvalidSignature:
                print(f"❌ Signature is invalid")
                continue

            except Exception as e:
                continue
        print("❌ Group signature is invalid with all public keys")
        return jsonify({
            "verify": "Group signature invalid"
        })

def signup():
    data = request.get_json()
    conn = open_connection()
    Name = data['Name']
    signPK = data['signPK']
    encPK = data['encPK']
    with conn.cursor() as cursor:
        cursor.execute('INSERT INTO `user` (`user_ID`, `Name`) VALUES (null, %s)', (Name))
        conn.commit()
        ID = cursor.lastrowid
        print(ID)
        cursor.execute('INSERT INTO `PubK` (`user_ID`, `PK`) VALUES (%s, %s)', (int(ID) , encPK))
        cursor.execute('INSERT INTO `PubKSig` (`user_ID`, `PK`) VALUES (%s, %s)', (int(ID) , signPK))
        conn.commit()
        conn.close()
        return jsonify({"userID": ID}) 
    
def sendm():
    data = request.get_json()
    conn = open_connection()
    CT = data["Output"]
    sID = data["sID"]
    rID = data["rID"]

    with conn.cursor() as cursor:
        cursor.execute('INSERT INTO `message` (`m_id`, `message`,`from`,`to`) VALUES (null, %s,%s,%s)', (CT,sID,rID))
        conn.commit()
        conn.close()
        return jsonify({"result": "done"}) 
    
def sendm2():
    #data = request.get_json()
    conn = open_connection()
    # Load from .env or set manually
    print("Using bucket:", GCS_BUCKET_NAME)
    print("Request.files keys:", request.files.keys())
    print("Request.form keys:", request.form.keys())
    print("File received: ", request.files)
    print(request.content_type)
    print(request.headers)
    #print(request.data)

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    storage_client = storage.Client()
    
    metadata = json.loads(request.form['metadata'])
    sID = metadata.get('sID')
    rID = metadata.get('rID')
    signature = metadata.get('signature')
    file = request.files['file']
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = "CT/" + f"{timestamp}_{secure_filename(file.filename)}"
    blob = storage_client.bucket(GCS_BUCKET_NAME).blob(filename)
    blob.upload_from_file(file, content_type='application/octet-stream')
    blob.make_public()  

    
    with conn.cursor() as cursor:
        cursor.execute('INSERT INTO `message2` (`m_id`, `message`,`from`,`to`,`signature`) VALUES (null, %s,%s,%s,%s)', (blob.public_url,sID,rID, signature))
        conn.commit()
        conn.close()
        return jsonify({"url": blob.public_url}), 200

def getPK():
    data = request.get_json()
    ID = data['ReceiverID']
    conn = open_connection()
    with conn.cursor() as cursor:
        result = cursor.execute('SELECT PK FROM PubK WHERE user_ID = %s', (ID))
        row = cursor.fetchone()
        if row:
            return jsonify({"pk": row["PK"]})
        else:
            return jsonify({"error": "Public key not found"}), 404
        
def getsignPK():
    data = request.get_json()
    ID = data['ReceiverID']
    conn = open_connection()
    with conn.cursor() as cursor:
        result = cursor.execute('SELECT PK FROM PubKSig WHERE user_ID = %s', (ID))
        row = cursor.fetchone()
        if row:
            return jsonify({"pk": row["PK"]})
        else:
            return jsonify({"error": "Public key not found"}), 404
    
def Getgroupprik():
    data = request.get_json()
    myID = data['myID']
    name = data['name']
    conn = open_connection()
    print(myID)
    print(name)
    with conn.cursor() as cursor:
        result = cursor.execute('SELECT private_keys FROM groupSK WHERE userID = %s AND  name = %s', (myID,name))
        row = cursor.fetchone()
        if row:
            return jsonify({"prik": row["private_keys"]})
        else:
            return jsonify({"error": "Private key not found"})
        
def Getgrouppubk():
    data = request.get_json()
    name = data['name']
    conn = open_connection()
    print(name)
    with conn.cursor() as cursor:
        result = cursor.execute('SELECT public_keys FROM groupPK WHERE name = %s', (name))
        row = cursor.fetchone()
        if row:
            print(row["public_keys"])
            return row["public_keys"]
        else:
            return jsonify({"error": "Public key not found"})
        
def vieW():
    data = request.get_json()
    ID = data['ID']
    conn = open_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT m_ID FROM message WHERE `to` = %s', (ID))
        rows = cursor.fetchall()
        if rows:
            print(rows[0])
            results = [{"m_ID": row["m_ID"]} for row in rows]
            return jsonify(results)
        else:
            return jsonify({"error": "Message ID not found"}), 404
        
def vieW2():
    data = request.get_json()
    ID = data['ID']
    conn = open_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT m_ID FROM message2 WHERE `to` = %s', (ID))
        rows = cursor.fetchall()
        if rows:
            print(rows[0])
            results = [{"m_ID": row["m_ID"]} for row in rows]
            return jsonify(results)
        else:
            return jsonify({"error": "Message ID not found"}), 404
        
def Read():
    data = request.get_json()
    mID = data['m_ID']
    conn = open_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT message,`from` FROM message WHERE `m_ID` = %s', (mID))
        row = cursor.fetchone()
        if row:
            return jsonify({
                "message" : row["message"], 
                "from": row["from"]
                })
        else:
            return jsonify({"error": "Message not found"}), 404
        
def Read2():
    data = request.get_json()
    mID = data['m_ID']
    conn = open_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT message, signature, `from` FROM message2 WHERE `m_ID` = %s', (mID))
        row = cursor.fetchone()
        if row:
            file_url = row["message"]
            filename = file_url.split("/")[-1]  # Extract filename from URL
            #signature = row[1]
            return jsonify({
                "message" : row["message"], 
                "from": row["from"],
                "filename": filename,
                "signature": row["signature"]
                })
        else:
            return jsonify({"error": "Message not found"}), 404
        
def Creategroup():
    cloud = "e6433564f1f33af4eef3c194223557c928d7bec1e30d05bc469128a1fe6ac28d"
    data = request.get_json()
    userID = [item['userID'] for item in data if 'userID' in item]
    name = next(item['Gname'] for item in data if 'Gname' in item)
    print(type(data))
    print(name)
    print(userID)
    conn = open_connection()
    with conn.cursor() as cursor:
        groupPK = []
        for id in userID:
            priv, pub = generate_member_key()
            groupPK.append({"PK": pub})
            
            with conn.cursor() as cursor2:
                result = cursor2.execute('SELECT PK FROM PubK WHERE user_ID = %s', (id))
                row = cursor2.fetchone()
                if row:
                    pk = row["PK"]
                else:
                    return jsonify({"error": "Public key not found"}), 404
                
            priv2 = encrypt_with_x25519(cloud, pk, priv)
            print(priv2)
            cursor.execute('INSERT INTO `groupSK` (`id`, `userID`,`name`,`private_keys`) VALUES (null, %s, %s, %s)', (id,name,priv2))
            
        cursor.execute('INSERT INTO `groupPK` (`id`,`name`,`public_keys`) VALUES (null, %s, %s)', (name,json.dumps(groupPK)))
        conn.commit()
        conn.close()
        return jsonify({"res": "done"})

def generate_member_key():
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_bytes.hex(), public_bytes.hex()

def encrypt_with_x25519(sender_priv_hex: str, receiver_pub_hex: str, plaintext: bytes):
    # Convert hex to key objects
    sender_priv_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(sender_priv_hex))
    receiver_pub_key = X25519PublicKey.from_public_bytes(bytes.fromhex(receiver_pub_hex))

    # Derive shared secret
    shared_secret = sender_priv_key.exchange(receiver_pub_key)

    # Derive AES key from shared secret (use first 16 bytes)
    aes_key = shared_secret[:16]
    aesgcm = AESGCM(aes_key)

    # Generate nonce
    nonce = os.urandom(12)

    # Encrypt the message
    ciphertext = aesgcm.encrypt(nonce, bytes.fromhex(plaintext), None)
    print(nonce.hex()+ciphertext.hex())
    return nonce.hex()+ciphertext.hex()

def read3(): #unused
    data = request.get_json()
    mID = data['m_ID']
    Gname = data['Gname']
    conn = open_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT message, signature, `from` FROM message2 WHERE `m_ID` = %s', (mID,))
        row = cursor.fetchone()
        if row:
            file_url = row["message"]
            filename = file_url.split("/")[-1]  
            signature64 = row["signature"]
            print("sig64",signature64)
            signature = base64.b64decode(signature64)
            print("sig",signature)
            with conn.cursor() as cursor2:
                print(row["message"])
                print(row["from"])
                result = cursor2.execute('SELECT public_keys FROM groupPK WHERE name = %s', (Gname))
                row2 = cursor2.fetchone()
                response = requests.get(file_url)
                message = response.content
                PEmessage = vernam_cipher(bytes_to_hex(message), "XiaSenpaiDaisukiDesuwa")
                print(PEmessage)
                if response.status_code != 200:
                    raise Exception(f"Failed to download file: {response.status_code}")
                print(row2['public_keys'])
                group_keys = json.loads(row2['public_keys'])
                for i, key_entry in enumerate(group_keys):
                    pk_hex = key_entry["PK"]
                    print(pk_hex)
                    try:
                        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
                        print("pk", public_key)
                        public_key.verify(signature, PEmessage)  # Will raise if invalid

                        # ✅ Signature is valid — stop here
                        print(f"✅ Signature is valid for public key #{i + 1}")
                        return jsonify({
                            "message": row["message"],
                            "from": row["from"],
                            "filename": filename,
                            "signature": row["signature"],
                            "verify": f"Group signature valid (by public key #{i + 1})"
                        })

                    except InvalidSignature:
                        # ❌ Keep going — try next public key
                        print(f"❌ Signature is invalid for public key #{i + 1}")
                        continue

                    except Exception as e:
                        # ⚠️ Other unexpected error — log and try next key
                        print(f"⚠️ Error with public key #{i + 1}: {e}")
                        continue
                print("❌ Group signature is invalid with all public keys")
                return jsonify({
                    "message": row["message"],
                    "from": row["from"],
                    "filename": filename,
                    "signature": row["signature"],
                    "verify": "Group signature invalid (no match found)"
                })
            
def repeat_key_to_length(key: str, length: int) -> str:
    """Repeat the key so it's at least as long as the text."""
    return (key * (length // len(key) + 1))[:length]

def vernam_cipher(text: str, key: str) -> str:
    repeated_key = repeat_key_to_length(key, len(text))
    result = ''.join(chr(ord(t) ^ ord(k)) for t, k in zip(text, repeated_key))
    return result

def bytes_to_hex(byte_data: bytes) -> str:
    return ''.join(f'{b:02x}' for b in byte_data)

'''
def create(song):
    conn = open_connection()
    with conn.cursor() as cursor:
        cursor.execute('INSERT INTO songs (title, artist, genre) VALUES(%s, %s, %s)',
                       (song["title"], song["artist"], song["genre"]))
    conn.commit()
    conn.close()
'''