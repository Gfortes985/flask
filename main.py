import json
import hashlib
import os
import sqlite3
import base64
from flask import Flask,abort,make_response,jsonify,request
from flask_httpauth import HTTPBasicAuth
from datetime import datetime

app = Flask(__name__)
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username,password):
    try:
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute(f"SELECT * FROM data WHERE user='{username}'")
            _data = cursor.fetchall()

            bsalt=_data[0][2]
            salt = base64.b64decode(bsalt)
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            bkey = str(base64.b64encode(key))
            bkey = bkey[1:].replace("'", "")

            cursor.close()
            db.commit()
            if bkey == _data[0][1]:
                return True
            else:
                return False
    except:
        return False

@app.route('/')
@auth.login_required()
def index():
    return auth.username()

@app.route('/api/data/<id>',methods=["GET"])
@auth.login_required
def get_data(id):
    with open('data/data.json','r') as f:
        task = json.loads(f.read())
        for i in task:
            if task[f'{i}']['id'] == id:
                return {f'{i}':task[f"{i}"]}
        abort(404)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error':'Not found'}),404)

@app.route('/api/register')
def register():
    login = request.args.get('login')
    password = request.args.get('password')
    if login == None or password ==  None:
        return make_response(jsonify({'error':'No credentials'}))

    salt = os.urandom(32)
    bsalt = str(base64.b64encode(salt))
    bsalt = bsalt[1:].replace("'", "")
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    bkey = str(base64.b64encode(key))
    bkey = bkey[1:].replace("'", "")
    _time = datetime.now().date()

    with sqlite3.connect('users.db') as db:
        cursor = db.cursor()
        try:
            cursor.execute(f"INSERT INTO data VALUES ('{login}','{bkey}', '{bsalt}', '{_time}')")
            db.commit()
            cursor.close()
            return make_response(jsonify({'info':f'{login} successfully registered'}))
        except sqlite3.IntegrityError:
            return make_response(jsonify({'error':f'{login} already exists'}))

@app.route('/api/logout')
def logout():
    return 'logout',401

#curl -u user:pass -i -H "Content-Type: application/json" -X POST -d "{"""asd""":"""1"""}" http://127.0.0.1:5000/api/data
@app.route('/api/data',methods=["POST"])
@auth.login_required
def add_data():
    if not request.json:
        abort(404)
    data = request.json
    data = dict(data)
    filedata = None
    with open('data/data.json','r') as f:
        filedata = json.loads(f.read())
        filedata = dict(filedata)
        filedata[f'{list(data.keys())[0]}'] = list(data.values())[0]
    with open('data/data.json','w') as f:
        f.write(json.dumps(filedata,indent=4))
        return json.dumps(filedata,indent=4)

if __name__ == '__main__':
    app.run(debug=True)