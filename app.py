import datetime
import hashlib
from bson import ObjectId
from pymongo import MongoClient
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt

SECRET_KEY = 'turtle'

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})
# 오리진은 프론트엔드

client = MongoClient('localhost', 27017)
db = client.dbturtle


@app.route('/')
def hello_world():
    return jsonify({'message': 'success'})


@app.route("/signup", methods=["POST"])
def sign_up():
    # print(request)
    # print(request.form)
    # print(request.form['id'])
    # request.form.get('id')을 사용하면 none값으로 그냥돌아간다. 안정성
    # print(request.form.get('id'))
    # print(request.data)
    # request 데이터를 사용하기 위해 json.loads로 가져온다.
    data = json.loads(request.data)
    print(data)
    password = data['password']  # password = data.get('password', None)
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    exists = bool(db.user.find_one({"email": data['email']}))
    if not exists:
        doc = {
            'email': data['email'],  # data.get('email')
            'password': password_hash
        }
        db.user.insert_one(doc)
        return jsonify({'message': 'success'})
    else:
        print("중복되었습니다.")
        return jsonify({'message': 'fail'})


@app.route("/login", methods=["POST"])
def sign_in():
    print(request)
    data = json.loads(request.data)
    print(data)

    email = data.get("email")
    password = data.get("password")
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    print(hashed_pw)

    result = db.user.find_one({"email": email, "password": hashed_pw})
    print(result)

    if result is None:
        return jsonify({'message': '아이디나 비밀번호가 옳지 않습니다'}), 401

    payload = {
        "id": str(result["_id"]),
        "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24)  # 로그인 24시간 유지
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    print(token)
    return jsonify({'message': 'login', 'token': token})


@app.route("/getuserinfo", methods=["GET"])
def get_user_info():
    # print("1.", request.headers) #header hidden
    token = request.headers.get("Authorization")
    print("2.", token)
    user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    print("3.", user)
    result = db.user.find_one({'_id': ObjectId(user["id"])})
    print("4.", result)
    return jsonify({"message": "success", "email": result['email']})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5002, debug=True)
