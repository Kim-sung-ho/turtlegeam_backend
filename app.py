import datetime
from functools import wraps
import hashlib
from bson import ObjectId
from pymongo import MongoClient
import json
from flask import Flask, abort, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt

SECRET_KEY = 'turtle'

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})
# 오리진은 프론트엔드

client = MongoClient('localhost', 27017)
db = client.dbturtle

# 인증을 확인하는 함수


def authorize(f):
    # 랩스 또한 임포트 해준다. (한 함수를 여러곳에 사용하기 위해서)
    @wraps(f)
    def decorated_function():
        # Authorization 인지 확인을 하고, Authorization이아니라면 에러를냄.
        if not 'Authorization' in request.headers:
            abort(401)
        # Authorization이 헤더에 있었다면 토큰값을 헤더에서 꺼내온다.
        token = request.headers['Authorization']
        # 디코드가 아니면 어볼트 오류를 낸다.
        try:
            user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except:
            abort(401)
        # 이러한값을 펑션안에 넣어 보여주면
        return f(user)
    # 완성
    return decorated_function


@app.route('/')
@authorize
def hello_world(user):
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
            'email': data.get['email'],  # data.get('email'),
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
@authorize
def get_user_info(user):
    # print("1.", request.headers)  # header hidden
    # token = request.headers.get("Authorization")
    # print("2.", token)
    # user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    # print("3.", user)
    result = db.user.find_one({'_id': ObjectId(user["id"])})
    # print("4.", result)
    return jsonify({"message": "success", "email": result['email']})

# 게시글 작성을하기위한


@app.route("/article", methods=["POST"])
@authorize  # 인증이 된사람을 판별
def post_article(user):
    data = json.loads(request.data)
    # 포스트맨에서 데이터 테스트 print(data)
    # 유저의 아이디값을 가져온다, 유저의이메일 값을 가져온다.
    db_user = db.user.find_one({'_id': ObjectId(user.get('id'))})
    # 현재 시간을 가져온다.
    now = datetime.now().strftime("%H-%M-%S")
    doc = {
        'title': data.get('title', None),
        'content': data.get('content', None),
        'user': user['id'],
        'user_email': db_user['email'],
        'time': now
    }
    print(doc)

    db.article.insert_one(doc)

    return jsonify({"message": "success"})


@app.route("/article", methods=["GET"])
def get_article():
    # 리스트로 아티클을 다가져와서
    articles = list(db.article.find())
    print(articles)
    for article in articles:
        print(article.get("title"))
        article["_id"] = str(article["_id"])
    return jsonify({"message": "success", "articles": articles})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5002, debug=True)
