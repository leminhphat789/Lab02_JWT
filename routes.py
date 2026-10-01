import base64
import binascii
import secrets
import time

import jwt
from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.security import check_password_hash

from database import get_db
from middleware import require_jwt, unauthorized

account = Blueprint('account', __name__)
protected = Blueprint('protected', __name__)
protected.before_request(require_jwt)


@account.post('/')
@account.post('/login')
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='INVALID_BODY', message='Body phải là JSON object'), 400
    username, encoded = data.get('userName'), data.get('password')
    if not isinstance(username, str) or not isinstance(encoded, str) or not username or not encoded:
        return jsonify(error='MISSING_FIELDS', message='Cần userName và password Base64'), 400
    if len(username) > 255 or len(encoded) > 1024:
        return jsonify(error='INVALID_INPUT'), 400
    try:
        password = base64.b64decode(encoded, validate=True).decode('utf-8')
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return jsonify(error='INVALID_BASE64', message='password phải là Base64 của UTF-8'), 400
    db = get_db()
    user = db.execute('SELECT * FROM "User" WHERE UserName = ?', (username,)).fetchone()
    if user is None or not check_password_hash(user['Password'], password):
        return unauthorized('INVALID_CREDENTIALS', 'Sai tài khoản hoặc mật khẩu')
    now = int(time.time())
    payload = {'sub': str(user['IdUser']), 'iat': now,
               'exp': now + current_app.config['JWT_TTL'], 'jti': secrets.token_hex(8)}
    token = jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm='HS256')
    if len(token) > 255:
        raise RuntimeError('Token does not fit the required VARCHAR(255) schema')
    db.execute('UPDATE "User" SET Token = ? WHERE IdUser = ?', (token, user['IdUser']))
    db.commit()
    return jsonify(access_token=token, token_type='Bearer',
                   expires_in=current_app.config['JWT_TTL'],
                   user={'IdUser': user['IdUser'], 'UserName': user['UserName']})


@protected.get('/auth')
def auth():
    return jsonify(authenticated=True, user={'IdUser': g.user['IdUser'], 'UserName': g.user['UserName']},
                   jwt={'header': g.jwt_header, 'payload': g.claims,
                        'parts': len(g.token.split('.')), 'signatureVerified': True})


@protected.get('/api/hello')
def hello():
    return jsonify(message='Hello World', userName=g.user['UserName'],
                   middleware='JWT verified', framework='Flask')
