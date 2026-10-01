import secrets

import jwt
from flask import current_app, g, jsonify, request

from database import get_db


def unauthorized(code, message):
    response = jsonify(error=code, message=message)
    response.status_code = 401
    response.headers['WWW-Authenticate'] = 'Bearer'
    return response


def require_jwt():
    """Runs before every route registered on the protected Blueprint."""
    if request.method == 'OPTIONS':
        return None
    value = request.headers.get('Authorization', '')
    parts = value.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return unauthorized('MISSING_TOKEN', 'Cần Authorization: Bearer <JWT>')
    token = parts[1]
    if len(token) > 255:
        return unauthorized('INVALID_TOKEN', 'JWT không hợp lệ')
    try:
        claims = jwt.decode(token, current_app.config['JWT_SECRET'],
                            algorithms=['HS256'],
                            options={'require': ['sub', 'iat', 'exp', 'jti']})
    except jwt.ExpiredSignatureError:
        return unauthorized('TOKEN_EXPIRED', 'JWT đã hết hạn')
    except jwt.InvalidTokenError:
        return unauthorized('INVALID_TOKEN', 'JWT không hợp lệ hoặc sai chữ ký')
    user = get_db().execute('SELECT * FROM "User" WHERE CAST(IdUser AS TEXT) = ?',
                            (claims['sub'],)).fetchone()
    if user is None or not user['Token'] or not secrets.compare_digest(user['Token'], token):
        return unauthorized('TOKEN_REVOKED', 'JWT không còn là phiên đăng nhập hiện tại')
    g.user, g.claims, g.token = user, claims, token
    g.jwt_header = jwt.get_unverified_header(token)  # Signature already verified above.
