import jwt
from functools import wraps
from flask import request, abort
import time
import os

secret_key = os.getenv('SECRET_KEY')
jwt_algo = "HS256"

def encode_jwt(user_id):
    print(secret_key)
    payload = {
        "user_id": user_id,
        "expires": time.time() + 600
    }
    token = jwt.encode(payload, secret_key, algorithm=jwt_algo)
    return token

def decode_jwt(token: str):
    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=[jwt_algo])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        abort(403)

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            # dapetin bearer token
            token = request.headers["Authorization"].split(" ")[1]
        if token is None:
            return {
                "msg": "Authentication Fails",
                "status": "Unathorized"
            }, 401
        jwt_process = decode_jwt(token)
        if jwt_process is None:
            abort(500)
        return f(jwt_process, *args, **kwargs)
    return decorator
