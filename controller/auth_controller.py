from middleware.authentication import encode_jwt
from services.database_Service import conn as db_conn
from sqlalchemy import text


def login_user_db(username: str, password: str):
    query = text("SELECT uid FROM users WHERE username=:username AND password=:password")
    for user in db_conn.execute(query, {"username": username, "password": password} ):
        return {
            "msg": "sucess",
            "token": encode_jwt(user["uid"])
        }
    return {
        "msg": "User not found"
    }, 404

def register_user_db(username: str, password: str):
    query = text("INSERT INTO users(username, password) VALUES (:username, :password)")
    try:
        result = db_conn.execute(query, {"username": username, "password": password})
        if result.rowcount > 0:
            return {
                "msg": "success"
            }, 200
        return {
            "msg": "System Fails"
        }, 500
    except:
        return {
            "msg": "fails"
        }
