from flask import Blueprint, request
from middleware.authentication import token_required
from controller.auth_controller import register_user_db, login_user_db
group = "user"
blueprint = Blueprint(group, __name__)



@blueprint.post(f"/{group}/login")
def sign_in_user():
    data = request.get_json()
    return login_user_db(data["username"], data["password"])


@blueprint.post(f"/{group}/register")
def sign_up_user():
    data = request.get_json()
    try:
        return register_user_db(data["username"], data["password"])
    except:
        return {
            "msg": "System fails"
        }, 500

@blueprint.get("/locked")
@token_required
def required_auth_example(current_user):
    return {
        "msg": current_user
    }
