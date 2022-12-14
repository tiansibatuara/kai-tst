from flask import Blueprint, request
from middleware.authentication import token_required

group = "nba"
blueprint = Blueprint(group, __name__)

@token_required
@blueprint.get(f"/{group}/salary")
def get_player_salary(session):
    limit = request.args.get('user')
    if limit is None: limit = 10
    page = request.args.get('page')
    if page is None: page = 1
    player_name = request.args.get('name')
    if player_name is None :
        return {
            "msg": "Bad Request"
        }
