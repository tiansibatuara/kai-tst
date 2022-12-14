from services.database_Service import conn as db_conn
from sqlalchemy import text

def get_player_salary(limit: int, page: int, player_name: str):
    l2 = page * limit
    l1 = l2 - limit
    query = text("SELECT * FROM players_salary WHERE name= :name lIMIT :l1,:l2")
    for player in db_conn.execute(query, {"l1": l2, "l2": l2, "name": player_name}):
        return 