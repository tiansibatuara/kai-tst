from sqlalchemy import create_engine

db_user = "doadmin" # ex : root
db_password = "AVNS_mVez6y_ykgMWWtrI_hr"
db_host = "eagen-love-tst-do-user-10225549-0.b.db.ondigitalocean.com" # ex : localhost
db_port = 25060 # ex :3306
db_database = "kai" #ex : db_afkar
db_sslmode = True

# ini klo pake mysql
db_engine = f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_database}"

engine = create_engine(db_engine)
conn = engine.connect()