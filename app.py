from flask import Flask, render_template, request, jsonify, redirect, session
from route.user import blueprint as user_blueprint
from services.database_Service import conn as cur
from dotenv import load_dotenv
from decimal import Decimal
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from sqlalchemy import text
import bcrypt
import jwt
import secrets
import re
import json

load_dotenv()
app = Flask(__name__)


app.config["SECRET_KEY"] = "secret"
app.config["MAIL_PORT"] = 587
app.config["MAIL_SERVER"] = "imap.gmail.com"
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_DEFAULT_SENDER"] = "sibatuarachristian@gmail.com"
app.config["MAIL_USERNAME"] = "sibatuarachristian@gmail.com"
app.config["MAIL_PASSWORD"] = "sbbwxwbusamrkoku"

mail = Mail(app)

@app.route('/')
def hello_world():  # put application's code here
    return 'Hello! This is Kai!'

# Authentication

key = "tiantampan"

def encodeStr(ePass):
  hashed_password = bcrypt.hashpw((key+ePass).encode("utf-8"), bcrypt.gensalt())
  return hashed_password

def verifyUser(ePass, cPass):
  return bcrypt.checkpw((key+ePass).encode("utf-8"), cPass.encode("utf-8"))

def otpHandler(data):
  otp = secrets.token_hex(3)
  session["otp"] = otp  # Store the OTP in the session
  msg = Message("Your OTP, Happy Coding!", recipients=[data['email']])
  msg.body = f"Your OTP is {otp}"
  mail.send(msg)

  return "Successfully sending OTP request! Please check your email!"

def checkUserAvailable(cur, data):
    result = cur.execute('SELECT * FROM user WHERE email=%s', (data['email'],))
    return result.rowcount > 0

def checkToken(bearer):
  try:
    token = bearer.split()[1]
    decodedToken = jwt.decode(token, "secret", algorithms=['HS256'])
    date_str = decodedToken['exp_date']
    tokenDate = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
    if (tokenDate < datetime.now()):
      raise

    return True
  except:
    return False

def checkOTP(otp):
  sessionOtp = session.get('otp')
  if (otp == sessionOtp):
    try:
      createUser()
    except:
      return "Failed to create user", 400

    session.clear()
    return "Success creating new account!", 201

  else: 
    return "Wrong OTP!", 200

def validEmail(email):
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if re.match(regex, email):
        return True
    return False

def createUser():
  data = session.get('user_cred')

  encodedPass = encodeStr(data['password'])

  cur.execute('INSERT INTO user(email, password) VALUES (%s, %s) ', (data['email'], encodedPass))

@app.route('/sign-up', methods=['POST'])
def signUp():
  json_data = request.json

  otp = request.args.get('otp')
  if (otp):
    return checkOTP(otp)

  data = {
    'email': json_data['email'],
    'password': json_data['password']
    }
  session['user_cred'] = data

  if not validEmail(data['email']):
    return "Please enter a valid Email", 401

  if checkUserAvailable(cur, data):
    return "Your email or Password is already used!", 401

  else:
    try:
      res = otpHandler(data)
    except:
      return "Failed to send OTP! Please retry!", 400
    return res, 200

@app.route('/log-in', methods=['POST'])
def logIn():
    json_data = request.json

    data = {
        "email": json_data['email'],
        "password": json_data['password'],
    }

    for user in cur.execute(' SELECT * FROM user WHERE email=%s LIMIT 1', (data['email'],)):
        if (verifyUser(data['password'], user['password'])):
            date = datetime.now() + timedelta(days=7)
            date_str = date.strftime("%Y-%m-%dT%H:%M:%S")
            token = jwt.encode({'exp_date' : date_str}, "secret")
            return jsonify(
                {
                'message': 'Please save this token and use it to access our provided API! This token will last for 7 Days',
                'token' : token
                }), 201
    return "No available email! Please sign in", 404

# Main App

@app.route('/teamByName', methods=['GET', 'POST'])
def teamByName():
  name = request.args.get('name')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
    
  rows = []
  for pinfo in cur.execute(text("SELECT * FROM `football_teams` WHERE Team LIKE :tname"), {"tname": f"%{name}%"}):
    rows.append(pinfo)
  team_info = []
  
  for p in rows:
    team_info.append({
      "Id" : p[0],
      "Team" : p[1],
      "Tournament" : p[2],
      "Goals" : str(p[3]),
      "Shots_pg": str(p[4]),
      "Yellow_cards" : str(p[5]),
      "Red_cards" : str(p[6]),
      "Percent_Possession" : str(p[7]),
      "Percent_Pass" : str(p[8]),
      "AerialsWon" : str(p[9]),
      "Rating" : str(p[10])
    })
  return jsonify(team_info)

@app.route('/teamById', methods=['GET', 'POST'])
def teamById():
  Id = request.args.get('Id')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
    
  rows = []
  for pinfo in cur.execute(text("SELECT * FROM `football_teams` WHERE `Id` =:pid"), {"pid": Id}):
    rows.append(pinfo)
  team_info = []
  
  for p in rows:
    team_info.append({
      "Id" : p[0],
      "Team" : p[1],
      "Tournament" : p[2],
      "Goals" : str(p[3]),
      "Shots_pg": str(p[4]),
      "Yellow_cards" : str(p[5]),
      "Red_cards" : str(p[6]),
      "Percent_Possession" : str(p[7]),
      "Percent_Pass" : str(p[8]),
      "AerialsWon" : str(p[9]),
      "Rating" : str(p[10])
    })
  print(team_info)
  return jsonify(team_info)

@app.route('/addTeams', methods=['POST'])
def addTeams():
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
  
  body = request.json

  payload = {
    "Team": body['Team'],
    "Tournament": body['Tournament'],
    "Goals" : body['Goals'],
    "Shots_pg" : body['Shots_pg'],
    "Yellow_cards" : body['Yellow_cards'],
    "Red_cards" : body['Red_cards'],
    "Percent_Possession" : body['Percent_Possession'],
    "Percent_Pass" : body['Percent_Pass'],
    "AerialsWon" : body['AerialsWon'],
    "Rating" :  body['Rating']
  }
  cur.execute("INSERT INTO football_teams (Team, Tournament, Goals, Shots_pg, Yellow_cards, Red_cards, Percent_Possession, Percent_Pass, AerialsWon, Rating) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (payload['Team'], payload['Tournament'], payload['Goals'], payload['Shots_pg'], payload['Yellow_cards'], payload['Red_cards'], payload['Percent_Possession'], payload['Percent_Pass'], payload['AerialsWon'], payload['Rating']))
  return jsonify(payload)

@app.route('/updateTeams', methods=['PUT'])
def updateTeams():
  auth_header = request.args.get("Authorization")
  Id = request.args.get("Id")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  body = request.json

  payload = {
    "Id": Id,
    "Team": body['Team'],
    "Tournament": body['Tournament'],
    "Goals" : body['Goals'],
    "Shots_pg" : body['Shots_pg'],
    "Yellow_cards" : body['Yellow_cards'],
    "Red_cards" : body['Red_cards'],
    "Percent_Possession" : body['Percent_Possession'],
    "Percent_Pass" : body['Percent_Pass'],
    "AerialsWon" : body['AerialsWon'],
    "Rating" :  body['Rating']
  }
  
  cur.execute("UPDATE football_teams SET Team = %s, Tournament = %s, Goals = %s, Shots_pg = %s, Yellow_cards = %s, Red_cards = %s, Percent_Possession = %s, Percent_Pass = %s, AerialsWon = %s, Rating = %s  WHERE Id = %s", (payload['Team'], payload['Tournament'], payload['Goals'], payload['Shots_pg'], payload['Yellow_cards'], payload['Red_cards'], payload['Percent_Possession'], payload['Percent_Pass'], payload['AerialsWon'], payload['Rating'], payload['Id']))
  return jsonify(payload)

@app.route('/deleteTeams')
def deleteTeams():
  auth_header = request.args.get("Authorization")
  Id = request.args.get("Id")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  cur.execute("DELETE FROM football_teams WHERE Id = %s", (Id))
  # conn.commit()
  return f"Delete team success! [Id = {Id}]"





@app.route('/winPredict', methods=['GET', 'POST'])
def winPredict():
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  body = request.json

  payload = {
    "Team 1 Id" : body['Team 1 Id'],
    "Team 2 Id" : body['Team 2 Id']
  }

  rows = []
  for pinfo in cur.execute("SELECT * FROM `football_teams` WHERE `Id` IN (%s, %s);", (payload['Team 1 Id'], payload['Team 2 Id'])):
    rows.append(pinfo)
  player_info = []

  for p in rows:
    expectedGoals = p[3]/p[4]
    player_info.append({
      "Id" : p[0],
      "Team" : p[1],
      "Tournament" : p[2],
      "Shots_pg" : str(p[4]),
      "Rating" : str(p[10]),
      "Calculation" : str(expectedGoals * p[10])
    })
  
  if float(player_info[0]['Calculation']) > float(player_info[1]['Calculation']):
    predictionTeam = player_info[0]['Team']
    predictionLeague = player_info[0]['Tournament']
  else:
    predictionTeam = player_info[1]['Team']
    predictionLeague = player_info[1]['Tournament']

  response = {"Team 1" : player_info[0]['Team'], "Team 2" : player_info[1]['Team'], "Winner Team Prediction" : predictionTeam, "Winner Team Prediction Leauge" : predictionLeague}

  print(response)
  return jsonify(response)

if __name__ == '__main__':
  app.run()

# mysql.connection.commit()
# host='0.0.0.0', port=5000