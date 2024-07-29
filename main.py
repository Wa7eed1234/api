from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import spacy
app = Flask(__name__)
api = Api(app)

# Configure the SQLAlchemy part of the app instance
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///similaritydb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Create the SQLAlchemy db instance
db = SQLAlchemy(app)

# Define a User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    tokens = db.Column(db.Integer, nullable=False)

# Create the database and tables
with app.app_context():
    db.create_all()

def UserExist(username):
    return db.session.query(User.id).filter_by(username=username).scalar() is not None

class Register(Resource):
    def post(self):
        # Step 1 is to get posted data by the user
        try:
            postedData = request.get_json()
            print("Received data:", postedData)  # Logging the received data

            # Get the data
            username = postedData["username"]
            password = postedData["password"]
        except Exception as e:
            return jsonify({"status": 400, "msg": "Invalid input", "error": str(e)})

        if UserExist(username):
            retJson = {
                'status': 301,
                'msg': 'Invalid Username'
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Store username and pw into the database
        new_user = User(username=username, password=hashed_pw, tokens=6)
        db.session.add(new_user)
        db.session.commit()

        retJson = {
            "status": 200,
            "msg": "You successfully signed up for the API"
        }
        return jsonify(retJson)

def verifyPw(username, password):
    if not UserExist(username):
        return False

    user = User.query.filter_by(username=username).first()
    return bcrypt.hashpw(password.encode('utf8'), user.password) == user.password

def countTokens(username):
    user = User.query.filter_by(username=username).first()
    return user.tokens

class Detect(Resource):
    def post(self):
        # Step 1 get the posted data
        try:
            postedData = request.get_json()
            print("Received data:", postedData)  # Logging the received data

            # Step 2 is to read the data
            username = postedData["username"]
            password = postedData["password"]
            text1 = postedData["text1"]
            text2 = postedData["text2"]
        except Exception as e:
            return jsonify({"status": 400, "msg": "Invalid input", "error": str(e)})

        if not UserExist(username):
            retJson = {
                'status': 301,
                'msg': "Invalid Username"
            }
            return jsonify(retJson)

        # Step 3 verify the username pw match
        correct_pw = verifyPw(username, password)

        if not correct_pw:
            retJson = {
                "status": 302,
                "msg": "Incorrect Password"
            }
            return jsonify(retJson)

        # Step 4 Verify user has enough tokens
        num_tokens = countTokens(username)
        if num_tokens <= 0:
            retJson = {
                "status": 303,
                "msg": "You are out of tokens, please refill!"
            }
            return jsonify(retJson)

        # Calculate edit distance between text1, text2
        import spacy
        nlp = spacy.load('en_core_web_sm')
        text1 = nlp(text1)
        text2 = nlp(text2)

        ratio = text1.similarity(text2)

        retJson = {
            "status": 200,
            "ratio": ratio,
            "msg": "Similarity score calculated successfully"
        }

        # Take away 1 token from user
        user = User.query.filter_by(username=username).first()
        user.tokens -= 1
        db.session.commit()

        return jsonify(retJson)

class Refill(Resource):
    def post(self):
        try:
            postedData = request.get_json()
            print("Received data:", postedData)  # Logging the received data

            username = postedData["username"]
            password = postedData["admin_pw"]
            refill_amount = postedData["refill"]
        except Exception as e:
            return jsonify({"status": 400, "msg": "Invalid input", "error": str(e)})

        if not UserExist(username):
            retJson = {
                "status": 301,
                "msg": "Invalid Username"
            }
            return jsonify(retJson)

        correct_pw = "abc123"
        if not password == correct_pw:
            retJson = {
                "status": 304,
                "msg": "Invalid Admin Password"
            }
            return jsonify(retJson)

        # MAKE THE USER PAY!
        user = User.query.filter_by(username=username).first()
        user.tokens = refill_amount
        db.session.commit()

        retJson = {
            "status": 200,
            "msg": "Refilled successfully"
        }
        return jsonify(retJson)

api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refill, '/refill')

if __name__ == "__main__":
    app.run(host='0.0.0.0')