import os
from flask import Flask, g, url_for
from flask_restful import reqparse, Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


# define flask vars
app = Flask(__name__)
app.config['SECRET_KEY'] = 'something really really secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

auth = HTTPBasicAuth()
db = SQLAlchemy(app)

# define api stuff
api = Api(app)
parser = reqparse.RequestParser()
parser.add_argument('username')
parser.add_argument('password')


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None     # valid token, but expired
        except BadSignature:
            return None     # invalid token
        user = User.query.get(data['id'])
        return user


# create db for shitty testing
if not os.path.exists('db.sqlite'):
            db.create_all()


@auth.verify_password
def verify_password(username_or_token, password):
    # first try auth by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try user/pass auth
        user = User.query.filter_by(username=username_or_token)
        if not user or not user.verify_password(password):
            return False

        g.user = user
        return True


# user resources
class Users(Resource):
    def get(self):
        users = User.query.all()
        user_names = list()
        for user in users:
            user_names.append(user.username)

        return {'users' : user_names}

    def post(self):
        # add a new user to the db
        args = parser.parse_args()
        username = args.get('username')
        password = args.get('password')

        if username is None or password is None:
            return {'error': 'missing arguments'}, 400
        if User.query.filter_by(username=username).first() is not None:
            return {'error': 'existing user'}, 400

        user = User(username=username)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()

        return {'username': user.username}, 201, \
                {'Location': url_for('users', id=user.id, _external=True)}


# auth resource
class Auth(Resource):
    @auth.login_required
    def post(self):
        # get a token
        token = g.user.generate_auth_token(600)
        return {'token': token.decode('ascii'), 'duration': 600}


# api resources
api.add_resource(Auth, '/api/auth')
api.add_resource(Users, '/api/users')
