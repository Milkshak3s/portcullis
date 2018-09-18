import os
from flask import Flask, request, g, url_for, json
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


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    group_id = db.Column(db.Integer)

    def hash_password(self, password):
        """
        Given a password, hash and store under user.password_hash
        """
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        """
        Check a password againt the hash stored with this user
        """
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        """
        Generate an auth token for this user
        """
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        """
        Given a token, return username if valid or None if invalid
        """
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None     # valid token, but expired
        except BadSignature:
            return None     # invalid token
        user = User.query.get(data['id'])
        return user


class UserPerm(db.Model):
    __tablename__ = 'users_perm'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    perm_id = db.Column(db.Integer, nullable=False)


class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(32), index=True, nullable=False)


class GroupPerm(db.Model):
    __tablename__ = 'groups_perm'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, nullable=False)
    perm_id = db.Column(db.Integer, nullable=False)


class Permission(db.Model):
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    perm_name = db.Column(db.String(32), index=True, nullable=False)


class ObjectPerm(db.Model):
    __tablename__ = "object_perm"
    id = db.Column(db.Integer, primary_key=True)
    perm_id = db.Column(db.Integer, nullable=False)
    object_path = db.Column(db.String(128), nullable=False)


# create db for shitty testing
if not os.path.exists('db.sqlite'):
    db.create_all()


@auth.verify_password
def verify_password(username_or_token, password):
    # first try auth by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try user/pass auth
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False

        g.user = user
        return True
    else:
        g.user = user
        return True


class Users(Resource):

    """
    Resources for working with users
    """

    def get(self):
        users = User.query.all()
        user_names = list()
        for user in users:
            user_names.append(user.username)

        return {'users' : user_names}

    def post(self):
        """
        Add a new user to the db
        """
        options = ['username', 
                   'password', 
                   'group', 
                   'permissions_list']

        data = request.get_json()
        for k in data.keys():
            if k not in options:
                return {'error': 'unknown option: {}'.format(k)}, 400

        username = data.get('username')
        password = data.get('password')
        group = data.get('group')
        group_id = None
        permissions_list = data.get('permissions_list')
        perm_id_list = list()

        if username is None or password is None:
            # required fields
            return {'error': 'missing arguments'}, 400
        if User.query.filter_by(username=username).first() is not None:
            # user with name already in DB
            return {'error': 'existing user'}, 400
        if group is not None:
            group_query = Group.query.filter_by(group_name=group).first()
            if group_query is None:
                # group with name does not exist
                return {'error': 'group does not exist'}, 400
            else:
                group_id = group_query.id
        if permissions_list is not None:
            # iterate through permissions, make sure they all exist
            for permission in permissions_list:
                if Permission.query.filter_by(perm_name=permission).first() is None:
                    return {'error': 'permission {} does not exist'.format(permission)}
                else:
                    perm_id_list.append(perm_query.id)

        user = User(username=username, group_id=group_id)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()

        # create references for permissions that do exit
        if permissions_list is not None:
            for perm_id in perm_id_list:
                user_perm = UserPerm(user_id=user.id, perm_id=perm_id)
                db.session.add(user_perm)
                db.session.commit()

        return {'user_id': user.id}


class Groups(Resource):

    """
    Resources for working with groups
    """

    def get(self):
        """
        Returns a list of all group names
        """
        groups = Group.query.all()
        group_names = list()
        for group in groups:
            group_names.append(group.group_name)

        return {'groups' : group_names}

    def post(self):
        """
        Registers a new group
        """
        options = ['group_name', 
                   'permissions_list']

        data = request.get_json()
        for k in data.keys():
            if k not in options:
                return {'error': 'unknown option: {}'.format(k)}, 400

        group_name = data.get('group_name')
        permissions_list = data.get('permissions_list')
        perm_id_list = list()

        if group_name is None:
            # required fields
            return {'error': 'missing arguments'}, 400
        if Group.query.filter_by(group_name=group_name).first() is not None:
            # group with name already in DB
            return {'error': 'existing user'}, 400
        if permissions_list is not None:
            # iterate through permissions, make sure they all exist
            for permission in permissions_list:
                perm_query = Permission.query.filter_by(perm_name=permission).first()
                if perm_query is None:
                    return {'error': 'permission {} does not exist'.format(permission)}
                else:
                    perm_id_list.append(perm_query.id)

        group = Group(group_name=group_name)
        db.session.add(group)
        db.session.commit()
        
        # create references for permissions that do exit
        if permissions_list is not None:
            for perm_id in perm_id_list:
                group_perm = GroupPerm(group_id=group.id, perm_id=perm_id)
                db.session.add(group_perm)
                db.session.commit()

        return {'group_id': group.id}


class Permissions(Resource):

    """
    Resources for working with permissions
    """

    def get(self):
        """
        Returns a list of registered permissions
        """
        perms = Permission.query.all()
        perm_list = list()
        perm_dict = dict()
        for perm in perms:
            perm_dict['perm_id'] = perm.id
            perm_dict['name'] = perm.perm_name
            perm_list.append(perm_dict)

        return {'perms' : perm_list}

    def post(self):
        """
        Registers a new permission
        """
        options = ['perm_name', 
                   'object_path_list']

        data = request.get_json()
        for k in data.keys():
            if k not in options:
                return {'error': 'unknown option: {}'.format(k)}, 400

        perm_name = data.get('perm_name')
        object_path_list = data.get('object_path_list')

        if perm_name is None:
            # required fields
            return {'error': 'missing arguments'}, 400
        if Permission.query.filter_by(perm_name=perm_name).first() is not None:
            # perm with name already in DB
            return {'error': 'existing permission'}, 400

        perm = Permission(perm_name=perm_name)
        db.session.add(perm)
        db.session.commit()

        if object_path_list is not None:
            # add object/permissions associations
            for object_path in object_path_list:
                object_perm_asoc = ObjectPerm(perm_id=perm.id, object_path=object_path)
                db.session.add(object_perm_asoc)
                db.session.commit()

        return {'perm_id': perm.id}


# auth resource
class Auth(Resource):
    @auth.login_required
    def post(self):
        # get a token
        token = g.user.generate_auth_token(600)
        return {'token': token.decode('ascii'), 'duration': 600}


# api resources
api.add_resource(Auth, '/port/auth')
api.add_resource(Users, '/port/users')
api.add_resource(Groups, '/port/groups')
api.add_resource(Permissions, '/port/permissions')
