import os
from flask import Flask, request, g, url_for, json
from flask_cors import CORS
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

# enable cross-request
CORS(app)


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
        user_list = list()
        user_dict = dict()

        for user in users:
            user_dict['user_id'] = user.id
            user_dict['username'] = user.username
            user_list.append(user_dict)

        return {'users' : user_list}

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


class UsersByID(Resource):

    """
    Resources for working with individual users
    """

    def get(self, user_id):
        """
        Get all fields for a specific user
        """
        user = User.query.filter_by(id=user_id).first()

        if user is None:
            return {'error': 'user not found'}, 400

        permissions_id_list = list()
        permissions_list = list()
        for assoc_perm in UserPerm.query.filter_by(user_id=user.id).all():
            permissions_id_list.append(assoc_perm.perm_id)
        for perm_id in permissions_id_list:
            perm = Permission.query.filter_by(id=perm_id).first()
            permissions_list.append(perm.perm_name)

        return {'user_id': user.id, 
                'username': user.username, 
                'group_id': user.group_id,
                'permissions_list': permissions_list}, 200

    def patch(self, user_id):
        """
        Update the info for an existing user
        """
        user = User.query.filter_by(id=user_id).first()

        if user is None:
            return {'error': 'user not found'}, 400

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
        group_name = data.get('group')
        group_id = 0
        permissions_list = data.get('permissions_list')

        # check username
        if username is not None and username != user.username:
            if User.query.filter_by(username=username).first() is not None:
                    return {'error': 'username already exists'}
        else:
            username = user.username

        # check group
        if group_name is not None:
            group = Group.query.filter_by(group_name=group_name).first()
            if group is None:
                return {'error': 'group does not exist'}
            else:
                group_id = group.id
        else:
            group_id = user.group_id

        # check permissions list
        perm_id_list = list()
        if permissions_list is not None:
            for permission in permissions_list:
                perm_query = Permission.query.filter_by(perm_name=permission).first()
                if perm_query is None:
                    return {'error': 'permission {} does not exist'.format(permission)}
                else:
                    perm_id_list.append(perm_query.id)

        # update perms
        if permissions_list is not None:
            # remove old perms
            for perm in UserPerm.query.filter_by(user_id=user_id).all():
                db.session.delete(perm)
                db.session.commit()

            # add new perms
            for perm_id in perm_id_list:
                user_perm = UserPerm(user_id=user.id, perm_id=perm_id)
                db.session.add(user_perm)
                db.session.commit()

        # update password
        if password is not None:
            user.hash_password(password)

        # update group_id
        user.group_id = group_id

        # update username
        user.username = username

        return self.get(user_id)


class Groups(Resource):

    """
    Resources for working with groups
    """

    def get(self):
        """
        Returns a list of all group names
        """
        groups = Group.query.all()
        group_list = list()
        group_dict = dict()

        for group in groups:
            group_dict['group_id'] = group.id
            group_dict['group_name'] = group.group_name
            group_list.append(group_dict)

        return {'groups' : group_list}

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


class GroupsByID(Resource):

    """
    Resources for working with individual groups
    """

    def get(self, group_id):
        """
        Get all fields for a specific group
        """
        group = Group.query.filter_by(id=group_id).first()

        if group is None:
            return {'error': 'group not found'}, 400

        permissions_id_list = list()
        permissions_list = list()
        for assoc_perm in GroupPerm.query.filter_by(group_id=group.id).all():
            permissions_id_list.append(assoc_perm.perm_id)
        for perm_id in permissions_id_list:
            perm = Permission.query.filter_by(id=perm_id).first()
            permissions_list.append(perm.perm_name)

        return {'group_id': group.id, 
                'group_name': group.group_name, 
                'permissions_list': permissions_list}, 200

    def patch(self, group_id):
        """
        Update the info for an existing group
        """
        group = Group.query.filter_by(id=group_id).first()

        if group is None:
            return {'error': 'group not found'}, 400

        options = ['group_name', 
                   'permissions_list']

        data = request.get_json()
        for k in data.keys():
            if k not in options:
                return {'error': 'unknown option: {}'.format(k)}, 400

        group_name = data.get('group_name')
        permissions_list = data.get('permissions_list')

        # check username
        if group_name is not None and group_name != group.group_name:
            if Group.query.filter_by(group_name=group_name).first() is not None:
                    return {'error': 'group_name already exists'}
        else:
            group_name = group.group_name

        # check permissions list
        perm_id_list = list()
        if permissions_list is not None:
            for permission in permissions_list:
                perm_query = Permission.query.filter_by(perm_name=permission).first()
                if perm_query is None:
                    return {'error': 'permission {} does not exist'.format(permission)}
                else:
                    perm_id_list.append(perm_query.id)

        # update perms
        if permissions_list is not None:
            # remove old perms
            for perm in GroupPerm.query.filter_by(group_id=group_id).all():
                db.session.delete(perm)
                db.session.commit()

            # add new perms
            for perm_id in perm_id_list:
                group_perm = GroupPerm(group_id=group.id, perm_id=perm_id)
                db.session.add(group_perm)
                db.session.commit()

        # update group_name
        group.group_name = group_name

        return self.get(group_id)


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
            perm_dict['perm_name'] = perm.perm_name
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
                object_perm_assoc = ObjectPerm(perm_id=perm.id, object_path=object_path)
                db.session.add(object_perm_assoc)
                db.session.commit()

        return {'perm_id': perm.id}


class Token(Resource):

    """
    Handles token generation
    """

    @auth.login_required
    def post(self):
        # get a token
        token = g.user.generate_auth_token(600)
        return {'token': token.decode('ascii'), 'duration': 600}


class Auth(Resource):

    """
    Authenticates user with resources
    """

    @auth.login_required
    def post(self):
        """
        Return has_access True or False depending on permissions
        """
        options = ['resource_path']

        data = request.get_json()
        for k in data.keys():
            if k not in options:
                return {'error': 'unknown option: {}'.format(k)}, 400

        resource_path = data.get('resource_path')
        user_id = g.user.id

        # check if this API is even registered under a permission
        assoc_object_perm_list = ObjectPerm.query.filter_by(object_path=resource_path).all()
        if assoc_object_perm_list is None:
            return {'has_access': False}, 400

        # if it does, list the matching ids
        perm_id_list = list()
        for assoc_obect_perm in assoc_object_perm_list:
            perm_id_list.append(assoc_obect_perm.perm_id)

        # if the user has a group, check the permissions there first
        if g.user.group_id is not None:
            for perm_id in perm_id_list:
                if GroupPerm.query.filter_by(group_id=g.user.group_id, perm_id=perm_id).first() is not None:
                    return {'has_access': True}, 200

        for perm_id in perm_id_list:
            if UserPerm.query.filter_by(user_id=user_id, perm_id=perm_id).first is not None:
                return {'has_access': True}, 200

        # at this point it fails
        return {'has_access': False}, 400


# api resources
api.add_resource(Users, '/port/users')
api.add_resource(UsersByID, '/port/users/<int:user_id>')
api.add_resource(Groups, '/port/groups')
api.add_resource(GroupsByID, '/port/groups/<int:group_id>')
api.add_resource(Permissions, '/port/permissions')
api.add_resource(Token, '/port/token')
api.add_resource(Auth, '/port/auth')
