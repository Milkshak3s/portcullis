from flask import Flask
from flask_restful import reqparse, Resource, Api

# define flask vars
app = Flask(__name__)
api = Api(app)

parser = reqparse.RequestParser()
parser.add_argument('username')
parser.add_argument('password')


# user resources
class User(Resource):
    def get(self):
        # TODO: Write real API
        return {'users' : ['test1', 'test2']}


# auth resource
class Auth(Resource):
    def post(self):
        # TODO: Write real API
        args = parser.parse_args()
        user = args.get('username')
        password = args.get('password')

        if user and password:
            return {'token': 'abcdefg'}
        else:
            return {'error': 'invalid input'}, 400


# api resources
api.add_resource(Auth, '/api/auth')


# run flask server
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
