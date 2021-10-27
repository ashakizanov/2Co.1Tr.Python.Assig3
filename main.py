from datetime import datetime, timedelta
from functools import wraps
from flask import Flask
from flask.helpers import make_response
from flask import request
from flask.json import jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    token = db.Column(db.String(200), unique=True, nullable=True)

    def __repr__(self):
        return '<Task %r>' % self.id


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        try:
            data = jwt.decode(token.app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Helo,could not verify the token'}), 403

        return f(*args, **kwargs)

    return decorated


@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    new_user = User(id=data['id'], login=data['login'], password=data['password'], token=data['token'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})


@app.route('/protected')
@token_required
def protected():
    return jsonify({'message': 'Hello, token which is provided is correct'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not find the user with login ' + auth.username, 401,
                             {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(login=auth.username).first()

    if not user:
        return make_response('Could not find the user with login ' + auth.username, 401,
                             {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if user.password == auth.password:
        token = jwt.encode({'public_id': user.id, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        user.token = token
        return jsonify({'token': token})

    return make_response('Could not find the user with login ' + auth.username, 401,
                         {'WWW-Authenticate': 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run(debug=True)
