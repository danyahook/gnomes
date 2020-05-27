from gnomes.decorators import app_verification, user_verification
from flask import jsonify, request, abort, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from gnomes import db
from gnomes.models import User
from gnomes.config import Config

import datetime
import jwt

auth = Blueprint('auth', __name__)


@auth.route('/register', methods=['POST'])
@app_verification
def register():
    data = request.get_json()

    user_login = data.get('login')
    user_password = data.get('password')

    if user_login and user_password is not None:
        user_check = User.query.filter_by(db_login=user_login).first()

        if user_check is not None:
            return jsonify({'message': 'That login is already in use.'})

        hashed_password = generate_password_hash(user_password, method='sha256')
        new_user = User(db_login=user_login, db_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Successfully"})

    return abort(422)


@auth.route('/login', methods=['POST'])
@app_verification
def login():
    data = request.get_json()

    user_login, user_password = data.get('login'), data.get('password')

    if user_login and user_password is not None:
        user = User.query.filter_by(db_login=user_login).first()

        if not user:
            return jsonify({'message': 'User is unknown.'}), 401

        if not check_password_hash(user.db_password, user_password):
            return jsonify({'message': 'Wrong password.'})

        times = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({'login': user.db_login, 'exp': times}, Config.SECRET_KEY)
        user.time_check = int(times.replace(tzinfo=datetime.timezone.utc).timestamp())
        db.session.commit()

        return jsonify({'user_token': token.decode('UTF-8')})

    return abort(422)


@auth.route('/logout', methods=['GET'])
@app_verification
@user_verification
def logout(current_user):
    current_user.time_check += 1
    db.session.commit()
    return jsonify({'message': 'Successfully.'})
