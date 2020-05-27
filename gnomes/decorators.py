from functools import wraps
from flask import request
from flask import jsonify
from .config import Config
from .models import User


def app_verification(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        app_token = None

        if 'x-api-key' in request.headers:
            app_token = request.headers['x-api-key']

        if not app_token:
            return jsonify({'message': 'Token is missing!'}), 401

        if app_token != Config.APP_TOKEN:
            return jsonify({'message': 'Application token is invalid.'}), 422

        return f(*args, **kwargs)

    return decorated


def user_verification(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, Config.SECRET_KEY)
            current_user = User.query.filter_by(db_login=data['login']).first()

            if data['exp'] < current_user.time_check:
                return jsonify({'message': 'User token is invalid!'}), 401
        except Exception as e:
            print(e)
            return jsonify({'message': 'User token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated
