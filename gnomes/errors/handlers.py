from flask import Blueprint, make_response, jsonify

errors = Blueprint('errors', __name__)


@errors.errorhandler(422)
def error_422(error):
    return make_response(jsonify({'message': 'Unprocessable Entity.'}), 422)
