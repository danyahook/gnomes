from app import app
from app import db

from functools import wraps
from gnomes.models import User, Wallet
from gnomes.btc import GonmesBTC
from werkzeug.security import generate_password_hash, check_password_hash

from flask import jsonify
from flask import request
from flask import make_response
from flask import abort

import jwt
import datetime
import requests


@app.errorhandler(422)
def unprocessable_entity(error):
    return make_response(jsonify({'message': 'Unprocessable Entity.'}), 422)


def app_verification(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        app_token = None

        if 'x-api-key' in request.headers:
            app_token = request.headers['x-api-key']

        if not app_token:
            return jsonify({'message': 'Token is missing!'}), 401

        if app_token != app.config['APP_TOKEN']:
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
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(db_login=data['login']).first()

            if data['exp'] < current_user.time_check:
                return jsonify({'message': 'User token is invalid!'}), 401
        except Exception as e:
            print(e)
            return jsonify({'message': 'User token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/', methods=['GET'])
def index():
    return "<h1 style='color:blue'>Wallto's API!</h1>"


@app.route('/register', methods=['POST'])
@app_verification
def user_register():
    data = request.get_json()

    login = data.get('login')
    password = data.get('password')

    if login and password is not None:
        user_check = User.query.filter_by(db_login=login).first()

        if user_check is not None:
            return jsonify({'message': 'That login is already in use.'})

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(db_login=login, db_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Successfully"})

    return abort(422)


@app.route('/login', methods=['POST'])
@app_verification
def user_login():
    data = request.get_json()

    login, password = data.get('login'), data.get('password')

    if login and password is not None:
        user = User.query.filter_by(db_login=login).first()

        if not user:
            return jsonify({'message': 'User is unknown.'}), 401

        if not check_password_hash(user.db_password, password):
            return jsonify({'message': 'Wrong password.'})

        times = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({'login': user.db_login, 'exp': times}, app.config['SECRET_KEY'])
        user.time_check = int(times.replace(tzinfo=datetime.timezone.utc).timestamp())
        db.session.commit()

        return jsonify({'user_token': token.decode('UTF-8')})

    return abort(422)


@app.route('/logout', methods=['GET'])
@app_verification
@user_verification
def user_logout(current_user):
    current_user.time_check += 1
    db.session.commit()
    return jsonify({'message': 'Successfully.'})


@app.route('/create', methods=['POST'])
@app_verification
@user_verification
def wallet_create(current_user):
    data = request.get_json()

    test_net = data.get("testnet")
    title = data.get("title")

    if test_net is not None:
        try:
            test_net = int(test_net)
        except ValueError:
            return abort(422)

        wallet_details = GonmesBTC.add_wallet(login=current_user.db_login, password=current_user.db_password,
                                              test=test_net)

        if title is None:
            title = "Wallet for BTC."

        new_wallet = Wallet(db_prvkey=wallet_details['private'], db_pubkey=wallet_details['public'],
                            db_addres=wallet_details['address'], db_type="BTC", user_id=current_user.id,
                            db_title=title)

        db.session.add(new_wallet)
        db.session.commit()
        return jsonify({'message': 'Successfully.'})

    return abort(422)


@app.route('/add', methods=['POST'])
@app_verification
@user_verification
def wallet_add(current_user):
    data = request.get_json()

    private = data.get("private")
    public = data.get("public")
    address = data.get("address")
    title = data.get("title")

    if private and public and address is not None:
        if title is None:
            title = "Wallet for BTC."

        new_wallet = Wallet(db_prvkey=private, db_pubkey=public,
                            db_addres=address, db_type="BTC", user_id=current_user.id, db_title=title)

        db.session.add(new_wallet)
        db.session.commit()

        return jsonify({'message': 'Successfully.'})

    return abort(422)


@app.route('/wallets', methods=['GET'])
@app_verification
@user_verification
def check_wallets(current_user):
    wallets = Wallet.query.filter_by(user_id=current_user.id).all()
    data = list()
    for w in wallets:
        data.append({"id": w.id, "public": w.db_pubkey, "address": w.db_addres, "type": w.db_type, "title": w.db_title})

    return jsonify(data)


@app.route('/wallet/<int:wid>', methods=['GET'])
@app_verification
@user_verification
def check_wallet(current_user, wid):
    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()

    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401

    return jsonify({"id": wallet.id, "public": wallet.db_pubkey, "address": wallet.db_addres, "type": wallet.db_type,
                    "title": wallet.db_title})


@app.route('/balance/<wid>', methods=['GET'])
@app_verification
@user_verification
def balance_wallet(current_user, wid):
    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()

    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401
    balance = GonmesBTC.get_balance(address=wallet.db_addres)

    return jsonify(balance)


@app.route('/send/<wid>', methods=['POST'])
@app_verification
@user_verification
def send_wallet(current_user, wid):
    data = request.get_json()

    address = data.get("address")
    value = data.get("value")

    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()
    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401

    if address and value is not None:
        send = GonmesBTC.get_send(private=wallet.db_prvkey, to=address, value=value)
        return jsonify(send)

    return abort(422)


@app.route('/cvt', methods=['GET'])
@user_verification
def check(current_user):
    return jsonify({"message": "ok"})


@app.route('/history/<wid>')
@app_verification
@user_verification
def hist(current_user, wid):
    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()

    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401

    histoty = GonmesBTC.get_history(address=wallet.db_addres)

    return jsonify({"history": histoty})


@app.route('/cname/<int:wid>', methods=['POST'])
@app_verification
@user_verification
def change_name(current_user, wid):
    data = request.get_json()

    title = data.get("title")

    if title is None:
        return jsonify({'message': 'Title not found.'}), 401

    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()

    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401

    wallet.db_title = title
    db.session.commit()
    return jsonify({'message': 'Successfully.'})


@app.route('/price', methods=['GET'])
@app_verification
def curr_price():
    btc = requests.get("https://api.coinmarketcap.com/v1/ticker/bitcoin/")
    btc_json = btc.json()

    return jsonify({"btc": btc_json[-1]})


@app.route('/extend', methods=['POST'])
@app_verification
def extend():
    data = request.get_json()

    old_token = data.get("utoken")

    if old_token is not None:
        try:
            data = jwt.decode(old_token, verify=False)
        except jwt.exceptions.DecodeError:
            return jsonify({'message': "Incorrect token."}), 422

        user = User.query.filter_by(db_login=data['login']).first()
        if not user:
            return jsonify({'message': 'User is unknown.'}), 401

        times = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({'login': user.db_login, 'exp': times}, app.config['SECRET_KEY'])
        user.time_check = int(times.replace(tzinfo=datetime.timezone.utc).timestamp())
        db.session.commit()

        return jsonify({'user_token': token.decode('UTF-8')})

    return abort(422)
