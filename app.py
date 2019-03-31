# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from scripts import cryptodef
import datetime
import jwt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/scripts/account.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['APP_TOKEN'] = 'gnomes'
app.config['SECRET_KEY'] = 'thisissecretkey'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    db_login = db.Column(db.String(50))
    db_password = db.Column(db.String(80))
    time_check = db.Column(db.Integer)


class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    db_prvkey = db.Column(db.String)
    db_pubkey = db.Column(db.String)
    db_addres = db.Column(db.String)
    db_type = db.Column(db.String)
    user_id = db.Column(db.Integer)


def app_verification(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        app_token = request.args.get('app')

        if app_token != app.config['APP_TOKEN']:
            return jsonify({'message': 'Application token is invalid.'}), 422

        return f(*args, **kwargs)

    return decorated


def user_verification(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('utoken')
        if not token:
            return jsonify({'message': 'User token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(db_login=data['login']).first()
            if data['exp'] < current_user.time_check:
                return jsonify({'message': 'User token is invalid!'}), 401
        except:
            return jsonify({'message': 'User token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/register')
@app_verification
def user_register():
    login = request.args.get("login")
    password = request.args.get("password")

    if login and password is not None:
        user_check = User.query.filter_by(db_login=login).first()
        if user_check is not None:
            return jsonify({'message': 'That login is already in use.'})

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(db_login=login, db_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Successfully"})

    return jsonify({'message': "Unprocessable Entity."}), 422


@app.route('/login')
@app_verification
def user_login():
    login = request.args.get("login")
    password = request.args.get("password")

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

    return jsonify({'message': "Unprocessable Entity."}), 422


@app.route('/logout')
@app_verification
@user_verification
def user_logout(current_user):
    current_user.time_check += 1
    db.session.commit()
    return jsonify({'message': 'Successfully.'})


@app.route('/create')
@app_verification
@user_verification
def wallet_create(current_user):
    cur_type = request.args.get("type")
    test_net = request.args.get("testnet")
    if cur_type and test_net is not None:
        try:
            test_net = int(test_net)
        except ValueError:
            return jsonify({'message': "Unprocessable Entity."}), 422
        if cur_type in ["btc", "ltc"]:
            wallet_details = cryptodef.add_wallet(login=current_user.db_login, password=current_user.db_password,
                                                  cur_type=cur_type, test=test_net)
        else:
            return jsonify({'message': "Unprocessable Entity."}), 422

        new_wallet = Wallet(db_prvkey=wallet_details['private'], db_pubkey=wallet_details['public'],
                            db_addres=wallet_details['address'], db_type=cur_type, user_id=current_user.id)
        db.session.add(new_wallet)
        db.session.commit()
        return jsonify({'message': 'Successfully.'})

    return jsonify({'message': "Unprocessable Entity."}), 422


@app.route('/add')
@app_verification
@user_verification
def wallet_add(current_user):
    cur_type = request.args.get("type")
    private = request.args.get("pr")
    public = request.args.get("pu")
    address = request.args.get("ad")
    if cur_type and private and public and address is not None:

        new_wallet = Wallet(db_prvkey=private, db_pubkey=public,
                            db_addres=address, db_type=cur_type, user_id=current_user.id)
        db.session.add(new_wallet)
        db.session.commit()

        return jsonify({'message': 'Successfully.'})

    return jsonify({'message': "Unprocessable Entity."}), 422


@app.route('/wallets')
@app_verification
@user_verification
def check_wallets(current_user):
    wallets = Wallet.query.filter_by(user_id=current_user.id).all()
    data = list()
    for w in wallets:
        data.append({"id": w.id, "public": w.db_pubkey, "address": w.db_addres, "type": w.db_type})

    return jsonify({'wallets': data})


@app.route('/wallet/<wid>')
@app_verification
@user_verification
def check_wallet(current_user, wid):
    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()

    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401

    return jsonify({'wallet': {"id": wallet.id, "public": wallet.db_pubkey, "address": wallet.db_addres,
                               "type": wallet.db_type}})


@app.route('/balance/<wid>')
@app_verification
@user_verification
def balance_wallet(current_user, wid):
    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()

    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401
    balance = cryptodef.get_balance(address=wallet.db_addres, cur_type=wallet.db_type)

    return jsonify(balance)


@app.route('/send/<wid>')
@app_verification
@user_verification
def send_wallet(current_user, wid):
    address = request.args.get("ad")
    value = request.args.get("va")

    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()
    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401

    if address and value is not None:
        send = cryptodef.get_send(private=wallet.db_prvkey, to=address, value=value, cur_type=wallet.db_type)
        return jsonify(send)

    return jsonify({'message': "Unprocessable Entity."}), 422


@app.route('/cvt')
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

    histoty = cryptodef.get_history(address=wallet.db_addres, cur_type=wallet.db_type)
    return jsonify({"histoty": histoty})


if __name__ == '__main__':
    app.run(host='176.53.162.231')

