from gnomes.decorators import app_verification, user_verification
from flask import jsonify, request, abort, Blueprint
from gnomes.models import Wallet, User
from gnomes import db
from gnomes.config import Config
from .utils import *

import datetime
import jwt

user = Blueprint('user', __name__)


@user.route('/create', methods=['POST'])
@app_verification
@user_verification
def create_wallet(current_user):
    data = request.get_json()

    test_net = data.get("testnet")
    title = data.get("title")

    if test_net is not None:
        try:
            test_net = int(test_net)
        except ValueError:
            return abort(422)

        wallet_details = add_wallet(login=current_user.db_login, password=current_user.db_password,
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


@user.route('/add', methods=['POST'])
@app_verification
@user_verification
def add_wallet(current_user):
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


@user.route('/wallets', methods=['GET'])
@app_verification
@user_verification
def get_wallets(current_user):
    wallets = Wallet.query.filter_by(user_id=current_user.id).all()
    data = list()
    for w in wallets:
        data.append({"id": w.id, "public": w.db_pubkey, "address": w.db_addres, "type": w.db_type, "title": w.db_title})

    return jsonify(data)


@user.route('/wallet/<int:wid>', methods=['GET'])
@app_verification
@user_verification
def get_wallet_by_id(current_user, wid):
    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()

    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401

    return jsonify({"id": wallet.id, "public": wallet.db_pubkey, "address": wallet.db_addres, "type": wallet.db_type,
                    "title": wallet.db_title})


@user.route('/balance/<int:wid>', methods=['GET'])
@app_verification
@user_verification
def get_balance_by_id(current_user, wid):
    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()

    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401
    balance = get_balance(address=wallet.db_addres)

    return jsonify(balance)


@user.route('/send/<int:wid>', methods=['POST'])
@app_verification
@user_verification
def send_btc(current_user, wid):
    data = request.get_json()

    address = data.get("address")
    value = data.get("value")

    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()
    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401

    if address and value is not None:
        send = get_send(private=wallet.db_prvkey, to=address, value=value)
        return jsonify(send)

    return abort(422)


@user.route('/cvt', methods=['GET'])
@user_verification
def check_valid_token(current_user):
    return jsonify({"message": "ok"})


@user.route('/history/<int:wid>')
@app_verification
@user_verification
def get_hist_by_id(current_user, wid):
    wallet = Wallet.query.filter_by(user_id=current_user.id, id=wid).first()

    if not wallet:
        return jsonify({'message': 'Wallet ID is unknown.'}), 401

    histoty = get_history(address=wallet.db_addres)

    return jsonify({"history": histoty})


@user.route('/cname/<int:wid>', methods=['POST'])
@app_verification
@user_verification
def change_wallet_name(current_user, wid):
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


@user.route('/extend', methods=['POST'])
@app_verification
def extend_token():
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
        token = jwt.encode({'login': user.db_login, 'exp': times}, Config.SECRET_KEY)
        user.time_check = int(times.replace(tzinfo=datetime.timezone.utc).timestamp())
        db.session.commit()

        return jsonify({'user_token': token.decode('UTF-8')})

    return abort(422)
