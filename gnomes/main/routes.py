from flask import jsonify, Blueprint
import requests
from gnomes.decorators import app_verification

main = Blueprint('main', __name__)


@main.route('/', methods=['GET'])
def index():
    return "<h1 style='color:blue'>Wallto's API!</h1>"


@main.route('/price', methods=['GET'])
@app_verification
def get_btc_price():
    btc = requests.get("https://api.coinmarketcap.com/v1/ticker/bitcoin/")
    btc_json = btc.json()

    return jsonify({"btc": btc_json[-1]})
