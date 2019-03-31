# -*- coding: utf-8 -*-

import hashlib
import cryptos
import datetime
from string import ascii_uppercase, digits
from random import choice


def id_generator(size=32, chars=ascii_uppercase + digits):
    return ''.join(choice(chars) for _ in range(size))


def add_wallet(login, password, cur_type, test):
    test = bool(test)
    gnome_word = login + password + id_generator()
    binary_data = gnome_word if isinstance(gnome_word, bytes) else bytes(gnome_word, 'utf-8')
    private_key = hashlib.sha256(b'GNOMES' + binary_data).digest().hex()
    public_key = cryptos.privtopub(private_key)
    if cur_type == "btc":
        c = cryptos.Bitcoin(testnet=test)
    elif cur_type == "ltc":
        c = cryptos.Litecoin(testnet=test)
    else:
        return None
    address = c.pubtoaddr(public_key)

    return {'private': private_key, 'public': public_key, 'address': address}


def get_balance(address, cur_type):
    if cur_type == 'btc':
        balance_value = cryptos.Bitcoin(testnet=True).history(address)
        if len(balance_value) != 0:
            return {'value': '{:.8f}'.format(balance_value['final_balance']/100000000)}
        else:
            return {'value': "0"}
    elif cur_type == 'ltc':
        balance_value = cryptos.Litecoin(testnet=True).history(address)
        if len(balance_value) != 0:
            return {'value': balance_value['data']['balance']}
        else:
            return {'value': "0"}


def get_send(private, to, value, cur_type):
    if cur_type == 'btc':
        bit1 = cryptos.Bitcoin(testnet=True).send(private, to, value)
        return bit1
    elif cur_type == 'ltc':
        ltc1 = cryptos.Litecoin(testnet=True).send(private, to, value)
        return ltc1


def get_history(address, cur_type):
    if cur_type == "btc":
        history = cryptos.Bitcoin(testnet=True).history(address)
        history_data = list()
        for txs in history["txs"]:
            output = list()
            for j in txs["out"]:
                output.append([j["addr"], j["value"]])
            input_adr = txs["inputs"][0]["prev_out"]["addr"]
            value = txs["inputs"][0]["prev_out"]["value"]
            send_date = datetime.datetime.utcfromtimestamp(txs["time"] + 10800).strftime('%H:%M:%S %d-%m-%Y')
            send_hash = txs["hash"]
            if txs["inputs"][0]["prev_out"]["addr"] == address:
                send_colour = "red"
            else:
                send_colour = "green"
            history_data.append({"input_adr": input_adr, "value": value, "output_adrs": output, "send_date": send_date,
                                 "send_hash": send_hash, "send_colour": send_colour})

        return history_data

