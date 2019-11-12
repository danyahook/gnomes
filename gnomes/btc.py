import hashlib
import cryptos
import datetime
from string import ascii_uppercase, digits
from random import choice


def id_generator(size=32, chars=ascii_uppercase + digits):
    return ''.join(choice(chars) for _ in range(size))


class GonmesBTC:
    @staticmethod
    def add_wallet(login, password, test):
        test = bool(test)
        gnome_word = login + password + id_generator()
        binary_data = gnome_word if isinstance(gnome_word, bytes) else bytes(gnome_word, 'utf-8')
        private_key = hashlib.sha256(b'GNOMES' + binary_data).digest().hex()
        public_key = cryptos.privtopub(private_key)

        c = cryptos.Bitcoin(testnet=test)

        address = c.pubtoaddr(public_key)

        return {'private': private_key, 'public': public_key, 'address': address}

    @staticmethod
    def get_balance(address):
        balance_value = cryptos.Bitcoin(testnet=True).history(address)
        if len(balance_value) != 0:
            return {'value': '{:.8f}'.format(balance_value['final_balance']/100000000)}
        else:
            return {'value': "0"}

    @staticmethod
    def get_send(private, to, value):
        try:
            bit1 = cryptos.Bitcoin(testnet=True).send(private, to, value)
        except:
            bit1 = {"message": "error sending"}
        return bit1

    @staticmethod
    def get_history(address):
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

        if len(history_data) == 0:
            history_data.append('empty')
        return history_data
