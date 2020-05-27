from gnomes import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    db_login = db.Column(db.String(50))
    db_password = db.Column(db.String(80))
    time_check = db.Column(db.Integer)

    def __repr__(self):
        return '<User id: {}, login: {}.>'.format(self.id, self.db_login)


class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    db_title = db.Column(db.String)
    db_prvkey = db.Column(db.String)
    db_pubkey = db.Column(db.String)
    db_addres = db.Column(db.String)
    db_type = db.Column(db.String)
    user_id = db.Column(db.Integer)

    def __repr__(self):
        return '<User id: {}, wallet: {}.>'.format(self.id, self.db_title)
