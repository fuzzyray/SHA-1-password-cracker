import hashlib


class HashedPasswordData:
    def __init__(self):
        self.lookup_table = {}
        with open('top-10000-passwords.txt') as f:
            data = f.read()

        with open('known-salts.txt') as f:
            salts = f.read()

        for password in data.split('\n'):
            password_hash = hashlib.sha1(password.encode('ascii')).hexdigest()
            self.lookup_table[password_hash] = password
            for salt in salts.split('\n'):
                password_hash = hashlib.sha1('{}{}'.format(salt, password).encode('ascii')).hexdigest()
                self.lookup_table[password_hash] = password
                password_hash = hashlib.sha1('{}{}'.format(password, salt).encode('ascii')).hexdigest()
                self.lookup_table[password_hash] = password


def crack_sha1_hash(hash, use_salts=False):
    global hashed_password
    try:
        return hashed_password.lookup_table[hash]
    except KeyError:
        return 'PASSWORD NOT IN DATABASE'


# SHA1 is not that computationally expensive, however rather than doing up to 410,000
# computations per hash (for this dataset), compute all the data at once and build a
# dictionary of the resulting password hashes. For this dataset, that result isn't that
# big and it makes our lookups quick and easy. A larger dataset would require that we
# use another solution due to memory constraints.
hashed_password = HashedPasswordData()
