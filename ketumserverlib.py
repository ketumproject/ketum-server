import os
import uuid

import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from cryptography.fernet import Fernet
from werkzeug.contrib.cache import MemcachedCache
import settings
from utils import sha256hex, sha256

cache = MemcachedCache(
    ['127.0.0.1:11211'],
    default_timeout=15,
    key_prefix=uuid.uuid4().hex,
)


class KetumServerError(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['status'] = 'FAIL'
        rv['message'] = self.message
        return rv


class ContractBase(object):
    def __init__(self, contract=None):
        if contract is None:
            contract = uuid.uuid4().hex
        self.contract = contract
        self.type = None

    def destroy(self):
        cache.delete(self._cache_key())

    def _cache_key(self):
        return "%s[%s]" % (self.type, self.contract)

    def _contract_value(self):
        return cache.get(self._cache_key())

    def _save(self, value):
        cache.set(self._cache_key(), value)


class RegistrationContract(ContractBase):
    def __init__(self, contract=None):
        super(RegistrationContract, self).__init__(contract)
        self.type = 'registration'
        if not contract:
            self.save()

    def save(self):
        self._save(True)

    def validate(self, public_key_str, signature_b64):
        if bool(self._contract_value()) is not True:
            raise KetumServerError('Contract not found')
        contract_hash = SHA256.new()
        contract_hash.update(self.contract)
        public_key = RSA.importKey(public_key_str)
        verifier = PKCS1_PSS.new(public_key)
        self.destroy()
        signature = base64.b64decode(signature_b64)
        if not verifier.verify(contract_hash, signature):
            raise KetumServerError('Signature is not valid')


class AuthContract(ContractBase):
    def __init__(self, fingerprint, contract=None):
        super(AuthContract, self).__init__(contract)
        self.type = 'auth'
        self.fingerprint = fingerprint
        if not contract:
            self.save()

    def save(self):
        self._save(self.fingerprint)

    def validate(self, signature_b64):
        user = User(fingerprint=self._contract_value())
        result = user.validate(data=self.contract, signature_b64=signature_b64)
        if result:
            self.destroy()
            return user
        else:
            raise KetumServerError('Signature is not valid')


class User(object):
    def __init__(self, fingerprint=None, public_key_str=None):
        self.is_registered = False
        if fingerprint is None and public_key_str is None:
            raise Exception(
                'fingerprint and public_key_str can not be None at same time'
            )

        if public_key_str:
            self.public_key_str = public_key_str

        self.fingerprint = fingerprint or sha256hex(self.public_key_str)

        if self.exists():
            with open(self._get_path('public_key')) as f:
                self.public_key_str = f.read()
            with open(self._get_path('master_key')) as f:
                self.user_master_key = f.read()
            self.is_registered = True

    def register(self):
        if self.is_registered or self.exists():
            raise KetumServerError('User already registered')

        os.makedirs(self._get_path(''))

        self.user_master_key = Fernet.generate_key()
        with open(self._get_path('public_key'), 'w') as f:
            f.write(self.public_key_str)
        with open(self._get_path('master_key'), 'w') as f:
            f.write(self.user_master_key)

        self.is_registered = True

    def exists(self):
        return os.path.isfile(self._get_path('public_key'))

    def validate(self, data, signature_b64):
        if not self.is_registered or not self.public_key_str:
            return False
        signature = base64.b64decode(signature_b64)
        contract_hash = sha256(data)
        public_key = RSA.importKey(self.public_key_str)
        verifier = PKCS1_PSS.new(public_key)
        return verifier.verify(contract_hash, signature)

    def new_file(self):
        file_address = uuid.uuid4().hex

        file_key = Fernet.generate_key()
        file_crypter = Fernet(file_key)

        with open(self._get_path(file_address), 'w') as f:
            f.write(file_crypter.encrypt('empty'))

        with open(self._get_path('%s.key' % file_address), 'w') as f:
            f.write(self.master_encrypt(file_key))

        self.set_file(file_address, 'empty')
        return file_address

    def set_file(self, file_address, container):
        with open(self._get_path('%s.key' % file_address), 'r') as f:
            file_key = self.master_decrypt(f.read())
        file_crypter = Fernet(file_key)

        with open(self._get_path(file_address), 'w') as f:
            f.write(file_crypter.encrypt(container))

    def get_file(self, file_address):
        with open(self._get_path('%s.key' % file_address), 'r') as f:
            file_key = self.master_decrypt(f.read())
        file_crypter = Fernet(file_key)

        with open(self._get_path(file_address), 'r') as f:
            return file_crypter.decrypt(f.read())

    def set_storage_init(self, data):
        with open(self._get_path('storage_init'), 'w+') as f:
            f.write(self.master_encrypt(data))

    def get_storage_init(self):
        with open(self._get_path('storage_init'), 'r') as f:
            return self.master_decrypt(f.read())

    def master_encrypt(self, data):
        master_crypter = Fernet(self.user_master_key)
        return master_crypter.encrypt(data)

    def master_decrypt(self, data):
        master_crypter = Fernet(self.user_master_key)
        return master_crypter.decrypt(data)

    def _get_path(self, path):
        return os.path.join(settings.DATA_DIR, self.fingerprint, path)


def init_data_dir():
    if not os.path.exists(settings.DATA_DIR):
        os.makedirs(settings.DATA_DIR)
