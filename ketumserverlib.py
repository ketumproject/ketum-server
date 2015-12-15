import os
import subprocess
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
        storage = Storage(fingerprint=self._contract_value())
        result = storage.validate(data=self.contract, signature_b64=signature_b64)
        if result:
            self.destroy()
            return storage
        else:
            raise KetumServerError('Signature is not valid')


class Storage(object):
    def __init__(self, fingerprint=None, public_key_str=None):
        self.is_registered = False
        if fingerprint is None and public_key_str is None:
            raise Exception(
                'fingerprint and public_key_str can not be None at same time'
            )

        if public_key_str:
            self.public_key_str = public_key_str

        self.fingerprint = fingerprint or sha256hex(self.public_key_str)
        self.storage_path = os.path.join(settings.DATA_DIR, self.fingerprint)

        if self.exists():
            with open(self.get_path('public_key')) as f:
                self.public_key_str = f.read()
            with open(self.get_path('master_key')) as f:
                self.storage_master_key = f.read()
            self.is_registered = True
            self.file_manager = FileManager(self)
            self.storage_meta = StorageMeta(self)

    def register(self):
        if self.is_registered or self.exists():
            raise KetumServerError('Storage already registered')

        os.makedirs(self.get_path(''))

        self.storage_master_key = Fernet.generate_key()
        with open(self.get_path('public_key'), 'w') as f:
            f.write(self.public_key_str)
        with open(self.get_path('master_key'), 'w') as f:
            f.write(self.storage_master_key)

        self.is_registered = True

    def exists(self):
        return os.path.isfile(self.get_path('public_key'))

    def validate(self, data, signature_b64):
        if not self.is_registered or not self.public_key_str:
            return False
        signature = base64.b64decode(signature_b64)
        contract_hash = sha256(data)
        public_key = RSA.importKey(self.public_key_str)
        verifier = PKCS1_PSS.new(public_key)
        return verifier.verify(contract_hash, signature)

    def master_encrypt(self, data):
        master_crypter = Fernet(self.storage_master_key)
        return master_crypter.encrypt(data)

    def master_decrypt(self, data):
        master_crypter = Fernet(self.storage_master_key)
        return master_crypter.decrypt(data)

    def get_path(self, path):
        return os.path.join(self.storage_path, path)

    def destroy_storage(self):
        master_key_path = self.get_path('master_key')

        # Secure delete the master key, so the storage will be unreachable
        subprocess.check_call(['srm', '-r', master_key_path])

        # Mark the storage as garbage by adding underscore
        storage_path = os.path.join(settings.DATA_DIR, self.fingerprint)
        new_storage_path = os.path.join(settings.DATA_DIR, '_%s' % self.fingerprint)
        os.rename(storage_path, new_storage_path)


class FileManager(object):
    def __init__(self, storage):
        self.storage = storage

    def new_file(self):
        file_address = uuid.uuid4().hex

        file_key = Fernet.generate_key()
        file_crypter = Fernet(file_key)

        with open(self.storage.get_path(file_address), 'w') as f:
            f.write(file_crypter.encrypt(''))

        with open(self.storage.get_path('%s.key' % file_address), 'w') as f:
            f.write(self.storage.master_encrypt(file_key))

        return file_address

    def set_file(self, file_address, container):
        with open(self.storage.get_path('%s.key' % file_address), 'r') as f:
            file_key = self.storage.master_decrypt(f.read())

        with open(self.storage.get_path(file_address), 'w') as f:
            file_crypter = Fernet(file_key)
            f.write(file_crypter.encrypt(container))

    def get_file(self, file_address):
        with open(self.storage.get_path('%s.key' % file_address), 'r') as f:
            file_key = self.storage.master_decrypt(f.read())
        file_crypter = Fernet(file_key)

        with open(self.storage.get_path(file_address), 'r') as f:
            return file_crypter.decrypt(f.read())

    def destroy_file(self, file_address):
        key_path = self.storage.get_path('%s.key' % file_address)
        file_path = self.storage.get_path(file_address)

        if os.path.exists(key_path):
            # Secure delete the file key, so the file will be unreachable
            subprocess.check_call(['srm', '-r', key_path])

        if os.path.exists(file_path):
            # Mark the file as garbage by adding underscore
            new_file_path = self.storage.get_path('_%s' % file_address)
            os.rename(file_path, new_file_path)


class StorageMeta(object):
    def __init__(self, storage):
        self.storage = storage
        self.storage_meta_path = os.path.join(
            self.storage.storage_path, 'storage_meta')

    def set_storage_meta(self, data):
        with open(self.storage_meta_path, 'w+') as f:
            f.write(self.storage.master_encrypt(data))

    def get_storage_meta(self):
        with open(self.storage_meta_path, 'r') as f:
            return self.storage.master_decrypt(f.read())


def init_data_dir():
    if not os.path.exists(settings.DATA_DIR):
        os.makedirs(settings.DATA_DIR)
