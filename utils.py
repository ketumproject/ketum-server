from Crypto.Hash import SHA256


def sha256(data):
    shahash = SHA256.new()
    shahash.update(data)
    return shahash


def sha256hex(data):
    return sha256(data).hexdigest()
