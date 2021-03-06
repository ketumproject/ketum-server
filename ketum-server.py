from flask import Flask, jsonify, request

from ketumserverlib import KetumServerError, RegistrationContract, Storage, init_data_dir, AuthContract

app = Flask(__name__)


@app.errorhandler(KetumServerError)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/get-registration-contract')
def get_registration_contract():
    contract_obj = RegistrationContract()

    return jsonify({
        'status': 'OK',
        'contract': contract_obj.contract,
    })


@app.route('/get-auth-contract', methods=['POST'])
def get_auth_contract():
    contract_obj = AuthContract(request.form['fingerprint'])

    return jsonify({
        'status': 'OK',
        'contract': contract_obj.contract,
    })


@app.route('/login', methods=['POST'])
def login():
    fingerprint, contract, signature = request.form['auth'].split(':')
    try:
        contract_obj = AuthContract(fingerprint, contract)
        storage = contract_obj.validate(signature)
        if storage:
            storage_meta = storage.storage_meta.get_storage_meta()
            return jsonify({
                'status': 'OK',
                'storage_meta': storage_meta,
            })
    except KetumServerError:
        return jsonify({
            'status': 'FAIL',
            'message': 'Login failed',
        })


@app.route('/register', methods=['POST'])
def register():
    contract_obj = RegistrationContract(request.form['contract'])
    contract_obj.validate(request.form['public_key_str'], request.form['sign'])

    storage = Storage(public_key_str=request.form['public_key_str'])

    storage.register()

    return jsonify({
        'status': 'OK',
    })


@app.route('/new-file', methods=['POST'])
def new_file():
    fingerprint, contract, signature = request.form['auth'].split(':')
    contract_obj = AuthContract(fingerprint, contract)
    storage = contract_obj.validate(signature)

    address = storage.file_manager.new_file()

    return jsonify({
        'status': 'OK',
        'address': address,
    })


@app.route('/set-file', methods=['POST'])
def set_file():
    fingerprint, contract, signature = request.form['auth'].split(':')
    contract_obj = AuthContract(fingerprint, contract)
    storage = contract_obj.validate(signature)

    storage.file_manager.set_file(request.form['file_address'], request.form['container'].encode())

    return jsonify({
        'status': 'OK',
    })


@app.route('/get-file', methods=['POST'])
def get_file():
    fingerprint, contract, signature = request.form['auth'].split(':')
    contract_obj = AuthContract(fingerprint, contract)
    storage = contract_obj.validate(signature)

    container = storage.file_manager.get_file(request.form['file_address'])

    return jsonify({
        'status': 'OK',
        'container': container,
    })


@app.route('/destroy-file', methods=['POST'])
def destroy_file():
    fingerprint, contract, signature = request.form['auth'].split(':')
    contract_obj = AuthContract(fingerprint, contract)
    storage = contract_obj.validate(signature)

    file_addresses = request.form['file_addresses'].split(',')

    for file_address in file_addresses:
        file_address = file_address.strip()
        storage.file_manager.destroy_file(file_address)

    return jsonify({
        'status': 'OK',
    })


@app.route('/destroy-storage', methods=['POST'])
def destroy_storage():
    fingerprint, contract, signature = request.form['auth'].split(':')
    contract_obj = AuthContract(fingerprint, contract)
    storage = contract_obj.validate(signature)

    storage.destroy_storage()

    return jsonify({
        'status': 'OK',
    })


@app.route('/set-storage-meta', methods=['POST'])
def set_storage_meta():
    fingerprint, contract, signature = request.form['auth'].split(':')
    contract_obj = AuthContract(fingerprint, contract)
    storage = contract_obj.validate(signature)

    storage.storage_meta.set_storage_meta(request.form['data'].encode())

    return jsonify({
        'status': 'OK',
    })


if __name__ == '__main__':
    init_data_dir()
    app.run(debug=True)
