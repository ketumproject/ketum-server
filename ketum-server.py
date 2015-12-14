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
            storage_init = storage.get_storage_init()
            return jsonify({
                'status': 'OK',
                'storage_init': storage_init,
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

    address = storage.new_file()

    return jsonify({
        'status': 'OK',
        'address': address,
    })


@app.route('/set-file', methods=['POST'])
def set_file():
    fingerprint, contract, signature = request.form['auth'].split(':')
    contract_obj = AuthContract(fingerprint, contract)
    storage = contract_obj.validate(signature)

    storage.set_file(request.form['file_address'], request.form['container'].encode())

    return jsonify({
        'status': 'OK',
    })


@app.route('/get-file', methods=['POST'])
def get_file():
    fingerprint, contract, signature = request.form['auth'].split(':')
    contract_obj = AuthContract(fingerprint, contract)
    storage = contract_obj.validate(signature)

    container = storage.get_file(request.form['file_address'])

    return jsonify({
        'status': 'OK',
        'container': container,
    })


@app.route('/set-storage-init', methods=['POST'])
def set_storage_init():
    fingerprint, contract, signature = request.form['auth'].split(':')
    contract_obj = AuthContract(fingerprint, contract)
    storage = contract_obj.validate(signature)

    storage.set_storage_init(request.form['data'].encode())

    return jsonify({
        'status': 'OK',
    })


if __name__ == '__main__':
    init_data_dir()
    app.run(debug=True)
