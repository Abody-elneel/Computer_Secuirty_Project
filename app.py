from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import os
import json
from io import BytesIO
from datetime import datetime

# ==================== IMPORTS FROM ALGORITHMS ====================
from algorithms.des import DES
from algorithms.sdes import SDES
from algorithms.rsa import RSA
from algorithms.diffie_hellman import DiffieHellman
from algorithms.hash_algo import HashAlgorithm
from algorithms.dss import DSS

# ==================== FLASK APP ====================

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize algorithms
algorithms = {
    'sdes': SDES(),
    'des': DES(),
    'rsa': RSA(),
    'dh': DiffieHellman(),
    'hash': HashAlgorithm(),
    'dss': DSS()
}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    """Generate keys for algorithm"""
    algo = request.json.get('algorithm')

    if algo == 'sdes':
        key = algorithms['sdes'].generate_key()
        return jsonify({'success': True, 'key': key})

    elif algo == 'des':
        key = algorithms['des'].generate_key()
        round_keys = algorithms['des'].list_round_keys()
        return jsonify({'success': True, 'key': key, 'round_keys': round_keys})

    elif algo == 'rsa':
        keys = algorithms['rsa'].generate_keys()
        return jsonify({'success': True, 'keys': keys})

    elif algo == 'dh':
        priv = algorithms['dh'].generate_private_key()
        pub = algorithms['dh'].compute_public_key()
        params = algorithms['dh'].get_params()
        return jsonify({'success': True, 'private_key': priv, 'public_key': pub, 'params': params})

    elif algo == 'dss':
        keys = algorithms['dss'].generate_keys()
        return jsonify({'success': True, 'keys': keys})

    return jsonify({'success': False, 'error': 'Unknown algorithm'})


@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    """Encrypt data"""
    algo = request.json.get('algorithm')
    plaintext = request.json.get('plaintext', '')

    try:
        if algo == 'sdes':
            ciphertext = algorithms['sdes'].encrypt(plaintext)
        elif algo == 'des':
            ciphertext = algorithms['des'].encrypt(plaintext)
        elif algo == 'rsa':
            ciphertext = algorithms['rsa'].encrypt(plaintext)
        else:
            return jsonify({'success': False, 'error': 'Algorithm does not support encryption'})

        return jsonify({'success': True, 'ciphertext': str(ciphertext)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    """Decrypt data"""
    algo = request.json.get('algorithm')
    ciphertext = request.json.get('ciphertext', '')

    try:
        if algo == 'sdes':
            plaintext = algorithms['sdes'].decrypt(ciphertext)
        elif algo == 'des':
            plaintext = algorithms['des'].decrypt(ciphertext)
        elif algo == 'rsa':
            plaintext = algorithms['rsa'].decrypt(ciphertext)
        else:
            return jsonify({'success': False, 'error': 'Algorithm does not support decryption'})

        return jsonify({'success': True, 'plaintext': str(plaintext)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/hash', methods=['POST'])
def hash_data():
    """Hash data"""
    algo = request.json.get('algorithm')
    data = request.json.get('data', '')

    try:
        if algo == 'md5':
            result = HashAlgorithm.md5(data)
        elif algo == 'sha1':
            result = HashAlgorithm.sha1(data)
        else:
            return jsonify({'success': False, 'error': 'Unknown hash algorithm'})

        return jsonify({'success': True, 'hash': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/sign', methods=['POST'])
def sign():
    """Sign message"""
    message = request.json.get('message', '')

    try:
        signature = algorithms['dss'].sign(message)
        return jsonify({'success': True, 'signature': str(signature)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/verify', methods=['POST'])
def verify():
    """Verify signature"""
    message = request.json.get('message', '')
    signature = request.json.get('signature', '')

    try:
        is_valid = algorithms['dss'].verify(message, int(signature))
        return jsonify({'success': True, 'valid': is_valid})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/upload-encrypt', methods=['POST'])
def upload_encrypt():
    """Upload and encrypt file"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'})

    file = request.files['file']
    algo = request.form.get('algorithm', 'des')

    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})

    try:
        content = file.read().decode('utf-8')

        if algo == 'hybrid':
            # Hybrid Encryption: DES + RSA
            # Step 1: Generate RSA keys if not already generated
            if not algorithms['rsa'].e:
                algorithms['rsa'].generate_keys()

            # Step 2: Generate random DES key
            des_key = algorithms['des'].generate_key()

            # Step 3: Encrypt file with DES
            encrypted_file = algorithms['des'].encrypt(content)

            # Step 4: Encrypt DES key with RSA
            encrypted_key = algorithms['rsa'].encrypt(int(des_key[:16], 2))  # Use first 16 bits

            # Step 5: Save both to file
            timestamp = str(datetime.now().timestamp()).replace('.', '')
            filename = secure_filename(f"hybrid_{timestamp}.json")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            hybrid_data = {
                'encrypted_file': encrypted_file,
                'encrypted_key': str(encrypted_key),
                'des_key': des_key,
                'rsa_n': algorithms['rsa'].n,
                'rsa_e': algorithms['rsa'].e,
                'rsa_d': algorithms['rsa'].d
            }

            with open(filepath, 'w') as f:
                json.dump(hybrid_data, f, indent=2)

            return jsonify({
                'success': True,
                'filename': filename,
                'message': 'File encrypted with Hybrid (DES+RSA)',
                'des_key': des_key,
                'encrypted_key': str(encrypted_key)
            })

        elif algo == 'des':
            encrypted = algorithms['des'].encrypt(content)
        else:
            encrypted = algorithms['sdes'].encrypt(content)

        filename = secure_filename(f"encrypted_{datetime.now().timestamp()}.txt")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        with open(filepath, 'w') as f:
            f.write(encrypted)

        return jsonify({'success': True, 'filename': filename, 'message': 'File encrypted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/download-decrypt/<filename>', methods=['GET'])
def download_decrypt(filename):
    """Download and decrypt file"""
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))

        if filename.startswith('hybrid_'):
            # Hybrid decryption
            with open(filepath, 'r') as f:
                hybrid_data = json.load(f)

            # Step 1: Decrypt DES key with RSA
            algorithms['rsa'].n = hybrid_data['rsa_n']
            algorithms['rsa'].e = hybrid_data['rsa_e']
            algorithms['rsa'].d = hybrid_data['rsa_d']

            encrypted_key_int = int(hybrid_data['encrypted_key'])
            decrypted_key_int = pow(encrypted_key_int, algorithms['rsa'].d, algorithms['rsa'].n)
            des_key = format(decrypted_key_int, '016b')

            # Step 2: Restore DES key
            algorithms['des'].key = hybrid_data['des_key']

            # Step 3: Decrypt file with DES
            encrypted_file = hybrid_data['encrypted_file']
            decrypted = algorithms['des'].decrypt(encrypted_file)
        else:
            # Standard decryption
            with open(filepath, 'r') as f:
                encrypted_content = f.read()

            decrypted = algorithms['des'].decrypt(encrypted_content)

        return send_file(
            BytesIO(decrypted.encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name='decrypted.txt'
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


if __name__ == '__main__':
    app.run(debug=True)