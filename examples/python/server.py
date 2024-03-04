from flask import Flask, request
import json
import base64
import jwt
from jwt import PyJWKClient
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
jwks_client = PyJWKClient('https://api.appfolio.com/.well-known/jwks.json')
jws = jwt.PyJWS()

@app.route('/', methods=['POST'])
def webhook():
    try:
        signature = request.headers['x-jws-signature']
        encoded_header, encoded_signature = signature.split('..')
        decoded_signature = base64.urlsafe_b64decode(encoded_signature + "===")
        encoded_payload = base64.urlsafe_b64encode(request.data).decode("utf-8")

        jws_header_json = json.loads(base64.urlsafe_b64decode(encoded_header + "===").decode("utf-8"))
        signing_key = jwks_client.get_jwk_set()[jws_header_json['kid']].key

        signing_key.verify(
            decoded_signature,
            str.encode(encoded_header + "." + encoded_payload),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size
            ),
            hashes.SHA256(),
        )

        print('Webhook received and signature verified')
        return '', 200
    except Exception as e:
        print('Failed to verify signature:', e)
        return '', 401

if __name__ == '__main__':
    app.run(port=8000)
