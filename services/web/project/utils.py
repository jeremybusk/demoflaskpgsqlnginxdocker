from cryptography.hazmat.primitives import serialization \
    as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend \
    as crypto_default_backend
from email.mime.text import MIMEText
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

import random
import string
import smtplib


def gen_random_string(chars=32, lower=False):
    s = ''.join(
        random.choice(
            string.ascii_uppercase + string.ascii_lowercase + string.digits
        ) for _ in range(chars))
    if lower:
        return s.lower()
    return s


def send_email(recipients, subject, body):
    email_username = 'smtprelayuser@uvoo.io'

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'no-reply <no-reply@uvoo.io>'
    msg['To'] = recipients
    msg = msg.as_string()

    session = smtplib.SMTP('smtp.uvoo.io', 587)
    session.ehlo()
    session.starttls()
    session.login(email_username, '$mtpRelayUser123@')
    session.sendmail(email_username, recipients, msg)
    session.quit()


def create_key_pair(key_cipher='rsa', key_format='openssh'):
    if key_cipher == 'rsa' and key_format == 'openssh':
        rsa_key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=4096
        )
        private_key = rsa_key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())
        public_key = rsa_key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH
        )

    elif key_cipher == 'rsa' and key_format == 'pem':
        rsa_key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=4096
        )
        private_key = rsa_key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())
        public_key = rsa_key.public_key().public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo
        )

    elif key_cipher == 'ec' and key_format == 'pem':
        # Ciphers: SECP384R1, SECP521R1
        ec_key = ec.generate_private_key(
            ec.SECP521R1(),
            default_backend()
        )
        private_key = ec_key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())
        public_key = ec_key.public_key().public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        s = f"Unsupported key cipher {key_cipher} and/or format {key_format}."
        print(s)
        return -1

    return {'private_key': private_key.decode('utf-8'),
            'public_key': public_key.decode('utf-8'),
            'key_cipher': key_cipher,
            'key_format': key_format}


def load_private_key(filename, file_format='pem'):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = crypto_serialization.load_pem_private_key(
        pemlines, None, default_backend())
    return private_key


def load_key(filename, key_type='private', file_format='pem'):
    with open(filename, 'rb') as f:
        key_lines = f.read()

    if key_type == 'private':
        private_key = crypto_serialization.load_pem_private_key(
            key_lines, default_backend(), password=None)
        return private_key
    elif key_type == 'public':
        public_key = crypto_serialization.load_pem_public_key(
            key_lines, default_backend())
        return public_key
    else:
        raise Exception('E: Unsupported key type.')


def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.OpenSSH
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)
