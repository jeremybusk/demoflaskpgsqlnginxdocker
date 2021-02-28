import base64
import datetime
import enum
# from flask_login import LoginManager, UserMixin, login_user, logout_user, \A
# current_user
from flask_login import LoginManager, UserMixin
from flask_migrate import Migrate
from flask_sessionstore import Session
from flask_sqlalchemy import SQLAlchemy
import onetimepass
import os
from project import app
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy(app)
app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_TYPE'] = 'sqlalchemy'
db_session = Session(app)
db_session.app.session_interface.db.create_all()

migrate = Migrate(app, db)

lm = LoginManager(app)


class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), index=True)
    org_id = db.Column(db.Integer, db.ForeignKey('orgs.id'))
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(128), index=True)
    phone = db.Column(db.String(20), index=True)
    phone_has_sms = db.Column(db.Boolean(), default=False)
    recovery_email = db.Column(db.String(128))
    recovery_mobile_phone = db.Column(db.String(20), index=True)
    reset_token = db.Column(db.String(128))
    reset_token_ts = db.Column(db.DateTime)
    status = db.Column(db.String(1))
    email_to_sms = db.Column(db.String(128))
    failed = db.Column(db.String(128))
    otp_secret = db.Column(db.String(64))
    otp_enabled = db.Column(db.Boolean(), default=False)
    note = db.Column(db.String(256))
    ts_created = db.Column(db.DateTime, default=datetime.datetime.now)
    ts_updated = db.Column(db.DateTime, onupdate=datetime.datetime.now)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            random_str = os.getrandom(32, os.GRND_NONBLOCK)
            self.otp_secret = base64.b32encode(random_str).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        s = "otpauth://totp/DemoPortal:{0}?secret={1}&issuer=DemoPortal"
        return s.format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class Auth(db.Model):
    """Licenses model."""
    __tablename__ = 'auth'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    failed_login_count_without_success = db.Column(db.Integer)
    last_successful_login_timestamp = db.Column(db.DateTime,
                                                default=datetime.datetime.now)
    last_failed_login_timestamp = db.Column(db.DateTime,
                                            default=datetime.datetime.now)


class License(db.Model):
    """Licenses model."""
    __tablename__ = 'licenses'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    uuid = db.Column(db.String(128))
    token = db.Column(db.String(128))
    private_key = db.Column(db.String(128))
    public_key = db.Column(db.String(128))
    expiration_date = db.Column(db.DateTime)


class KeyCipher(enum.Enum):
    ed25519 = 1
    rsa = 2


class KeyFormat(enum.Enum):
    openssh = 1
    pem = 2
    pkcs12 = 3


class Key(db.Model):
    """Private/Pubilc Keys model."""
    __tablename__ = 'key'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    private_key = db.Column(db.String())
    public_key = db.Column(db.String())
    key_cipher = db.Column(db.Enum(KeyCipher))
    key_format = db.Column(db.Enum(KeyFormat))
    add_to_authorized_keys = db.Column(db.Boolean(), default=False)
    note = db.Column(db.String(256), default='')


class AccessToken(db.Model):
    """Licenses model."""
    __tablename__ = 'access_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    org_id = db.Column(db.Integer, db.ForeignKey('orgs.id'))
    access_token = db.Column(db.String(128))
    note = db.Column(db.String(128))


class Api(db.Model):
    """Service API model."""
    __tablename__ = 'apis'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    display_name = db.Column(db.String(128))
    desc_text = db.Column(db.String(128))
    url = db.Column(db.String(128), unique=True)
    version = db.Column(db.String(16))
    note = db.Column(db.String(128))


class UserApi(db.Model):
    """Service API model."""
    __tablename__ = 'user_apis'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    api_id = db.Column(db.Integer, db.ForeignKey('apis.id'), nullable=False)
    monthly_requests = db.Column(db.Integer, default=0)
    total_requests = db.Column(db.Integer, default=0)
    note = db.Column(db.String(128))


class Org(db.Model):
    """Orgs model."""
    __tablename__ = 'orgs'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    short_name = db.Column(db.String(128))
    note = db.Column(db.String(256))
    ts_created = db.Column(db.DateTime, default=datetime.datetime.now)
    ts_updated = db.Column(db.DateTime, onupdate=datetime.datetime.now)


class Product(db.Model):
    """Products model."""
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    short_name = db.Column(db.String(128))
    note = db.Column(db.String(256))
    license_id = db.Column(db.Integer, index=True)
    ts_created = db.Column(db.DateTime, default=datetime.datetime.now)
    ts_updated = db.Column(db.DateTime, onupdate=datetime.datetime.now)


class ContainerTypes(enum.Enum):
    lxd = 1
    docker = 2


class Container(db.Model):
    """Container model."""
    __tablename__ = 'container'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    org_id = db.Column(db.Integer, db.ForeignKey('orgs.id'))
    type = db.Column(db.Enum(ContainerTypes))
    name = db.Column(db.String(128))
    short_name = db.Column(db.String(128))
    created = db.Column(db.DateTime, default=datetime.datetime.now)
    deleted = db.Column(db.DateTime, default=datetime.datetime.now)
    status = db.Column(db.Integer)
    note = db.Column(db.String(256), default='')
    license_id = db.Column(db.Integer, index=True)
    ts_created = db.Column(db.DateTime, default=datetime.datetime.now)
    ts_updated = db.Column(db.DateTime, onupdate=datetime.datetime.now)


class AppName(enum.Enum):
    demoapp1 = 1


class AppProtocol(enum.Enum):
    ssh = 1
    http = 2
    https = 3


class TransportProtocol(enum.Enum):
    tcp = 1
    udp = 2


class ContainerPortMap(db.Model):
    """Container model."""
    __tablename__ = 'container_port_map'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'))
    ipv4_address = db.Column(db.String(128))
    ipv6_address = db.Column(db.String(128))
    transport_protocol = db.Column(db.Enum(TransportProtocol))
    proxy_port = db.Column(db.Integer)
    container_port = db.Column(db.Integer)
    app_protocol = db.Column(db.Enum(AppProtocol))
    app_name = db.Column(db.Enum(AppName))
    created = db.Column(db.DateTime, default=datetime.datetime.now)
    deleted = db.Column(db.DateTime, default=datetime.datetime.now)
    status = db.Column(db.Integer)
    note = db.Column(db.String(255))


class TaskQueueClient(db.Model):
    """Task Queue Client Model."""
    __tablename__ = 'task_queue_client'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    ips = db.Column(db.String(128))
    token = db.Column(db.String(128))
    note = db.Column(db.String(256))


class ProvClient(db.Model):
    """Provision(Prov) Runner Client Model."""
    __tablename__ = 'prov_client'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    ips = db.Column(db.String(128))
    token = db.Column(db.String(128))
    note = db.Column(db.String(256))


class TaskQueue(db.Model):
    """Task Queue Model."""
    __tablename__ = 'task_queue'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    task_queue_client_id = db.Column(db.Integer,
                                     db.ForeignKey('task_queue_client.id'))
    cmd = db.Column(db.JSON)
    completed = db.Column(db.Boolean(), nullable=False, default=False)
    ts_created = db.Column(db.DateTime(), default=datetime.datetime.utcnow())
    ts_updated = db.Column(db.DateTime(), onupdate=datetime.datetime.utcnow())


class SshKey(db.Model):
    """SSH Key Model."""
    __tablename__ = 'ssh_key'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    private_key = db.Column(db.String(128))
    public_key = db.Column(db.String(128))
    key_format = db.Column(db.String(32))
    key_cipher = db.Column(db.String(32))
    add_to_authorized_keys = db.Column(db.Boolean(), default=False)
    note = db.Column(db.String(256), default='')


class ApiLog(db.Model):
    """Products model."""
    __tablename__ = 'api_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    name = db.Column(db.String(128))
    ts_created = db.Column(db.DateTime, default=datetime.datetime.now)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
