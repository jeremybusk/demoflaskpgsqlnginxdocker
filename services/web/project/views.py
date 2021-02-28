import base64
import json
import jwt
import logging
from systemd.journal import JournalHandler
import time
from io import BytesIO
from flask import render_template, redirect, url_for, flash, session, \
    abort, send_from_directory, request, jsonify
from flask_bootstrap import Bootstrap
# from flask_login import LoginManager, UserMixin, login_user, logout_user, \
from flask_login import login_required, login_user, logout_user, \
    current_user
from flask_wtf import FlaskForm
import os
import psycopg2
import pyqrcode
from demoportal import app
from demoportal.models import AccessToken, db, License, User, UserApi, \
    Container, Key
import redis
from sqlalchemy.sql import text  # bind params - raw sql prevent injection.
import demoportal.utils as utils
import uuid
from werkzeug.security import generate_password_hash
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp

pgconn = psycopg2.connect(host=app.config['DB_HOST'],
                          dbname=app.config['DB_NAME'],
                          user=app.config['DB_USER'],
                          password=app.config['DB_PASS'])


def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ))


bootstrap = Bootstrap(app)


@app.route("/health")
def health():
    return 'health: ok'


@app.route('/api/jtester1', methods=['GET', 'POST'])
def api_jtester1():
    msg = "jtester1 This is an auth test from jtester."
    log_msg(msg)
    return jsonify({'msg': msg}), 200
    # return jsonify({'msg': msg}), 403
    # return jsonify({'msg': msg}), 303
    # return jsonify({'msg': msg}), 401


@app.route('/api/jtester2', methods=['GET', 'POST'])
def api_jtester2():
    msg = "jtester2 This is a test result page."
    log_msg(msg)
    return jsonify({'msg': msg}), 200


@app.route('/api/get_node_urls', methods=['GET', 'POST'])
def get_service_urls():
    cur = pgconn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    sql = "SELECT name, url FROM apis"
    cur.execute(sql)
    return jsonify(cur.fetchall())
    # non-db way
    # return jsonify(uvooapp='https://uvoo.io',
    #                ethnode='https://api.uvoo.io/ethereum/',
    #                btcnode='https://api.uvoo.io/bitcoin/')


def create_jwt(user_id):
    # user_apis = (db.session.query(UserApi.api_id)
    #              .filter_by(user_id=user_id)
    #              .all())
    cur = pgconn.cursor()
    sql = "SELECT api_id FROM user_apis WHERE user_id = %s"
    cur.execute(sql, (user_id,))
    rows = cur.fetchall()
    aud = []
    for row in rows:
        aud.append(str(row[0]))
    iss = 'https://portal.uvoo.io'
    sub = user_id
    # aud = ['demoapp1', 'uvooapp', '3']  # project id, uuid, map table id.
    aud = aud  # This is list of user's api_ids.
    iat = int(time.time())
    nbf = int(time.time())
    exp = int(time.time()) + 315360000  # expires in 24*365*10 or ~ 10 yrs
    jti = str(uuid.uuid1())
    # token_type  # access/refresh, email, refresh_token 'token_type': 'bearer'
    jwt_payload = {'iss': iss,
                   'sub': sub,
                   'aud': aud,
                   'iat': iat,
                   'nbf': nbf,
                   'exp': exp,
                   'jti': jti}

    encoded_jwt = jwt.encode(
        jwt_payload,
        app.config['JWT_PRIVATE_KEY'],
        algorithm=app.config['JWT_ALGORITHM']).decode('utf-8')

    # https://tools.ietf.org/html/rfc6749#section-4.4
    payload = {"access_token": encoded_jwt,
               "token_type": "bearer"}
    # ??? "refresh_token": "rtoken" } "expires_in": 84600 is in token
    return payload


def validate_jwt(jwt_bytes, request_uri=''):
    options = {
        'verify_signature': True,
        'verify_exp': True,
        'verify_nbf': True,
        'verify_iat': True,
        'verify_aud': False,  # ??? had audience issues earlier so disabled
        'verify_iss': True,
        'require_exp': False,
        'require_iat': False,
        'require_nbf': False
    }
    audience = ['1', '2']  # This currently is ethereum & bitcoin apis.
    try:
        r = jwt.decode(jwt_bytes,
                       app.config['JWT_PUBLIC_KEY'],
                       audience=audience,
                       algorithm=app.config['JWT_ALGORITHM'],
                       options=options)
        msg = f"S: JWT verify success! + {r}"
        try:
            user_id = r['sub']
            if 'ethereum' in request_uri:
                api_id = 1
            elif 'bitcoin' in request_uri:
                api_id = 2
            else:
                api_id = 0
            cmd = ("UPDATE user_apis "
                   "set monthly_requests = monthly_requests + 1 "
                   "WHERE user_id=:user_id and api_id=:api_id")
            t = text(cmd)
            db.engine.execute(t, user_id=user_id, api_id=api_id)
        except Exception as e:
            msg = "E: Issue updating api request counter." + repr(e)
            return 0, msg
        return 1, r
    except Exception as e:
        msg = "E: JWT verify failure!  " + repr(e)
        return 0, msg


@app.route('/api/auth_verify_show_info', methods=['GET', 'POST'])
def auth_verify_return_show_info():
    jwt_bearer = request.headers.get('Authorization')
    jwt_bytes = jwt_bearer.split(" ")[1].encode('utf-8')
    r = validate_jwt(jwt_bytes)
    msg = r[1]
    log_msg(msg)
    return jsonify({'msg': msg})


@app.route('/api/auth', methods=['GET', 'POST'])
def get_jwt():
    try:
        username = request.json['username']
        password = request.json['password']
    except Exception as e:
        return jsonify(msg="Invalid request."), 400
        # return jsonify(msg=repr(e))  # A little insecure.
    user = User.query.filter_by(username=username).first()
    if user is None or not user.verify_password(password):
        return jsonify(msg="Invalid authentication."), 401
    else:
        payload = create_jwt(user.id)
        return jsonify(payload)


# This route is for external authorization from reverse proxies like nginx.
# https://docs.nginx.com/nginx/admin-guide/security-controls/
# configuring-subrequest-authentication/
# 2xx allows access. 401 or 403 access is denied. Anything else, 500.
@app.route('/api/auth_verify', methods=['GET', 'POST'])
def jwt_verify():
    try:
        jwt_bearer = request.headers.get('Authorization')
        jwt_bytes = jwt_bearer.split(" ")[1].encode('utf-8')
        request_uri = request.headers.get('X-Original-URI')
        r = validate_jwt(jwt_bytes, request_uri)
        msg = r[1]
        log_msg(msg)
        if r[0]:
            return jsonify({'msg': msg}), 200
        else:
            return jsonify({'msg': msg}), 401
    except Exception as e:
        return jsonify({'msg': e}), 400


@app.route('/api/user_api_request_inc', methods=['GET', 'POST'])
def user_api_request_inc():
    # Increment user_apis requests counter on use from reverse proxy.
    try:
        client_token = request.json['client_token']
        if client_token != app.config['CLIENT_TOKEN']:
            return jsonify(msg="Invalid auth."), 401
        user_id = request.json['user_id']
        api_id = request.json['api_id']
    except Exception as e:
        return jsonify(msg="Invalid request."), 400
    try:
        cmd = ("UPDATE user_apis set monthly_requests = monthly_requests + 1 "
               "WHERE user_id=:user_id and api_id=:api_id")
        t = text(cmd)
        result = db.engine.execute(t, user_id=user_id, api_id=api_id)
        result = vars(result)
        return jsonify(result=f"{result}", rcode=200, msg="Success."), 200
    except Exception as e:
        return jsonify(msg="E: DB Commit fail."), 500


def log_msg(msg):
    log = logging.getLogger('portalwall')
    log.addHandler(JournalHandler())
    log.setLevel(logging.INFO)
    log.info(msg)


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/accesstokens', methods=['GET', 'POST'])
@login_required
def accesstokens():
    """User Access Tokens."""
    if current_user.is_authenticated:
        if request.method == 'POST':
            if request.form['submit_button'] == 'Add':
                access_token = access_token = utils.gen_random_string(32)
                if len(access_token) > 24:
                    accesstoken = AccessToken(
                        user_id=current_user.id,
                        note="",
                        access_token=access_token)
                    db.session.add(accesstoken)
                    db.session.commit()
                    flash(u'Token added.', 'success')
                else:
                    flash(u'E: Add validation error.', 'error')
            elif request.form['submit_button'] == 'Update':
                if len(request.form['l_access_token']) > 24:
                    access_token = AccessToken.query.filter_by(
                        user_id=current_user.id,
                        id=request.form['l_id']).update(
                            dict(access_token=request.form['l_access_token'],
                                 note=request.form['l_note']))
                    db.session.commit()
                    flash(u'Token updated.', 'success')
                else:
                    flash(u'E: Update validation error.', 'error')
            elif request.form['submit_button'] == 'Delete':
                AccessToken.query.filter_by(
                    user_id=current_user.id,
                    id=request.form['l_id']).delete()
                db.session.commit()
                flash(u'Token deleted.', 'success')
            else:
                flash(u'Unsupported submit.', 'error')
        r = AccessToken.query.filter_by(
            user_id=current_user.id).order_by(AccessToken.id).all()
        return render_template("accesstokens.html", accesstokens=r)
    return redirect(url_for('index'))


@app.route('/services', methods=['GET', 'POST'])
@login_required
def services():
    """APIs Dash Board View."""
    if current_user.is_authenticated:
        if request.method == 'POST':
            if request.form['submit_button'] == 'add_ethereum':
                count = (db.session.query(UserApi)
                         .filter_by(api_id=1, user_id=current_user.id)
                         .count())
                if count == 0:
                    sql = f"""INSERT INTO user_apis
                        (api_id, user_id, monthly_requests, total_requests)
                        VALUES (1, {current_user.id}, 0, 0)"""
                    result = db.engine.execute(sql)
                    flash(u'Bitcoin API Added.', 'success')

            elif request.form['submit_button'] == 'add_bitcoin':
                count = (db.session.query(UserApi)
                         .filter_by(api_id=2, user_id=current_user.id)
                         .count())
                if count == 0:
                    sql = f"""INSERT INTO user_apis
                        (api_id, user_id, monthly_requests, total_requests)
                        VALUES (2, {current_user.id}, 0, 0)"""
                    result = db.engine.execute(sql)
                    flash(u'Bitcoin API Added.', 'success')

        sql = ("SELECT apis.name, apis.url, apis.version, "
               "user_apis.monthly_requests, user_apis.total_requests "
               "FROM apis, user_apis user_apis "
               "WHERE user_apis.user_id='%s' "
               "AND apis.id = user_apis.api_id")
        result = db.engine.execute(sql, current_user.id).fetchall()
        return render_template('services.html', user_apis=result)
    return redirect(url_for('index'))


@app.route('/ethereum', methods=['GET', 'POST'])
@login_required
def ethereum():
    """Ethereum access route."""
    if current_user.is_authenticated:
        rdb = redis.Redis(host=app.config['REDIS_HOST'],
                          port=6379, db=app.config['REDIS_NAME'],
                          password=app.config['REDIS_PASS'])
        r = rdb.hget(current_user.username, 'ethereum_count')
        return render_template('ethereum.html', access_count=r.decode('utf-8'))
    return redirect(url_for('index'))


@app.route('/fail')
@login_required
def fail():
    """User fail route."""
    return render_template('fail.html')


@app.route('/favicon.png')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'logo-uvooapp-1220x400.png', mimetype='image/png')


@app.route('/licenses', methods=['GET', 'POST'])
@login_required
def licenses():
    """User licenses."""
    if current_user.is_authenticated:

        if request.method == 'POST':
            if request.form['submit_button'] == 'add_license_demoapp1':
                subq = "SELECT id FROM licenses WHERE user_id IS NULL LIMIT 1"
                sql = ("UPDATE licenses "
                       "SET user_id=%s "
                       f"WHERE id = ({subq})")
                db.engine.execute(sql, current_user.id)
                flash(u'DemoApp License Added.', 'success')

        r = License.query.filter_by(user_id=current_user.id).all()
        return render_template("licenses.html", licenses=r)
    return redirect(url_for('index'))


@app.route('/containers', methods=['GET', 'POST'])
@login_required
def containers():
    """User Containers."""
    if not current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if request.form['submit_button'] == 'create_demoapp1_container':
            # requires create extension "pgcrypto";
            sql = "select 'n-' || gen_random_uuid()"
            container_name = str(db.engine.execute(sql).fetchone()[0])
            sql = ("INSERT INTO container "
                   "(name, user_id) "
                   "VALUES (%s, %s)")
            r = db.engine.execute(sql, container_name, current_user.id)

            if r:
                flash(u'New container is being created.', 'success')

    r = Container.query.filter_by(user_id=current_user.id).all()
    return render_template("containers.html", containers=r)


@app.route('/container_ports', methods=['GET', 'POST'])
@login_required
def container_ports():
    """User Containers."""
    if not current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if request.form['submit_button'] == 'create_container_port_map':
            container_port = request.form.get('internal_port')
            container_name = request.form.get('container_name')
            q1 = ("SELECT id FROM container_port_map "
                  "WHERE container_id IS NULL LIMIT 1")
            q2 = "SELECT id FROM container WHERE name=%s"
            sql = (f"UPDATE container_port_map "
                   f"SET user_id=%s, container_id=({q2}), container_port=%s "
                   f"WHERE id=({q1})")
            r = db.engine.execute(sql,
                                  current_user.id,
                                  container_name,
                                  container_port)

            cmd = json.dumps({'container_name': container_name,
                              'container_type': 'lxd'})
            task_queue_client_id = 1  # currently client 1 handles all
            sql = ("INSERT INTO task_queue "
                   "(user_id, cmd, task_queue_client_id, completed) "
                   "VALUES (%s, %s, %s, %s)")
            r = db.engine.execute(sql,
                                  current_user.id,
                                  cmd,
                                  task_queue_client_id,
                                  'FALSE')

            if r:
                flash(u'New container port map is being created.', 'success')

    # r = ContainerPortMap.query.filter_by(user_id=current_user.id).all()
    sql = ("SELECT container.name, "
           "container_port_map.ipv4_address, "
           "transport_protocol, "
           "container_port_map.proxy_port, "
           "container_port_map.container_port "
           "FROM container, container_port_map "
           "WHERE container.id = container_port_map.container_id "
           "AND container_port_map.user_id=%s")
    r = db.engine.execute(sql, current_user.id)
    return render_template("container_ports.html", container_ports=r)


def get_prov_client_id():
    access_token = request.args.get('access_token')
    cur = pgconn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM prov_client WHERE token = %s LIMIT 1",
                (access_token,))
    row = cur.fetchone()
    return row['id']


@app.route('/prov/api/container', methods=['GET', 'POST'])
def api_provision():
    # access_token = '27c2ba2b-f060-4a14-81e4-1fe981fe695d'
    cur = pgconn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    prov_client_id = get_prov_client_id()

    if prov_client_id:
        if request.method == 'GET':
            if request.args.get('action') == 'get_uncreated':
                cur.execute("SELECT name, user_id FROM container "
                            "WHERE created IS NULL",
                            (prov_client_id,))
                return jsonify(cur.fetchall())
            if request.args.get('action') == 'get_authorized_keys':
                cur.execute("SELECT public_key FROM key "
                            "WHERE add_to_authorized_keys = TRUE "
                            "AND user_id = %s",
                            (request.args.get('user_id'),))
                return jsonify(cur.fetchall())
            if request.args.get('action') == 'get_container_proxy_port_maps':
                sql = ("SELECT container.name, "
                       "transport_protocol, "
                       "container_port_map.proxy_port, "
                       "container_port_map.container_port, "
                       "container_port_map.id as container_port_id "
                       "FROM container, container_port_map "
                       "WHERE container.id = container_port_map.container_id "
                       "AND container_port_map.created IS NULL")
                cur.execute(sql)
                return jsonify(cur.fetchall())

        if request.method == 'POST':
            if request.args.get('action') == 'update_container_created':
                container_name = request.json['container_name']
                r = cur.execute("UPDATE container "
                                "SET created = CURRENT_TIMESTAMP "
                                "WHERE name = %s", (container_name,))
                pgconn.commit()
            if request.args.get('action') == 'update_container_port_created':
                sql = ("UPDATE container_port_map "
                       "SET created = CURRENT_TIMESTAMP "
                       "WHERE id = %s")
                r = cur.execute(sql, (request.json['container_port_id'],))
                pgconn.commit()
            return jsonify(r)

    return redirect(url_for('index'))


@app.route('/keys', methods=['GET', 'POST'])
@login_required
def keys():
    """User Keys."""
    if not current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if request.form['submit_button'] == 'create_ssh_key_pair':
            sql = ('SELECT * from key '
                   'WHERE user_id = %s LIMIT 1')
            rows = db.engine.execute(sql, current_user.id).fetchall()
            # Only add ssh key if one doesn't already exist
            if len(rows) == 0:
                r = utils.create_key_pair()
                public_key = r['public_key']
                private_key = r['private_key']
                key_cipher = r['key_cipher']
                key_format = r['key_format']

                sql = ("INSERT INTO key "
                       "(user_id, private_key, public_key, key_cipher, "
                       " key_format, add_to_authorized_keys) "
                       f"VALUES (%s, %s, %s, %s, %s, %s)")
                r = db.engine.execute(sql,
                                      current_user.id, private_key,
                                      public_key, key_cipher,
                                      key_format, True)
                if r:
                    flash(u'Added public ssh key to available keys', 'success')
            else:
                    flash(u'Currently imited to only one key.', 'error')

    rows = Key.query.filter_by(user_id=current_user.id).all()
    return render_template("keys.html", keys=rows)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST' and request.form['submit_button'] == 'login':
        username = request.form.get("username")
        password = request.form.get("password")
        time_token = request.form.get("token")
        user = User.query.filter_by(username=username).first()
        if user is None or not user.verify_password(password):
            flash(u'Invalid username, password or token.', 'error')
            return redirect(url_for('login'))
        if user.otp_enabled:
            if not user.verify_totp(time_token):
                flash(u'Invalid token.', 'error')
                return redirect(url_for('login'))
        login_user(user)
        flash(u'You are now logged in!', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """User logout route."""
    logout_user()
    return redirect(url_for('index'))


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    # Note you might use flask-security but it limits flexability (2FA).
    # Trust is another issue as authentication is number one hack prevent.
    # https://github.com/mattupstate/flask-security
    """User Password Reset/Recovery via email."""
    if request.method == 'GET':
        if 'reset_token' in request.args:
            reset_token = request.args['reset_token']
            sql = ('SELECT username from users '
                   'WHERE reset_token = %s '
                   "AND reset_token_ts < (now() + '1 hour'::interval) LIMIT 1")
            username = db.engine.execute(sql, reset_token).fetchone()

            if username is not None:
                return render_template('reset_pass.html')

    if request.method == 'POST':
        if request.form['submit_button'] == 'update_password':
            reset_token = request.args['reset_token']
            password = generate_password_hash(request.form['password'])
            sql = ("UPDATE users "
                   "SET password_hash = %s "
                   "WHERE reset_token = %s")
            db.engine.execute(sql, password, reset_token)
            flash(u'Password has been updated.', 'success')
            return render_template('reset_pass.html')

        if request.form['submit_button'] == 'send_reset':
            email = request.form['email']
            sql = ('SELECT count(*) from users '
                   'WHERE username = %s OR email = %s '
                   'OR recovery_email = %s LIMIT 1')
            if (db.engine.execute(sql, email, email, email)
                    .fetchone() is not None):

                reset_token = reset_token = utils.gen_random_string(32)
                sql = ("UPDATE users "
                       "SET reset_token=%s, reset_token_ts = now() "
                       "WHERE username = %s OR email = %s "
                       "OR recovery_email = %s")
                db.engine.execute(sql, reset_token,
                                  email, email, email)
                domain = 'https://portal.uvoo.io'
                reset_url = f'{domain}/reset?reset_token={reset_token}'
                recipients = email
                subject = 'Demo Portal Password Reset'
                body = (f'Use {reset_url} to reset password.'
                        'Link will be active for 1 hour')
                utils.send_email(recipients, subject, body)

                flash('S: Email reset url link has been sent. Check email.',
                      'success')
            else:
                flash('E: Invalid email.', 'error')

    return render_template('reset_request.html')


@app.route('/reg_qrcode')
def reg_qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # Remove username from session for added security.
    del session['username']

    # Render qrcode for FreeOTP.
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    # url.svg(stream, scale=3)  # using svg instead of png
    url.png(stream, scale=4, module_color=[0, 0, 0, 128],
            background=[0xff, 0xff, 0xcc])
    return stream.getvalue(), 200, {
        # 'Content-Type': 'image/svg+xml',
        'Content-Type': 'image/png',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@login_required
@app.route('/qrcode')
def qrcode():
    user = User.query.filter_by(username=current_user.username).first()
    if user is None:
        return redirect(url_for('index'))

    # Render qrcode for FreeOTP.
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    # url.svg(stream, scale=3)  # using svg instread of png
    url.png(stream, scale=4, module_color=[0, 0, 0, 128],
            background=[0xff, 0xff, 0xcc])
    return stream.getvalue(), 200, {
        # 'Content-Type': 'image/svg+xml',
        'Content-Type': 'image/png',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if (request.method == 'POST' and
            request.form['submit_button'] == 'register'):
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user is not None:
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        user = User(username=username, password=password, otp_enabled=False)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
        # Redirect to page with 2FA QR to scan with FreeOTP or app like it.
        # session['username'] = user.username
        # return redirect(url_for('reg_two_factor_setup'))
    return render_template('register.html')


@app.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@app.route('/reg_two_factor_setup')
def reg_two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
    # Make sure the browser doesn't cache qrcode
    return render_template('reg_two_factor_setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@login_required
@app.route('/twofactorauth', methods=['GET', 'POST'])
def twofactorauth():
    if request.method == 'POST' and request.form['submit_button'] == 'update':
        random_str = os.getrandom(32, os.GRND_NONBLOCK)
        otp_secret = base64.b32encode(random_str).decode('utf-8')

        sql = ("UPDATE users "
               "SET otp_secret = %s "
               "WHERE username = %s")
        db.engine.execute(sql, otp_secret, current_user.username)
        s = u'OTP secret been updated. Capture new QRCode with camera.'
        flash(s, 'success')

    return render_template('twofactorauth.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User Profile Form Update route."""
    user = User.query.filter_by(id=current_user.id).first()
    form = UserProfileForm(obj=user)
    if request.method == 'POST' and form.validate():
        user = User.query.filter_by(id=current_user.id).first()
        user.username = request.form.get("username")
        user.recovery_email = request.form.get("recovery_email")
        user.phone = request.form.get("phone")
        if request.form.get("otp_enabled") == 'y':
            user.otp_enabled = True
        else:
            user.otp_enabled = False
        db.session.commit()
        flash(u'User profile info updated.', 'success')
        return redirect('/profile')
    return render_template('profile.html', form=form)


class RegisterForm(FlaskForm):
    """Registration form."""
    username = StringField('Email',
                           validators=[
                               DataRequired(),
                               Email(),
                               Length(4, 64)
                           ])
    regx = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\._!@#\$%\^&\*])(?=.{8,})'
    mesg = 'Requires upper/lowercase letter, number, and char like !@#$%_&.'
    password = PasswordField('Password',
                             validators=[
                                 DataRequired(),
                                 Length(12, 64),
                                 Regexp(regx, message=mesg)
                             ])

    password_again = PasswordField('Password again',
                                   validators=[
                                       DataRequired(),
                                       EqualTo('password')
                                   ])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """Login form."""
    username = StringField('Username/Email',
                           validators=[DataRequired(), Length(4, 64)])
    password = PasswordField('Password', validators=[DataRequired()])
    token = StringField('Token')  # length 6 when used
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')


class AccessTokenForm(FlaskForm):
    """Access Token Form."""
    s = "'Token String', validators=[DataRequired(), Length(15, 128)]"
    access_token = StringField(s)
    note = StringField('Note', validators=[Length(0, 128)])
    submit = SubmitField('Add', label='Add', value='Add')


class UserProfileForm(FlaskForm):
    """User Profile Form."""
    username = StringField('Username/E-mail', validators=[DataRequired(),
                           Length(5, 128)])
    recovery_email = StringField('Recovery E-mail',
                                 validators=[Length(0, 128)])
    phone = StringField('Phone Number', validators=[Length(0, 20)])
    otp_enabled = BooleanField('Two Factor Authentication(2FA) Enabled*')
    # phone_has_sms = Boolean(Phone Supports SMS',
    #     validators=[Length(5, 25)])
    # submit = SubmitField('Update', label='Update', value='update')
    submit = SubmitField('Update')
