# Derived from SEED Labs "Hash Length Extension Attack Lab" (c) Wenliang Du, CC BY-NC-SA 4.0
# Modifications for CyberRangeCZ: per-uid download ACL, /padcheck checker, /v2 HMAC endpoint.
from flask import Blueprint, render_template, request, current_app as app
import os
import hashlib
import hmac
import struct
import urllib.parse

bp = Blueprint('lab', __name__)
INVALID_KEY = '-1'


def raw_args():
    query = request.query_string.decode('utf-8', 'surrogateescape')
    if '%' in query:
        query = urllib.parse.unquote(query, errors='surrogateescape')
    args = {}
    for pair in query.split('&'):
        if '=' not in pair:
            continue
        key, value = pair.split('=', 1)
        args.setdefault(key, value)
    return args


def get_command():
    return raw_args().get('lstcmd', '')


def common_checks():
    uid = request.args.get('uid', default=None)
    if not uid:
        return None, 'UID argument not found. Aborting.'
    if not request.args.get('myname', default=''):
        return None, 'Please include the "myname" argument in the request'
    if not get_command() or not request.args.get('mac', default=''):
        return None, 'Please specify a command and its MAC'
    key = find_key(uid)
    if key == INVALID_KEY:
        return None, 'No key found for this user ' + uid
    return key, None


def build_message(my_name, uid, cmd, download):
    download_message = '' if not download else '&download=' + download
    return 'myname={}&uid={}&lstcmd='.format(my_name, uid) + cmd + download_message


def serve(valid, uid, cmd, download):
    if not valid:
        return render_template('index.html', valid=False)
    files = list_files() if cmd == '1' else []
    content = read_file(uid, download) if download else ''
    return render_template('index.html', valid=True, files=files, content=content)


@bp.route('/')
def main():
    key, err = common_checks()
    if err:
        return err
    uid = request.args.get('uid')
    my_name = request.args.get('myname')
    download = request.args.get('download', default='', type=str)
    mac = request.args.get('mac')
    cmd = get_command()
    app.logger.info('v1 request uid=%s myname=%s', uid, my_name)
    payload = key + ':' + build_message(my_name, uid, cmd, download)
    real_mac = hashlib.sha256(payload.encode('utf-8', 'surrogateescape')).hexdigest()
    return serve(mac == real_mac, uid, cmd, download)


@bp.route('/v2/')
def main_hmac():
    """Fixed server: MAC = HMAC-SHA256(key, message)."""
    key, err = common_checks()
    if err:
        return err
    uid = request.args.get('uid')
    my_name = request.args.get('myname')
    download = request.args.get('download', default='', type=str)
    mac = request.args.get('mac')
    cmd = get_command()
    app.logger.info('v2 request uid=%s myname=%s', uid, my_name)
    message = build_message(my_name, uid, cmd, download)
    real_mac = hmac.new(bytearray(key.encode('utf-8')),
                        msg=message.encode('utf-8', 'surrogateescape'),
                        digestmod=hashlib.sha256).hexdigest()
    return serve(hmac.compare_digest(mac, real_mac), uid, cmd, download)


@bp.route('/padcheck')
def padcheck():
    """Task 2 checker: expects SHA-256 padding of <key>:myname=<name>&uid=<uid>&lstcmd=1"""
    uid = request.args.get('uid', default='')
    my_name = request.args.get('myname', default='')
    if uid != app.config['STUDENT_UID']:
        return 'Use your own uid for this check.'
    if not my_name:
        return 'Please include the "myname" argument in the request'
    padding = raw_args().get('padding')
    if padding is None:
        return 'Please include the "padding" argument (URL-encoded, e.g. %80%00...)'
    key = find_key(uid)
    msg = '{}:myname={}&uid={}&lstcmd=1'.format(key, my_name, uid).encode('utf-8')
    n = len(msg)
    expected = b'\x80' + b'\x00' * ((55 - n) % 64) + struct.pack('>Q', n * 8)
    got = padding.encode('utf-8', 'surrogateescape')
    if got == expected:
        return 'Correct padding ({} bytes). Flag: {}'.format(len(expected), app.config['FLAG_PADDING'])
    return 'Wrong padding: received {} bytes, expected {} bytes.'.format(len(got), len(expected))


def find_key(uid):
    path = os.path.join(app.config['LAB_HOME_DIR'], app.config['KEY_FILE_NAME'])
    if not os.path.exists(path):
        return INVALID_KEY
    with open(path) as f:
        for line in f:
            line = line.strip()
            if app.config['KEY_FILE_DELIMITER'] not in line:
                continue
            _uid, _key = line.split(app.config['KEY_FILE_DELIMITER'], 1)
            if _uid == uid:
                return _key
    return INVALID_KEY


def list_files():
    return sorted(os.listdir(app.config['LAB_HOME_DIR']))


def read_file(uid, file):
    if file not in app.config['DOWNLOAD_ACL'].get(uid, []):
        return ['Access Denied: uid {} is not allowed to download {}'.format(uid, file)]
    path = os.path.join(app.config['LAB_HOME_DIR'], file)
    if not path_access_control(path) or not os.path.exists(path):
        return ['No Such File [{}]'.format(file)]
    with open(path) as f:
        return [line.strip() for line in f]


def path_access_control(path):
    normalized = os.path.normpath(path)
    return os.path.commonprefix([normalized, app.config['LAB_HOME_DIR']]) == app.config['LAB_HOME_DIR']
