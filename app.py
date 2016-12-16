from flask import Flask
from flask import request
from flask import abort
from suds.client import Client
import json
import binascii
import dateutil.parser
from hashlib import sha1
from datetime import tzinfo, timedelta, datetime

app = Flask(__name__)

IPCONTROL_LOGIN = 'user'
IPCONTROL_PASSWORD = 'password'
SCALR_SIGNING_KEY = 'scalr signing key'

import_url = 'http://server-diamondip/inc-ws/services/Imports?wsdl'
delete_url = 'http://server-diamondip/inc-ws/services/Deletes?wsdl'

@app.route('/addDevice/', methods=['POST'])
def handle_addDev():
    try:
        if not validateRequest(request):
            abort(403)
        data = request.get_json(force=True)
        client = Client(import_url, username=IPCONTROL_LOGIN, password=IPCONTROL_PASSWORD)
        device = client.factory.create('WSDevice')
        device.addressType = 'Reserved'
        device.hostname = data['SCALR_EVENT_SERVER_HOSTNAME']
        device.ipAddress = data['SCALR_EVENT_INTERNAL_IP']
        """device = {
            'addressType' : 'Reserved',
            'hostname' : data['SCALR_EVENT_SERVER_HOSTNAME'],
            'ipAddress': data['SCALR_EVENT_INTERNAL_IP']
        }"""
        client.service.importDevice(device)
        return ""
    except Exception as e:
        print(e)
        traceback.print_exc()
        abort(401)

@app.route('/delDevice/', methods=['POST'])
def handle_delDev():
    try:
        if not validateRequest(request):
            abort(403)
        data = request.get_json(force=True)
        client = Client(delete_url, username=IPCONTROL_LOGIN, password=IPCONTROL_PASSWORD)
        device = client.factory.create('WSDevice')
        device.ipAddress = data['SCALR_EVENT_INTERNAL_IP']
        """device = {
            'ipAddress': data['SCALR_EVENT_INTERNAL_IP']
        }"""
        client.service.deleteDevice(device)
        return ""
    except Exception as e:
        print(e)
        traceback.print_exc()
        abort(401)

def validateRequest(request):
    if not 'X-Signature' in request.headers or not 'Date' in request.headers:
        return False
    date = request.headers['Date']
    body = request.data
    expected_signature = binascii.hexlify(hmac.new(SCALR_SIGNING_KEY, body + date, sha1).digest())
    if expected_signature != request.headers['X-Signature']:
        return False
    date = dateutil.parser.parse(date)
    now = datetime.now(pytz.utc)
    delta = abs((now - date).total_seconds())
    return delta < 300

if __name__=='__main__':
    app.run(debug=False, host='0.0.0.0')