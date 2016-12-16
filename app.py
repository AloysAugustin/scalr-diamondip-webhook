from flask import Flask
from flask import request
from flask import abort
import pytz
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

@app.route("/", methods=['POST'])
def webhook_listener():
    try:
        if not validateRequest(request):
            abort(403)

        data = json.loads(request.data)
        if not 'eventName' in data or not 'data' in data:
            abort(404)

        if data['eventName'] == 'HostUp':
            return addDev(data['data'])
        elif data['eventName'] in ['HostDown', 'BeforeHostTerminate']:
            return delDev(data['data'])
    except Exception as e:
        print(e)
        traceback.print_exc()
        abort(401)

def addDev(data):
    client = Client(import_url, username=IPCONTROL_LOGIN, password=IPCONTROL_PASSWORD)
    device = client.factory.create('WSDevice')
    device.addressType = 'Static'
    device.hostname = getHostname(data)
    device.ipAddress = data['SCALR_EVENT_INTERNAL_IP']
    return client.service.importDevice(device)

def delDev(data):
    client = Client(delete_url, username=IPCONTROL_LOGIN, password=IPCONTROL_PASSWORD)
    device = client.factory.create('WSDevice')
    device.ipAddress = data['SCALR_EVENT_INTERNAL_IP']
    return client.service.deleteDevice(device)

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

def getHostname(data):
    hostname = data['SCALR_EVENT_SERVER_HOSTNAME']
    return hostname

if __name__=='__main__':
    app.run(debug=False, host='0.0.0.0')
