from flask import Flask
from flask import request
from flask import abort
import pytz
import suds
from suds.client import Client
import json
import logging
import binascii
import dateutil.parser
import hmac
from hashlib import sha1
from datetime import datetime

config_file = './config.json'

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# will be overridden if present in config_file
IPCONTROL_LOGIN = ''
IPCONTROL_PASSWORD = ''
SCALR_SIGNING_KEY = ''
DIAMONDIP_SERVER = ''
PROXY = {}

import_url = lambda: DIAMONDIP_SERVER + 'inc-ws/services/Imports?wsdl'
delete_url = lambda: DIAMONDIP_SERVER + 'inc-ws/services/Deletes?wsdl'
import_location = lambda: DIAMONDIP_SERVER + 'inc-ws/services/Imports'
delete_location = lambda: DIAMONDIP_SERVER + 'inc-ws/services/Deletes'

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
    except suds.WebFault as e:
        logging.exception('IPAM returned error')
        abort(503)
    except Exception as e:
        logging.exception('Error processing this request')
        abort(500)


def getHostname(data):
    return data['SCALR_EVENT_SERVER_HOSTNAME']

def get_ip(data):
    if data['SCALR_EVENT_INTERNAL_IP']:
        return data['SCALR_EVENT_INTERNAL_IP']
    else:
        return data['SCALR_EVENT_EXTERNAL_IP']

def getDomainName(data):
    return data['DNS_DOMAIN']

def addDev(data):
    client = Client(import_url(),
                    username=IPCONTROL_LOGIN,
                    password=IPCONTROL_PASSWORD,
                    location=import_location(),
                    timeout=10,
                    proxy=PROXY)
    device = client.factory.create('ns2:WSDevice')
    device.addressType = 'Static'
    device.deviceType = 'Static Server'
    device.hostname = getHostname(data)
    device.domainName = getDomainName(data)
    device.ipAddress = get_ip(data)
    udf = {
        'Location': 'DATACENTER',
        'Organization Unit': 'ACCOUNT_NAME',
        'Support Group': 'SUPPORT_TEAM',
        'AppCatId': 'SCALR_PROJECT_NAME',
        'Work Order': 'SCALR_PROJECT_NAME'
    }
    for name, gv in udf.items():
        if not gv in data:
            raise Exception('Global Variable {} not found, cannot set user defined field in IPAM')
        device.userDefinedFields[name] = data[gv]
    device.userDefinedFields['Floor'] = 'not applicable'

    logging.info(json.dumps(data, indent=2))
    logging.info('Adding: ' + device.hostname + ' ' + device.ipAddress)
    client.service.importDevice(device)
    # pushing DNS config

    return 'Ok'

def delDev(data):
    client = Client(delete_url(),
                    username=IPCONTROL_LOGIN,
                    password=IPCONTROL_PASSWORD,
                    location=delete_location(),
                    timeout=10,
                    proxy=PROXY)
    device = client.factory.create('ns2:WSDevice')
    device.ipAddress = get_ip(data)
    client.service.deleteDevice(device)
    return 'Deletion ok'


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

def loadConfig(filename):
    with open(config_file) as f:
        options = json.loads(f.read())
        for key in options:
            if key in ['IPCONTROL_LOGIN', 'IPCONTROL_PASSWORD', 'DIAMONDIP_SERVER', 'PROXY']:
                logging.info('Loaded config: {}'.format(key))
                globals()[key] = options[key]
            elif key in ['SCALR_SIGNING_KEY']:
                logging.info('Loaded config: {}'.format(key))
                globals()[key] = options[key].encode('ascii')

loadConfig(config_file)

if __name__=='__main__':
    app.run(debug=False, host='0.0.0.0')

