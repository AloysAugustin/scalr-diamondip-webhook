#!/usr/bin/env python

# Disable HTTPS verification
import ssl
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    print('AttrError')
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    print('Disabling https verification')
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

from flask import Flask
from flask import request
from flask import abort
import pytz
import suds
from suds.client import Client
import json
import dns.resolver
import logging
import binascii
import dateutil.parser
import hmac
from hashlib import sha1
from datetime import datetime
import re

config_file = './config_prod.json'

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# will be overridden if present in config_file
IPCONTROL_LOGIN = ''
IPCONTROL_PASSWORD = ''
SCALR_SIGNING_KEY = ''
DIAMONDIP_SERVER = ''
STATIC_ZONES = []
IGNORED_ZONES = []
PROXY = {}

import_url = lambda: DIAMONDIP_SERVER + 'inc-ws/services/Imports?wsdl'
import_location = lambda: DIAMONDIP_SERVER + 'inc-ws/services/Imports'
delete_url = lambda: DIAMONDIP_SERVER + 'inc-ws/services/Deletes?wsdl'
delete_location = lambda: DIAMONDIP_SERVER + 'inc-ws/services/Deletes'
tasks_url = lambda: DIAMONDIP_SERVER + 'inc-ws/services/TaskInvocation?wsdl'
tasks_location = lambda: DIAMONDIP_SERVER + 'inc-ws/services/TaskInvocation'

@app.route("/", methods=['POST'])
def webhook_listener():
    try:
        if not validateRequest(request):
            abort(403)

        data = json.loads(request.data)
        if not 'eventName' in data or not 'data' in data:
            abort(404)

        domainName = getDomainName(data['data'])
        if domainName in IGNORED_ZONES or domainName + '.' in IGNORED_ZONES:
            logging.info('Request to register host in %s zone ignored', domainName)
            return 'Ignored zone, skipping'

        if data['eventName'] == 'HostUp':
            return addDev(data['data'])
        elif data['eventName'] in ['HostDown', 'BeforeHostTerminate']:
            return delDev(data['data'])
    except suds.WebFault as e:
        logging.exception('IPAM returned error')
        abort(503)


def getHostname(data):
    return data['SCALR_EVENT_SERVER_HOSTNAME']


def get_ip(data):
    if data['SCALR_EVENT_INTERNAL_IP']:
        return data['SCALR_EVENT_INTERNAL_IP']
    else:
        return data['SCALR_EVENT_EXTERNAL_IP']


def getDomainName(data):
    return data['DNS_DOMAIN']


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def add_linux_aliases(device, data, imports):
    return process_aliases(device, data, imports, True)


def add_windows_aliases(device, data, imports):
    return process_aliases(device, data, imports, False)


def process_aliases(device, data, imports, is_linux):
        # Returns a list of domain nams that were impacted, to be updated
    names = data.get('LB_ALIAS_NAME')
    if not names:
        return set(), []
    changedDomainNames = []
    records_to_import = []

    for name in names.split():
        if not name:
            continue
        if not is_valid_hostname(name):
            logging.error('Invalid hostname found: %s, not registered', name)
            continue
        logging.info("Adding alias: %s", name)
        components = name.split('.')
        hostname = components[0]
        domain_name = '.'.join(components[1:])
        if domain_name[-1] != '.':
            domain_name = domain_name + '.'
        if is_linux:
            device.aliases.append(name)
        else:
            cname_record = imports.factory.create('ns2:WSDeviceResourceRec')
            cname_record.comment = 'Created automatically by Scalr DiamondIP integration'
            cname_record.domain = domain_name
            cname_record.ipAddress = device.ipAddress
            cname_record.owner = hostname
            cname_record.resourceRecordType = 'CNAME'
            cname_record.data = device.hostname + '.' + device.domainName
            records_to_import.append(cname_record)
        changedDomainNames.append(domain_name)

    return set(changedDomainNames), records_to_import

def get_authority(domainName):
    # pushing DNS config
    soa = dns.resolver.query(domainName, 'SOA')
    # select first response in SOA query
    return soa.rrset.items[0].mname.to_text()[:-1]

def pushChanges(domainName, task_client):
    if not domainName:
        return
    server = get_authority(domainName)
    if domainName in STATIC_ZONES or domainName + '.' in STATIC_ZONES:
        # Static zone
        # Using changed zones temporarily since our user doesn't have access to dnsConfigurationSelectedZones
        logging.info('Updating static zone: %s, server: %s', domainName, server)
        task_client.service.dnsConfigurationChangedZones(name=server, ip='', abortfailedcheck=True, checkzones=True)
    else:
        # Dynamic zone
        logging.info('Updating dynamic zone: %s, server: %s', domainName, server)
        task_client.service.dnsDDNSChangedRRs(name=server)
    

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
    device.ipAddress = get_ip(data)

    # Hostname, domain name & aliases
    device.hostname = getHostname(data)
    device.domainName = getDomainName(data)
    if device.domainName and device.domainName[-1] != '.':
            device.domainName = device.domainName + '.'
    if 'OS_ID' in data and data['OS_ID'].lower() == 'l':
        # Create resource records, add aliases directly
        device.resourceRecordFlag = True
        device.aliases = []
        changed_domains, records_to_import = add_linux_aliases(device, data, client)
        changed_domains.add(device.domainName)
    else:
        # Don't create resource records for the machine, create them manually for the aliases
        device.resourceRecordFlag = False
        changed_domains, records_to_import = add_windows_aliases(device, data, client)

    udf = {
        'location': 'DATACENTER',
        'OSOrgUnit': 'ACCOUNT_NAME',
        'SupportContactOS': 'SUPPORT_TEAM',
        'appcatid': 'SCALR_PROJECT_NAME',
        'WOREF': 'CRQ_NUMBER'
    }
    device.userDefinedFields = ['floor=not applicable']
    for name, gv in udf.items():
        if not gv in data:
            raise Exception('Global Variable {} not found, cannot set user defined field in IPAM'.format(gv))
        val = data[gv]
        device.userDefinedFields.append(name + '=' + val)

    logging.debug(json.dumps(data, indent=2))
    logging.info('Adding: OS ' + data['OS_ID'] + ', ' + device.hostname + ' ' + device.ipAddress)
    logging.info('Domain name: %s', device.domainName)
    logging.info('User defined fields: {}'.format(device.userDefinedFields))
    logging.info("Zones to update: {}, {} records to add manually".format(changed_domains, len(records_to_import)))

    client.service.importDevice(device)
    for record in records_to_import:
        client.service.importDeviceResourceRecord(record)

    task_client = Client(tasks_url(),
                         username=IPCONTROL_LOGIN,
                         password=IPCONTROL_PASSWORD,
                         location=tasks_location(),
                         timeout=10,
                         proxy=PROXY)
    for domain in changed_domains:
        pushChanges(domain, task_client)
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
    if 'OS_ID' in data and data['OS_ID'].lower() == 'l':
        task_client = Client(tasks_url(),
                             username=IPCONTROL_LOGIN,
                             password=IPCONTROL_PASSWORD,
                             location=tasks_location(),
                             timeout=10,
                             proxy=PROXY)
        pushChanges(getDomainName(data), task_client)
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
            if key in ['IPCONTROL_LOGIN', 'IPCONTROL_PASSWORD', 'DIAMONDIP_SERVER', 'PROXY', 'STATIC_ZONES', 'IGNORED_ZONES']:
                logging.info('Loaded config: {}'.format(key))
                globals()[key] = options[key]
            elif key in ['SCALR_SIGNING_KEY']:
                logging.info('Loaded config: {}'.format(key))
                globals()[key] = options[key].encode('ascii')

loadConfig(config_file)

if __name__=='__main__':
    app.run(debug=False, host='0.0.0.0')

