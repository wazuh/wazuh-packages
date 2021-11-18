from datetime import datetime
import time
import os
import re
import json
import sys
import subprocess
from subprocess import Popen, PIPE, check_output
import yaml
import requests
import urllib
from base64 import b64encode
import warnings
from subprocess import check_call
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# ----------------------------- Aux functions -----------------------------


services = None
p = Popen(['/var/ossec/bin/wazuh-control', 'status'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
if sys.version_info[0] < 3:
    services = p.stdout.read()
else:
    services = p.stdout
p.kill()

def get_elasticsearch_password():
    stream = open("/etc/filebeat/filebeat.yml", 'r')
    dictionary = yaml.safe_load(stream)
    return (dictionary.get('output.elasticsearch','password').get('password'))

def get_elasticsearch_username():
    stream = open("/etc/filebeat/filebeat.yml", 'r')
    dictionary = yaml.safe_load(stream)
    return (dictionary.get('output.elasticsearch','username').get('username'))

def get_kibana_password():
    stream = open("/etc/kibana/kibana.yml", 'r')
    dictionary = yaml.safe_load(stream)
    return (dictionary.get('elasticsearch.password'))

def get_kibana_username():
    stream = open("/etc/kibana/kibana.yml", 'r')
    dictionary = yaml.safe_load(stream)
    return (dictionary.get('elasticsearch.username'))

def get_elasticsearch_cluster_status():
    resp = requests.get('https://localhost:9200/_cluster/health',
                        auth=(get_elasticsearch_username(), 
                        get_elasticsearch_password()), 
                        verify=False)
    return (resp.json()['status'])

def get_kibana_status():
    resp = requests.get('https://localhost',
                        auth=(get_kibana_username(), 
                        get_kibana_password()), 
                        verify=False)
    return (resp.status_code)

def get_kibana_status():
    resp = requests.get('https://localhost',
                        auth=(get_kibana_username(), 
                        get_kibana_password()), 
                        verify=False)
    return (resp.status_code)

def get_wazuh_api_status():

    protocol = 'https'
    host = 'localhost'
    port = 55000
    user = 'wazuh'
    password = 'wazuh'
    login_endpoint = 'security/user/authenticate'

    login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
    basic_auth = f"{user}:{password}".encode()
    login_headers = {'Content-Type': 'application/json',
                    'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
    response = requests.get(login_url, headers=login_headers, verify=False)
    token = json.loads(response.content.decode())['data']['token']
    requests_headers = {'Content-Type': 'application/json',
                        'Authorization': f'Bearer {token}'}
    response = requests.get(f"{protocol}://{host}:{port}/?pretty=true", headers=requests_headers, verify=False)

    return response.json()['data']['title'] 

# ----------------------------- Tests ----------------------------- 



def test_check_wazuh_manager_authd():
    assert check_call("ps -xa | grep wazuh-authd | grep -v grep", shell=True) != ""

def test_check_wazuh_manager_db():
    assert check_call("ps -xa | grep wazuh-db | grep -v grep", shell=True) != ""

def test_check_wazuh_manager_execd():
    assert check_call("ps -xa | grep wazuh-execd | grep -v grep", shell=True) != ""

def test_check_wazuh_manager_analysisd():
    assert check_call("ps -xa | grep wazuh-analysisd | grep -v grep", shell=True) != ""

def test_check_wazuh_manager_syscheckd():
    assert check_call("ps -xa | grep wazuh-syscheckd | grep -v grep", shell=True) != ""

def test_check_wazuh_manager_remoted():
    assert check_call("ps -xa | grep wazuh-remoted | grep -v grep", shell=True) != ""

def test_check_wazuh_manager_logcollec():
    assert check_call("ps -xa | grep wazuh-logcollec | grep -v grep", shell=True) != ""

def test_check_wazuh_manager_monitord():
    assert check_call("ps -xa | grep wazuh-monitord | grep -v grep", shell=True) != ""

def test_check_wazuh_manager_modulesd():
    assert check_call("ps -xa | grep wazuh-modulesd | grep -v grep", shell=True) != ""

def test_check_wazuh_manager_apid():
    assert check_call("ps -xa | grep wazuh-apid | grep -v grep", shell=True) != ""

def test_check_filebeat_process():
    assert check_call("ps -xa | grep \"/usr/share/filebeat/bin/filebeat\" | grep -v grep", shell=True) != ""

def test_check_elasticsearch_process():
    assert check_call("ps -xa | grep \"/usr/share/elasticsearch/jdk/bin/java\" | grep -v grep | cut -d \" \" -f15", shell=True) != ""

def test_check_kibana_process():
    assert check_call("ps -xa | grep \"/usr/share/kibana/bin/../node/bin/node\" | grep -v grep", shell=True) != ""

def test_check_elasticsearch_cluster_status():
    assert get_elasticsearch_cluster_status() != "red"

def test_check_kibana_status():
    assert get_kibana_status() == 200

def test_test_check_wazuh_api_status():
    assert get_wazuh_api_status() == "Wazuh API REST"

def test_check_log_errors():
    found_error = False
    with open('/var/ossec/logs/ossec.log', 'r') as f:
        for line in f.readlines():
            if 'ERROR' in line:
                found_error = True
                break
    assert found_error == False, line