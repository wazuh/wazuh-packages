from datetime import datetime
import pytest
import json
import sys
import tarfile
from subprocess import Popen, PIPE, check_output
import yaml
import requests
import socket
from base64 import b64encode
import warnings
import subprocess
from subprocess import check_call

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# ----------------------------- Aux functions -----------------------------

def read_services():
    services = None
    p = Popen(['/var/ossec/bin/wazuh-control', 'status'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    if sys.version_info[0] < 3:
        services = p.stdout.read()
    else:
        services = p.stdout
    p.kill()

def get_password(username):
    pass_dict={'username': 'tmp_user', 'password': 'tmp_pass'}
    tmp_yaml=""

    with tarfile.open("../../../unattended_installer/wazuh-install-files.tar") as configurations:
        configurations.extract("wazuh-install-files/wazuh-passwords.txt")

    with open("wazuh-install-files/wazuh-passwords.txt", 'r') as pass_file:
        while pass_dict["username"] != username:
            for i in range(4):
                tmp_yaml+=pass_file.readline()
            tmp_dict=yaml.safe_load(tmp_yaml)
            if 'indexer_username' in tmp_dict:
                pass_dict["username"]=tmp_dict["indexer_username"]
                pass_dict["password"]=tmp_dict["indexer_password"]
            if 'api_username' in tmp_dict:
                pass_dict["username"]=tmp_dict["api_username"]
                pass_dict["password"]=tmp_dict["api_password"]
    return pass_dict["password"]

def get_wazuh_version():
    wazuh_version = None
    wazuh_version = subprocess.getoutput('/var/ossec/bin/wazuh-control info | grep VERSION | cut -d "=" -f2 | sed s/\\"//g')
    return wazuh_version

def get_indexer_ip():

    with open("/etc/wazuh-indexer/opensearch.yml", 'r') as stream:
        dictionary = yaml.safe_load(stream)
    return (dictionary.get('network.host'))

def get_dashboard_ip():

    with open("/etc/wazuh-dashboard/opensearch_dashboards.yml", 'r') as stream:
        dictionary = yaml.safe_load(stream)
    return (dictionary.get('server.host'))

def get_api_ip():

    with open("/var/ossec/api/configuration/api.yaml", 'r') as stream:
        dictionary = yaml.safe_load(stream)
    try:
      ip = dictionary.get('host')
    except:
      ip = '127.0.0.1'
    return ip

def api_call_indexer(host,query,address,api_protocol,api_user,api_pass,api_port):

    if (query == ""):   # Calling ES API without query
        if (api_user != "" and api_pass != ""): # If credentials provided
            resp = requests.get(api_protocol + '://' + address + ':' + api_port,
                    auth=(api_user,
                    api_pass),
                    verify=False)
        else:
            resp = requests.get(api_protocol + '://' + address + ':' + api_port, verify=False)

    else: # Executing query search
        if (api_pass != "" and api_pass != ""):
            resp = requests.post(api_protocol + '://' + address + ':' + api_port + "/wazuh-alerts-4.x-*/_search",
                        json=query,
                        auth=(api_user,
                        api_pass),
                        verify=False)
        else:
            resp = requests.get(api_protocol + "://" + address + ":" + api_port)
    response = resp.json()
    return response

def get_indexer_cluster_status():
    ip = get_indexer_ip()
    resp = requests.get('https://'+ip+':9200/_cluster/health',
                        auth=("admin",
                        get_password("admin")),
                        verify=False)
    return (resp.json()['status'])

def get_dashboard_status():
    ip = get_dashboard_ip()
    resp = requests.get('https://'+ip,
                        auth=("kibanaserver",
                        get_password("kibanaserver")),
                        verify=False)
    return (resp.status_code)

def get_wazuh_api_status():

    protocol = 'https'
    host = get_api_ip()
    port = 55000
    user = 'wazuh'
    password = get_password('wazuh')
    login_endpoint = 'security/user/authenticate'

    login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
    basic_auth = f"{user}:{password}".encode()
    login_headers = {'Content-Type': 'application/json',
                    'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
    response = requests.post(login_url, headers=login_headers, verify=False)
    token = json.loads(response.content.decode())['data']['token']
    requests_headers = {'Content-Type': 'application/json',
                        'Authorization': f'Bearer {token}'}
    response = requests.get(f"{protocol}://{host}:{port}/?pretty=true", headers=requests_headers, verify=False)
    return response.json()['data']['title']

# ----------------------------- Tests -----------------------------

@pytest.mark.wazuh
def test_check_wazuh_manager_authd():
    assert check_call("ps -xa | grep wazuh-authd | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_wazuh_manager_db():
    assert check_call("ps -xa | grep wazuh-db | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_wazuh_manager_execd():
    assert check_call("ps -xa | grep wazuh-execd | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_wazuh_manager_analysisd():
    assert check_call("ps -xa | grep wazuh-analysisd | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_wazuh_manager_syscheckd():
    assert check_call("ps -xa | grep wazuh-syscheckd | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_wazuh_manager_remoted():
    assert check_call("ps -xa | grep wazuh-remoted | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_wazuh_manager_logcollec():
    assert check_call("ps -xa | grep wazuh-logcollec | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_wazuh_manager_monitord():
    assert check_call("ps -xa | grep wazuh-monitord | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_wazuh_manager_modulesd():
    assert check_call("ps -xa | grep wazuh-modulesd | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_wazuh_manager_apid():
    assert check_call("ps -xa | grep wazuh_apid | grep -v grep", shell=True) != ""

@pytest.mark.wazuh_cluster
def test_check_wazuh_manager_clusterd():
    assert check_call("ps -xa | grep clusterd.py | grep -v grep", shell=True) != ""

@pytest.mark.wazuh
def test_check_filebeat_process():
    assert check_call("ps -xa | grep \"/usr/share/filebeat/bin/filebeat\" | grep -v grep", shell=True) != ""

@pytest.mark.indexer
def test_check_indexer_process():
    assert check_call("ps -xa | grep wazuh-indexer | grep -v grep | cut -d \" \" -f15", shell=True) != ""

@pytest.mark.dashboard
def test_check_dashboard_process():
    assert check_call("ps -xa | grep wazuh-dashboard | grep -v grep", shell=True) != ""

@pytest.mark.indexer
def test_check_indexer_cluster_status_not_red():
    assert get_indexer_cluster_status() != "red"

@pytest.mark.indexer_cluster
def test_check_indexer_cluster_status_not_yellow():
    assert get_indexer_cluster_status() != "yellow"

@pytest.mark.dashboard
def test_check_dashboard_status():
    assert get_dashboard_status() == 200

@pytest.mark.wazuh
def test_check_wazuh_api_status():
    assert get_wazuh_api_status() == "Wazuh API REST"

@pytest.mark.wazuh
def test_check_log_errors():
    found_error = False
    exceptions = [
        'WARNING: Cluster error detected',
        'agent-upgrade: ERROR: (8123): There has been an error executing the request in the tasks manager.',
        "ERROR: Could not send message through the cluster after '10' attempts"

    ]
    
    with open('/var/ossec/logs/ossec.log', 'r') as f:
        for line in f.readlines():
            if 'ERROR' in line:
                if not any(exception in line for exception in exceptions):
                    found_error = True
                    break
    assert found_error == False, line

@pytest.mark.wazuh_cluster
def test_check_cluster_log_errors():
    found_error = False
    with open('/var/ossec/logs/cluster.log', 'r') as f:
        for line in f.readlines():
            if 'ERROR' in line:
                found_error = True
                break
    assert found_error == False, line

@pytest.mark.wazuh_worker
def test_check_cluster_log_errors():
    found_error = False
    with open('/var/ossec/logs/cluster.log', 'r') as f:
        for line in f.readlines():
            if 'ERROR' in line:
                if 'Could not connect to master' not in line and 'Worker node is not connected to master' not in line and 'Connection reset by peer' not in line and "Error sending sendsync response to local client: Error 3020 - Timeout sending" not in line:
                    found_error = True
                    break
    assert found_error == False, line

@pytest.mark.wazuh_cluster
def test_check_api_log_errors():
    found_error = False
    with open('/var/ossec/logs/api.log', 'r') as f:
        for line in f.readlines():
            if 'ERROR' in line:
                found_error = True
                break
    assert found_error == False, line

@pytest.mark.indexer
def test_check_alerts():
    node_name = socket.gethostname()
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "wildcard": {
                            "agent.name": {
                                "value": '*'
                            }
                        }
                    }
                ]
            }
        }
    }

    response = api_call_indexer(get_indexer_ip(),query,get_indexer_ip(),'https',"admin",get_password("admin"),'9200')

    print(response)

    assert (response["hits"]["total"]["value"] > 0)
