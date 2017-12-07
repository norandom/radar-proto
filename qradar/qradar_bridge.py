import os
import json
import urllib
import requests
from requests.auth import HTTPBasicAuth
import ConfigParser
from collections import OrderedDict
import pandas as pd
from pandas.io.json import json_normalize

def generate_request_header(token=""):

    if token:
        print "Token auth not yet implemented. FIXME!"

    headers = OrderedDict([('Accept', "application/json"),
                          ('Version', "6.0")
                          ])
    return headers


def generate_params(query):
    # query = urllib.quote_plus(query)
    params = {
        'query_expression' : query
    }
    return params



def generate_request_url(server_ip, username="", passwd="", token=""):
    protocol = "https://"
    server_ip = server_ip
    base_uri = '/api'
    return protocol + server_ip + base_uri


def read_config(cfgname="config.ini", section="DEFAULT"):
    file = os.getcwd() + os.sep + cfgname
    print "Reading from " + file
    configParser = ConfigParser.RawConfigParser()
    configParser.read(file)
    # ip = configParser.get(section, "server_ip")
    return configParser


def ariel_request_dbs(server_ip, username="", passwd="", token=""):

    aheaders = generate_request_header(token)
    qreq_url = generate_request_url(server_ip, username, passwd, token)
    api_path = '/ariel/databases'
    qradar_api_url = qreq_url + api_path

    print qradar_api_url

    bauth = HTTPBasicAuth(username, passwd)
    dbs = requests.get(qradar_api_url, headers=aheaders, verify=False, auth=bauth).json()
    return dbs


def ariel_query(server_ip, username="", passwd="", token="", query="", keyword=""):

    if not query:
        print "You need to supply a query to this function."
        return

    if not keyword:

        print "The keyword belongs to the query, and defines the event data."
        print "Will use 'events' as default. Please specify it."
        keyword="events"

    aheaders = generate_request_header(token)
    rparams = generate_params(query)
    print rparams
    print type(rparams)
    # aheaders["query_expression"] = urllib.quote("SELECT sourceIP from events")

    bauth = HTTPBasicAuth(username, passwd)
    qreq_url = generate_request_url(server_ip, username, passwd, token)
    api_path = '/ariel/searches'
    qradar_api_url = qreq_url + api_path

    print qradar_api_url

    print aheaders
    # POST request to issue a search
    searchid_req = requests.post(qradar_api_url,
                             headers=aheaders,
                             params=rparams,
                             verify=False,
                             auth=bauth)

    print "Status code: " + str(searchid_req.status_code)
    print "Response   : " + str(searchid_req.json())

    search_id_response = json.loads(searchid_req.text.decode('utf-8'))
    search_id = search_id_response['search_id']


    print "Search ID: " + search_id
    # GET request for the search status
    searches = requests.get(qradar_api_url + "/" + search_id, headers=aheaders, verify=False, auth=bauth)

    # Check until it's done
    response_json = json.loads(searches.text.decode('utf-8'))
    print response_json
    error = False
    while (response_json['status'] != 'COMPLETED') and not error:
        if (response_json['status'] == 'EXECUTE') | \
                (response_json['status'] == 'SORTING') | \
                (response_json['status'] == 'WAIT'):
            response = requests.get(qradar_api_url + "/" + search_id, headers=aheaders, verify=False, auth=bauth)
            response_json = json.loads(response.text.decode('utf-8'))
            print response_json
        else:
            print(response_json['status'])
            error = True

    results = json_normalize(
            requests.get(qradar_api_url + "/" + search_id + '/results',
                                      headers=aheaders, verify=False, auth=bauth).json(), record_path=keyword)
    return results



def get_offenses(server_ip, username="", passwd="", token=""):
    aheaders = generate_request_header(token)
    qreq_url = generate_request_url(server_ip, username, passwd, token)
    api_path = '/siem/offenses'
    qradar_api_url = qreq_url + api_path

    print qradar_api_url

    bauth = HTTPBasicAuth(username, passwd)
    offenses = requests.get(qradar_api_url, headers=aheaders, verify=False, auth=bauth).json()
    print type(offenses)
    return offenses


def get_top_talkers_egress():
    pass


def get_talkers_random_egress():
    pass



