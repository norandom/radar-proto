import os
from collections import OrderedDict
from requests.auth import HTTPBasicAuth
import ConfigParser
import requests
import pandas as pd
from pandas.io.json import json_normalize
import json

from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter


def read_config(cfgname="config.ini", section="DEFAULT"):
    file = os.getcwd() + os.sep + cfgname
    print "Reading from " + file
    configParser = ConfigParser.RawConfigParser()
    configParser.read(file)
    # ip = configParser.get(section, "server_ip")
    return configParser


def generate_request_header(api_key, api_pw):
    headers = OrderedDict([('Accept', "application/json")])
    return headers


def get_threat_intel_by_ip(ip="", xforce_api_key="", xforce_api_pw="", xforce_url=""):
    xheaders = generate_request_header(xforce_api_key, xforce_api_pw)
    xforce_api_url = xforce_url + "/ipr/" + ip
    bauth = HTTPBasicAuth(xforce_api_key, xforce_api_pw)
    infos = requests.get(xforce_api_url, headers=xheaders, auth=bauth).json()
    _pretty_print_json(infos)
    df = json_normalize(infos, record_path="history")
    return df


def get_reputation_by_ip(ip="", xforce_api_key="", xforce_api_pw="", xforce_url=""):
    xheaders = generate_request_header(xforce_api_key, xforce_api_pw)
    xforce_api_url = xforce_url + "/ipr/history/" + ip
    bauth = HTTPBasicAuth(xforce_api_key, xforce_api_pw)
    infos = requests.get(xforce_api_url, headers=xheaders, auth=bauth).json()
    _pretty_print_json(infos)
    df = json_normalize(infos, record_path="history")
    return df


def get_threat_score_by_ip(ip="", xforce_api_key="", xforce_api_pw="", xforce_url=""):
    xheaders = generate_request_header(xforce_api_key, xforce_api_pw)
    xforce_api_url = xforce_url + "/ipr/" + ip
    bauth = HTTPBasicAuth(xforce_api_key, xforce_api_pw)
    infos = requests.get(xforce_api_url, headers=xheaders, auth=bauth).json()
    _pretty_print_json(infos)
    df = json_normalize(infos, record_path="history")
    return int(round(df["score"].mean()))


def _pretty_print_json(json_object):
    json_str = json.dumps(json_object, indent=4, sort_keys=True)
    print(highlight(json_str, JsonLexer(), TerminalFormatter()))