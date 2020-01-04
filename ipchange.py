#!/usr/bin/env python

import logging
import argparse
import re
import requests


def ip_address_type(arg_value, pat=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")):
	if not pat.match(arg_value):
		raise argparse.ArgumentTypeError(str(arg_value) + ' is not valid IP address')
	return arg_value

# Command line arguments
parser = argparse.ArgumentParser(description='Script allow to change IP address of the domain in cPanel')
parser.add_argument("-u", "--user", help="cPanel user name", required=True)
parser.add_argument("-p", "--password", help="cPanel user password", required=True)
parser.add_argument("-d", "--domain", help="domain name", required=True)
parser.add_argument("-ip", type=ip_address_type, metavar='IP_ADDRESS', help="new IP address for the domain", required=True)

args = parser.parse_args()

user = args.user
password = args.password
domain = args.domain
ipAddress = args.ip


# Logger
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('IP change cPanel')
logger.setLevel(logging.DEBUG)

# Console logger
consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.DEBUG)
consoleHandler.setFormatter(formatter)

logger.addHandler(consoleHandler)


session = requests.Session()
session.headers['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36"

# Login
loginData = {"user": user, "pass": password}
print(session.post("https://cpanel.antyzero.com/login/?login_only=1", loginData).text)

# Update domain data
changeIpData = {
	"cpanel_jsonapi_apiversion": 2,
	"cpanel_jsonapi_module": "ZoneEdit",
	"cpanel_jsonapi_func": "edit_zone_record",
	"domain": "antyzero.com",
	"name": "home.antyzero.com.",
	"type": "A",
	"class": "IN",
	"ttl": 30,
	"line": 33,
	"address": "89.70.181.34"
}
headers = {
	"accept": "*/*",
	"accept-encoding": "gzip, deflate, br",
	"accept-language": "pl-PL,pl;q=0.9,en;q=0.8",
	"content-length": "191",
	"content-type": "application/x-www-form-urlencoded; charset=UTF-8",
	"cookie": "timezone=Europe/Berlin; session_locale=pl; cpsession=antyzer1%3aQ9OmxWHZOldslJ9d%2c3ed89731a598f0772118a8ffeef2e997",
	"origin": "https://cpanel.antyzero.com",
	"referer": "https://cpanel.antyzero.com/",
	"sec-fetch-mode": "cors",
	"sec-fetch-site": "same-origin",
	"x-requested-with": "XMLHttpRequest"
}
print(session.post("https://cpanel.antyzero.com/cpsess8264491184/json-api/cpanel", changeIpData, headers=headers))