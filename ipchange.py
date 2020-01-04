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


loginData = {"user": user, "pass": password}
print(requests.post("https://cpanel.antyzero.com/login/?login_only=1", loginData).text)