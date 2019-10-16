#!/usr/bin/env python
# Developed by Michael Hyland 2019
# Licensed under the GNU GENERAL PUBLIC LICENSE V3

import requests
import json
import argparse
import time
import re
from yaspin import yaspin
from yaspin.spinners import Spinners
import subprocess
from OpenSSL import crypto as c
from config.config_reader import config_json_read


# Colors for printing
class bcolors:
    HEADER = '\033[95m'
    INFOBLUE = '\u001b[36m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


BANNER = r''' 
  _______             _______               _____        __  _ ____          __        __  __        __     __        
 / ___/ /__  __ _____/ / _/ /__ ________   / ___/__ ____/ /_(_) _(_)______ _/ /____   / / / /__  ___/ /__ _/ /____ ___
/ /__/ / _ \/ // / _  / _/ / _ `/ __/ -_) / /__/ -_) __/ __/ / _/ / __/ _ `/ __/ -_) / /_/ / _ \/ _  / _ `/ __/ -_|_-<
\___/_/\___/\_,_/\_,_/_//_/\_,_/_/  \__/  \___/\__/_/  \__/_/_//_/\__/\_,_/\__/\__/  \____/ .__/\_,_/\_,_/\__/\__/___/
                                                                                         /_/                          
'''

data = config_json_read()
content_type = data['auth']['content_type']
email = data['auth']['email']
token = data['auth']['token']


ap = argparse.ArgumentParser()
ap.add_argument("-n", "--hostname", required=True,
                help="the hostname to check")
ap.add_argument("-c", "--certificate", required=True,
                help="the certificate file to upload")
ap.add_argument("-k", "--key", required=True,
                help="the key file to upload")
ap.add_argument("-z", "--zone", required=True,
                help="the zone to check")
args = vars(ap.parse_args())

##FUNCTIONS##

def check_zones_match_argument():
    """
    This functions checks whether zones configured match the zone supplied via the argument
    :return:
    """
    zones = []
    z = data['zones']
    for k, v in z.items():
        zones.append(v)

    return zones

def match_zones_and_ids():
    """
    This function matches the zones to the ids in the configuration file
    :return:
    """
    data = config_json_read()
    zones = []
    ids = []
    z = data['zones']
    z_i = data['zone_ids']

    for k, v in z.items():
        z_values = v
        zones.append(z_values)

    for k, v in z_i.items():
        zid_values = v
        ids.append(zid_values)

    dict_of_zones = dict(zip(zones, ids))
    return dict_of_zones

def get_certificate_san(x509cert):
    """
    This function gathers the SANS from the supplied certificate
    :param x509cert:
    :return:
    """
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    return san


def get_total_pages():
    """
    This function returns the total amount of pages. It is used by the get_all_data function
    :return:
    """
    url = 'https://api.cloudflare.com/client/v4/zones/{}/custom_hostnames?per_page=50'
    headers = {
        'Content-Type': content_type,
        'X-Auth-Email': email,
        'X-Auth-Key': token
    }

    z = match_zones_and_ids()

    for k, v in z.items():
        if args["zone"] == k:
            r = requests.get(url.format(v), headers=headers)

    result = json.loads(r.text)
    total_pages = (result['result_info']['total_pages'])

    return total_pages


def get_data_per_page(page):
    """
    This function is used by the get_all_data function to get data for all pages.
    :param page:
    :return:
    """
    url = 'https://api.cloudflare.com/client/v4/zones/{}/custom_hostnames?' \
          'page={}&per_page=50'
    headers = {
        'Content-Type': content_type,
        'X-Auth-Email': email,
        'X-Auth-Key': token
    }

    z = match_zones_and_ids()

    for k, v in z.items():
        if args["zone"] == k:
            r = requests.get(url.format(v, page), headers=headers)

    result = json.loads(r.text)
    custom_hostnames = result['result']
    return custom_hostnames


def get_all_data():
    """
    This function returns a list of all hostname data
    :return:
    """
    total_pages = get_total_pages()
    cs = []
    for i in range(1, total_pages + 1):
        d = get_data_per_page(i)
        cs.append(d)
    return cs


def get_all_hostnames():
    """
    This function returns a list of all hostnames
    :return:
    """
    hostnames = []
    d = get_all_data()
    for i in d:
        for a in i:
            hostnames.append(a['hostname'])
    return hostnames


def check_hostname_match(hostname, checkname):
    """
    This function checks whether the hostname supplied exists on Cloudflare
    :param hostname:
    :param checkname:
    :return:
    """

    names = []
    for a in checkname:
        for i in a:
            names.append(i['hostname'])

    if hostname in names:
        pass
    else:
        sp.hide()
        print(bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + bcolors.BOLD + 'There is no hostname ' + args["hostname"]
              + ' on the ' + args["zone"] + ' Cloudflare zone')
        print('\n')
        exit()


def get_serial_number():
    """
    This function gets the cloudflare serial number of the supplied hostnam
    :return
    """
    custom_hostnames = get_all_data()

    for ch in custom_hostnames:
        for i in ch:
            if args["hostname"] == i['hostname']:
                cert_serial = i['ssl']['certificates'][0]['serial_number']
                return cert_serial


def get_all_names_with_same_certificate():
    """
    This function collects all the names with the same certificate
    :return:
    """

    serial_number = get_serial_number()

    custom_hostnames = get_all_data()

    check_hostname_match(args["hostname"], custom_hostnames)

    serial_names = []
    for ch in custom_hostnames:
        for i in ch:
            try:
                if serial_number == i['ssl']['certificates'][0]['serial_number']:
                    serial_names.append(i['hostname'])
            except KeyError:
                pass

    return serial_names


def get_id(hostname):
    """
    This function gets the cloudflare id numbers related to and including the supplied hostname
    :return:
    """
    custom_hostnames = get_all_data()

    ids = {}
    for ch in custom_hostnames:
        for i in ch:
            if hostname == i['hostname']:
                host_id = i['id']
                origin = i['custom_origin_server']
                ids['hostname'] = hostname
                ids['host_id'] = host_id
                ids['origin_server'] = origin

    return ids


def prepare_certificate_and_key():
    """
    This function prepares the certificate and key file for the API call
    :return:
    """
    with open(args["certificate"], "r") as fd:
        cert_lines = fd.read().splitlines()
    with open(args["key"], "r") as fd:
        key_lines = fd.read().splitlines()
    sep = ','
    cert = sep.join(cert_lines).replace(',', '\n')
    key = sep.join(key_lines).replace(',', '\n')

    return cert, key


def update_cert_on_cloudflare(host_details):
    """
    This function does the update and reports to stdout.
    :param host_details:
    :return:
    """
    for i in host_details:

        cert, key = prepare_certificate_and_key()

        headers = {
            'Content-Type': content_type,
            'X-Auth-Email': email,
            'X-Auth-Key': token
        }

        url_delete = 'https://api.cloudflare.com/client/v4/zones/{}/custom_hostnames/{}'

        sp.hide()

        print(bcolors.INFOBLUE + '[ INFO ] ' + bcolors.ENDC + bcolors.ENDC + 'Updating ' + i["hostname"])
        print('\n')

        sp.show()

        z = match_zones_and_ids()

        for k, v in z.items():
            if args["zone"] == k:
                r_delete = requests.delete(url_delete.format(v, i["host_id"]), headers=headers)

        result_delete = json.loads(r_delete.text)

        if result_delete["success"] == False:
            sp.hide()
            print(bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + bcolors.BOLD + i["hostname"] + ' failed to update. '
                  + result_delete["errors"][0]["message"])
            print('\n')
            exit()

        url_add = 'https://api.cloudflare.com/client/v4/zones/{}/custom_hostnames'
        data = {'hostname': i["hostname"], 'custom_origin_server': i["origin_server"],
                'ssl': {"custom_certificate": cert, "custom_key": key}}

        z = match_zones_and_ids()

        for k, v in z.items():
            if args["zone"] == k:
                r_add = requests.post(url_add.format(v), data=json.dumps(data), headers=headers)

        result_add = json.loads(r_add.text)

        if result_add["success"] == False:
            sp.hide()
            print(bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + bcolors.BOLD + i["hostname"] + ' failed to update. '
                  + result_add["errors"][0]["message"])
            print('\n')
            exit()

        sp.hide()

        print(bcolors.OKGREEN + '[ OK ] ' + bcolors.ENDC + i["hostname"] + ' successfully updated')
        print('\n')


##ENDFUNCTIONS##


print('\n')
print(bcolors.HEADER + BANNER + bcolors.ENDC)

'''
Analyze the supplied template.

HOW IT CURRENTLY WORKS:
      1. Ensure the user supplied hostname matches the Common Name or Alternative Name
          a. If its a wildcard certificate ensure the Common Names domain and the supplied hostname domain match
      2. Ensure the user supplied certificate and the key match    
      3. Display the following information:

        HOSTNAME
        ASSOCIATED HOST NAMES
        CERTIFICATE ISSUED ON
        CERTIFICATE EXPIRES ON

'''
with yaspin(Spinners.earth, text="Analyzing Supplied Certificate And Key For "
        + bcolors.BOLD + str(args[("hostname")]).upper()) as sp:

    zones = check_zones_match_argument()

    if args["zone"] not in zones:
        sp.hide()
        print(bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + bcolors.BOLD + 'There is no zone called '
              + args["zone"] + ' on Cloudflare')
        print('\n')
        exit()
    else:

        time.sleep(5)
        x509 = c.load_certificate(c.FILETYPE_PEM,
                                  open(args[("certificate")]).read())
        x509info_na = x509.get_notAfter()
        exp_day = x509info_na[6:8].decode('utf-8')
        exp_month = x509info_na[4:6].decode('utf-8')
        exp_year = x509info_na[:4].decode('utf-8')

        x509info_nb = x509.get_notBefore()
        nb_day = x509info_nb[6:8].decode('utf-8')
        nb_month = x509info_nb[4:6].decode('utf-8')
        nb_year = x509info_nb[:4].decode('utf-8')

        cn = x509.get_subject().CN.lower()

        san = get_certificate_san(x509)
        san = san.replace('DNS:', '').replace(' ', '')
        san_list = san.split(",")
        sp.hide()

        if re.search(r'\*.(.*)', cn):
            hn_wild_card = args[("hostname")].split('.', 1)[-1]
            cn_wild_card = cn.split('.', 1)[-1]
            if hn_wild_card == cn_wild_card:
                print('\n')
                print(bcolors.INFOBLUE + '[ INFO ] ' + bcolors.ENDC + bcolors.ENDC + 'This is a Wilcard Certificate')
                print('\n')
                print(bcolors.OKGREEN + '[ OK ] ' + bcolors.ENDC + bcolors.ENDC + 'The supplied hostname matches the'
                                                                                  ' Common Name Wildcard domain')
                print('\n')
            else:
                print(bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + bcolors.BOLD + ' This is a Wilcard Certificate.'
                                                                                  ' The supplied hostname does'
                                                                                  ' not match the certificate')

                print('\n')
                exit()

        elif args[("hostname")] not in san_list and args[("hostname")] != cn:
            print(bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + bcolors.BOLD + ' The supplied hostname does not match'
                                                                              ' the Common Name or Alternative Names'
                                                                              ' of the supplied Certificate')
            print('\n')
            exit()

        cert_cmd = 'openssl x509 -noout -modulus -in {} | openssl md5'.format(args[("certificate")])
        key_cmd = 'openssl rsa -noout -modulus -in  {}| openssl md5'.format(args[("key")])

        cert_proc = subprocess.Popen(cert_cmd, shell=True, stdout=subprocess.PIPE)

        key_proc = subprocess.Popen(key_cmd, shell=True, stdout=subprocess.PIPE)
        cert = cert_proc.communicate()[0]
        key = key_proc.communicate()[0]

        if cert == key:
            sp.hide()
            print(bcolors.OKGREEN + '[ OK ] ' + bcolors.ENDC + bcolors.BOLD + 'The certificate and the key match')
            print('\n')
        else:
            print(bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + bcolors.BOLD + "The certificate and the key don't match")
            print('\n')
            exit()
        print(bcolors.INFOBLUE + '[ INFO ] ' + bcolors.ENDC + bcolors.BOLD + str(args["hostname"]).upper()
              + bcolors.ENDC + ' Supplied Certificate Details:')
        print('\n')
        print(bcolors.BOLD + '     HOSTNAME: ' + bcolors.ENDC + args["hostname"])
        print(bcolors.BOLD + '     ASSOCIATED HOST NAMES: ' + bcolors.ENDC + san)
        print(bcolors.BOLD + '     CERTIFICATE ISSUED ON: ' + bcolors.ENDC + nb_year + '-' + nb_month + '-' + nb_day)
        print(
            bcolors.BOLD + '     CERTIFICATE EXPIRES ON: ' + bcolors.ENDC + exp_year + '-' + exp_month + '-' + exp_day)
        print('\n')

'''
Match all the host names on Cloudflare that will share this certificate and display them

'''

with yaspin(Spinners.earth, text="Collecting Certificate Information From Cloudflare For " + bcolors.BOLD
        + str(args[("hostname")]).upper()) as sp:
    names = get_all_names_with_same_certificate()
    sp.hide()
    print(bcolors.INFOBLUE + '[ INFO ] ' + bcolors.ENDC + bcolors.BOLD + bcolors.ENDC + ' The following names '
                                                                                        'share this certificate on Cloudflare. They will all be updated.')
    print('\n')
    print(bcolors.BOLD + '     SHARED CERTIFICATE NAMES: ' + ", ".join(names))

print('\n')

'''
Prompt to continue
'''

answer = input(bcolors.WARNING + '[ WARNING ] ' + bcolors.ENDC + 'Continue with certificate update(s)? yes/no: ')

'''
Update the certificate on Cloudflare
'''

if answer == "yes" or answer == 'y':
    print('\n')
    with yaspin(Spinners.earth, text="Updating certificate(s) on Cloudflare ") as sp:

        '''
        1. Get the certificate serial number of the supplied hostname.
        2. Match all other hosts on cloudflare with the same serial number including the supplied hostname.
        3. Get all the matched hostnames per id.
        4. Delete the custom hostname by id and add the custom hostname with new cert and key. This is done one by one.
        '''

        all_names = get_all_names_with_same_certificate()

        details_to_update = [get_id(x) for x in all_names]

        update_cert_on_cloudflare(details_to_update)

        print(bcolors.OKGREEN + '[ OK ] ' + bcolors.ENDC + 'Certificate Update(s) Complete')
        print('\n')

elif answer == "no" or answer == 'n':
    print('\n')
    print(bcolors.FAIL + '[ CANCELLED ]' + bcolors.ENDC + ' Certificate update(s) cancelled')
    print('\n')
