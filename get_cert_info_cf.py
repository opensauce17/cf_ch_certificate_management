#!/usr/bin/env python

import requests
import json
import argparse
from yaspin import yaspin
from yaspin.spinners import Spinners
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
  _______             _______               _____        __  _ ____          __        ____     ___   
 / ___/ /__  __ _____/ / _/ /__ ________   / ___/__ ____/ /_(_) _(_)______ _/ /____   /  _/__  / _/__ 
/ /__/ / _ \/ // / _  / _/ / _ `/ __/ -_) / /__/ -_) __/ __/ / _/ / __/ _ `/ __/ -_) _/ // _ \/ _/ _ \
\___/_/\___/\_,_/\_,_/_//_/\_,_/_/  \__/  \___/\__/_/  \__/_/_//_/\__/\_,_/\__/\__/ /___/_//_/_/ \___/

'''

data = config_json_read()
content_type = data['auth']['content_type']
email = data['auth']['email']
token = data['auth']['token']

ap = argparse.ArgumentParser()
ap.add_argument("-n", "--hostname", required=True,
                help="the hostname to check")
ap.add_argument("-z", "--zone", required=True,
                help="the zone to check")

args = vars(ap.parse_args())

print('\n')
print(bcolors.HEADER + BANNER + bcolors.ENDC)

'''
Get host certificate information from Cloudflare. 

Display the following information:

    HOSTNAME
    ASSOCIATED HOST NAMES
    CERTIFICATE ISSUED ON
    CERTIFICATE EXPIRES ON
    CERTIFICATE UPLOADED TO CF ON
    ORIGIN

'''

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

    serial_names = []
    for ch in custom_hostnames:
        for i in ch:
            try:
                if serial_number == i['ssl']['certificates'][0]['serial_number']:
                    serial_names.append(i['hostname'])
            except KeyError:
                pass

    return serial_names


    ##ENDFUNCTIONS##

with yaspin(Spinners.earth, text="Collecting Certificate Information From Cloudflare For " + bcolors.BOLD
        + str(args[("hostname")]).upper()) as sp:

    zones = check_zones_match_argument()

    if args["zone"] not in zones:
        sp.hide()
        print(bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + bcolors.BOLD + args["zone"] + ' is not a valid zone.'
                                                                                         ' Add additional zones to the'
                                                                                         ' config file')
        print('\n')
    else:
        data = get_all_data()

        check_hostname_match(args["hostname"], data)

        for a in data:
            for d in a:
                if d['hostname'] == args["hostname"]:
                    sp.hide()
                    print(bcolors.INFOBLUE + '[ INFO ] ' + bcolors.ENDC + bcolors.BOLD + str(d['hostname']).upper()
                          + bcolors.ENDC + ' Cloudflare Certificate Details:')
                    print('\n')
                    print(bcolors.BOLD + '     ZONE: ' + bcolors.ENDC + args["zone"])
                    print(bcolors.BOLD + '     HOSTNAME: ' + bcolors.ENDC + d['hostname'])
                    if d['ssl']['status'] == 'pending_validation':
                        print('\n')
                        print(bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + bcolors.BOLD
                              + 'The certificate is in a validation pending state')
                        print('\n')
                        exit()
                    print(bcolors.BOLD + '     ASSOCIATED HOST NAMES: ' + bcolors.ENDC + ", ".join(d['ssl']['hosts']))
                    print(bcolors.BOLD + '     STATUS: ' + bcolors.ENDC + d['ssl']['status'])
                    print(bcolors.BOLD + '     CERTIFICATE ISSUED ON: ' + bcolors.ENDC + d['ssl']['certificates'][0][
                        'issued_on'])
                    print(bcolors.BOLD + '     CERTIFICATE EXPIRES ON: ' + bcolors.ENDC + d['ssl']['certificates'][0][
                        'expires_on'])
                    try:
                        print(
                            bcolors.BOLD + '     CERTIFICATE UPLOADED TO CF ON: ' + bcolors.ENDC +
                            d['ssl']['uploaded_on'])
                    except KeyError:
                        print(
                            'This cert was not uploaded. It is using Cloudflare  SAAS service. Or cert is in '
                            'pending state')
                    try:
                        print(bcolors.BOLD + '     ORIGIN: ' + bcolors.ENDC + d['custom_origin_server'])
                    except KeyError:
                        print(
                            'This cert was not uploaded. It is using Cloudflare  SAAS service. Or cert is '
                            'in pending state')
                    print(bcolors.BOLD + '     CERTIFICATE SERIAL NUMBER: ' + bcolors.ENDC +
                          d['ssl']['certificates'][0]['serial_number'])
                    print('\n')

        sp.show()
        names = get_all_names_with_same_certificate()

        sp.hide()
        print(bcolors.INFOBLUE + '[ INFO ] ' + bcolors.ENDC + bcolors.BOLD + bcolors.ENDC + ' The following names '
                                                                                            'share this certificate on '
                                                                                            'Cloudflare')
        print('\n')
        print(bcolors.BOLD + '     SHARED CERTIFICATE NAMES: ' + ", ".join(names))

    print('\n')