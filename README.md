# Cloudflare Custom Hostname Certificate Management
These simple python scripts manage viewing and updating custom certificates to Cloudflare custom hostnames. 

# Setup

## Requirements

* Cloudflare enterprise account
* SSL for SaaS enabled on a Cloudflare zone
* Existing custom hostnames with custom certificates
* Python 3

## Install the required python packages
`pip install -r requirements.txt`

## Edit configuration file for your zone

The configuration file is config/congfig.json. Add the following:

* Authentication details in the auth section
* Zone names in the zone section
* Zone id's in the zone_ids section

It's important that zone names match zone id's. i.e zone1 name should match zone1 id

# Review a certificate

## Get parameters for get_cert_info_cf.py
`./get_cert_info_cf.py -h`

## Get information about current certificate
`./get_cert_info_cf.py -n hostname -z zonename`

# Update certificate

## Get parameters for update_cert_cf.py
`./update_cert_cf.py -h`

## Update the certificate
`./update_cert_cf.py -n hostname -c certificate.crt -k key.key -z zonename`
