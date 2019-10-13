# Cloudflare Custom Hostname Certificate Management
These scripts manage viewing and updating certificates to Cloudflare custom hostnames 

## Requirements

1. Cloudflare Enterprise Account
2. SSL for SaaS enabled on Cloudflare Zone
3. Python 3

## Install the required python packages
`pip install -r requirements.txt`

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
