#!/usr/bin/env python3
import argparse
import requests

parser = argparse.ArgumentParser()
parser.add_argument('-a', '--api_id', required=True,
                    type=int, help='API ID Number')
parser.add_argument('-j', '--jwt', required=True,
                    type=str, help='JSON Web Token String')
args = parser.parse_args()
jwt = args.jwt
api_id = args.api_id

client_token = "Aea84abc487da11e9afa48308d39e8e0aBAZHello"

url = "https://demoportal.uvoo.io/api/auth_verify"

hdrs = {'content-type': 'application/json', 'Authorization': f'Bearer {jwt}'}
r = requests.post(url, data='', headers=hdrs)
print(r.status_code)
print(r.text)
