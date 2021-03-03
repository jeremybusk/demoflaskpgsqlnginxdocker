#!/usr/bin/env python3
import json
import requests

with open('testjwt.txt', 'r') as f:
    jwt = f.read().rstrip('\n')

url = "https://api.uvoo.io/ethereum/"

headers = {'content-type': 'application/json',
           'Authorization': f'Bearer {jwt}'}
data = '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}'
r = requests.post(url, data=data, headers=headers)

print(r.status_code)
print(r.text)
print(r.headers)
