#!/usr/bin/env python3
import json
import requests

with open('testjwt.txt', 'r') as f:
    jwt = f.read().rstrip('\n')

# Use either testnet or prod bitcoin network.
url = "https://api.uvoo.io/bitcoin-testnet/"
url = "https://api.uvoo.io/bitcoin/"

headers = {
    'content-type': 'application/json',
    'Authorization': f'Bearer {jwt}'
}

data = {
    "jsonrpc": "1.0", "id": "bitcointest",
    "method": "estimatesmartfee", "params": {"conf_target": 6}
}

data = {
    "jsonrpc": "1.0", "id": "bitcointest",
    "method": "getnetworkinfo", "params": []
}

data = json.dumps(data)
r = requests.post(url, data=data, headers=headers)

print(r.status_code)
print(r.text)
print(r.headers)
