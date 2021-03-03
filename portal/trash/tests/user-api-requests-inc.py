#!/usr/bin/env python3
import requests
import json

client_token = 'Aea84abc487da11e9afa48308d39e8e0aBAZHello'
url = 'http://localhost:4000/api/user_api_request_inc'  # Use for local testing

payload = {'client_token': client_token, 'user_id': 1, 'api_id': 1}
headers = {'content-type': 'application/json'}
r = requests.post(url, data=json.dumps(payload), headers=headers)
print(r.status_code)
print(r.text)
