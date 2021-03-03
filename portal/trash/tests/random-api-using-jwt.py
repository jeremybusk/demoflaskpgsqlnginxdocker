#!/usr/bin/env python3
# Change as needed for random api tests.
import json
import requests
import sys

with open('testjwt.txt', 'r') as f:
    jwt = f.read().rstrip('\n')

jwt = ''

# url = "https://demoportal.uvoo.io/api/jtester1"
# url = "https://demoportal.uvoo.io/api/jtester2"
# url = "https://api.uvoo.io/portaltest"
url = "https://api.uvoo.io/portaltest"

headers = {'content-type': 'application/json',
           'Authorization': f'Bearer {jwt}'}
r = requests.post(url, data='', headers=headers)
print(r.status_code)
print(r.text)
print(r.headers)

sys.exit()

if r.status_code == 200:
    print("Success")
elif r.status_code == 400:
    print("Invalid request")
else:
    print("Unsupported.")

text = r.text.strip('\n')
data = {"status_code": r.status_code, "text": text}
json_data = json.loads(r.text)
print(json_data)
print("============")
print(json.dumps(data))
print("============")
print(data)
