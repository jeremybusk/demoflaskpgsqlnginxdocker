#!/usr/bin/env python3
import requests
import json

username = 'portaltester@uvoo.io'  # This is test user, change as needed.
password = 'DemoAppMe!987'
# url = 'http://localhost:4000/api'  # Used for local testing
url = "https://demoportal.uvoo.io/api"  # Used for live testing

jwt_auth_url = f"{url}/auth"
jwt_verify_url = f"{url}/auth_verify_show_info"

print("==============================")
print("GET JWT")
print("==============================")
payload = {'username': username, 'password': password}
headers = {'content-type': 'application/json'}
r = requests.post(jwt_auth_url, data=json.dumps(payload), headers=headers)
jwt = r.json()['access_token']
print(r.status_code)
print(r.text)
print(r.headers)

print("==============================")
print("VERIFY JWT")
print("==============================")

hdrs = {'content-type': 'application/json', 'Authorization': f'Bearer {jwt}'}
r = requests.post(jwt_verify_url, data=json.dumps(payload), headers=hdrs)
print(r.status_code)
print(r.text)
print(r.headers)
