#!/usr/bin/env python3
import requests

res = requests.get("https://demoportal.uvoo.io")
if "Login" in res:
    pass
else:
    print(res.content)
    print(res.content == res.text)
    raise SystemExit('E: Unable to find Login in url.')
