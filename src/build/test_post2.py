import urllib.request
import json

url = 'https://roblox-scanner-hioo.onrender.com/checker/add'
data = {
    'name': 'rico',
    'key': 'PENDING',
    'role': 'checker',
    'master_key': 'NatsuXAK2026'
}
req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json', 'X-Name': 'ak', 'X-Key': 'NatsuXAK2026'})
try:
    resp = urllib.request.urlopen(req)
    print(resp.read().decode())
except Exception as e:
    print(e.code)
    print(e.read().decode())
