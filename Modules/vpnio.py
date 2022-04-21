import requests


def check_vpn(ip_address, key):
    url = "https://vpnapi.io/api/" + ip_address + "?key=" + key
    req = requests.get(url)
    if(req.ok):
        return req.json()
    else:
        return "invalid vpnio response"
