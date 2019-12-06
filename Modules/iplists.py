"""
Author: Axel Robbe
Version: 0.1

This script checks given ip or domain names against online blacklists.
Minimal required Python version 3.3


"""

# import argparse
import ipaddress
import json
import requests

# import urllib


class userInput:
    def __init__(self, userInput):
        self.lookup = userInput
        self.version = 0

    def urlOrIP(self):
        # Test if it is an ip address, otherwise it must be a string, thus try as an URL.
        try:
            ip = ipaddress.ip_address(self.lookup)
            self.version = ip.version

        # If value error, then it cannot be an IP
        except ValueError:
            # valid_url = urllib.parse.urlparse(self.lookup)
            # print(valid_url)
            print("URLs are not (yet) supported")
            exit()

        except Exception as exc:
            print(exc)


class lookupLists:
    def __init__(self, name, desc, category, listURL, period):
        self.name = name
        self.desc = desc
        self.category = category
        self.listURL = listURL
        self.period = period

    def blacklistCheck(self, ipObjs):
        req = requests.get(self.listURL)
        if req.status_code == 200:
            lines = req.text.splitlines()

            # check if line matches with ip
            for line in lines:
                for ipObj in ipObjs:
                    if ipObj.lookup == line:
                        if not any(item.get(ipObj.lookup, None) for item in hitlist):
                            hitlist.append({ipObj.lookup: [self.name]})
                        else:
                            for index in range(0, len(hitlist)):
                                for key in hitlist[index]:
                                    if key == ipObj.lookup:
                                        hitlist[index][key].append(self.name)


hitlist = []
uniquehits = set()

userInputList = []

ipObjs = [userInput(entry) for entry in userInputList]
for ipObj in ipObjs:
    ipObj.urlOrIP()

with open("config/iplists.json") as settings:
    blacklists = json.load(settings)

blacklistObjs = [
    lookupLists(
        blacklist["name"],
        blacklist["desc"],
        blacklist["category"],
        blacklist["listURL"],
        blacklist["period"],
    )
    for blacklist in blacklists
]

for listObj in blacklistObjs:
    print("Checking " + listObj.name + "...")
    listObj.blacklistCheck(ipObjs)
    hit = 0
    for ipObj in ipObjs:
        for item in hitlist:
            if ipObj.lookup in item:
                print(str(ipObj.lookup) + " Found")
                hit = 1
    if hit == 1:
        print(listObj.name + ": " + listObj.desc + "\n")
