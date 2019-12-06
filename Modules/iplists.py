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
        self.hitlist = []
        req = requests.get(self.listURL)
        if req.status_code == 200:
            lines = req.text.splitlines()

            # check if line matches with ip
            for line in lines:
                for ipObj in ipObjs:
                    if ipObj.lookup == line:
                        self.hitlist.append(ipObj.lookup)

    def reporter(self):
        if len(self.hitlist) != 0:
            print("\nFound hits in " + listObj.name + ": " + listObj.desc)
        for ipObj in ipObjs:
            for item in self.hitlist:
                if ipObj.lookup in item:
                    print(str(ipObj.lookup))


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

print("\nResults:\n")
for listObj in blacklistObjs:
    listObj.reporter()

