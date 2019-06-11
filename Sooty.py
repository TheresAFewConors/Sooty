"""
Small Script developed to aid SOC analysts with sanitising and decoding urls, perform
dns / reverse dns lookups and automate reputation checks from ipdb.com via webscraping
"""

import hashlib
import html.parser
import re
import socket
import urllib.parse

import requests
from bs4 import BeautifulSoup

from tkinter import *
from tkinter import filedialog

API_KEY = 'Enter API key here'
menuChoice = 0

while int(menuChoice) == 0:
    print("\n --------------------------------- ")
    print("\n           S  O  O  T  Y           ")
    print("\n --------------------------------- ")

    print(" What would you like to do? ")
    print("\n OPTION 1: Sanitise URL For emails ")
    print(" OPTION 2: Decode ProofPoint URLs ")
    print(" OPTION 3: Reputation Checker")
    print(" OPTION 4: DNS Tools")
    print(" OPTION 5: Hashing Function")
    print(" OPTION 0: Exit Tool")

    menuChoice = input()
    print(menuChoice)

    if menuChoice == "1":
        print("\n --------------------------------- ")
        print(" U R L   S A N I T I S E   T O O L ")
        print(" --------------------------------- ")
        print("Enter URL to sanitize: ")
        url = input()
        x = re.sub("\.", "[.]", url)
        x = re.sub("http://", "hxxp://", x)
        x = re.sub("https://", "hxxps://", x)
        print("\n" + x)
        menuChoice = 0

    if menuChoice == "2":

        def decodev1(rewrittenurl):
            match = re.search(r'u=(.+?)&k=', rewrittenurl)
            if match:
                urlencodedurl = match.group(1)
                htmlencodedurl = urllib.parse.unquote(urlencodedurl)
                url = html.unescape(htmlencodedurl)
                url = re.sub("http://", "", url)
                print(url)
            else:
                print('Error parsing URL')

        def decodev2(rewrittenurl):
            match = re.search(r'u=(.+?)&[dc]=', rewrittenurl)
            if match:
                specialencodedurl = match.group(1)
                trans = str.maketrans('-_', '%/')
                urlencodedurl = specialencodedurl.translate(trans)
                htmlencodedurl = urllib.parse.unquote(urlencodedurl)
                url = html.unescape(htmlencodedurl)
                url = re.sub("http://", "", url)
                print("\n" + url)
            else:
                print('Error parsing URL')

        print("\n --------------------------------- ")
        print(" P R O O F P O I N T D E C O D E R ")
        print(" --------------------------------- ")
        print("Enter Proofpoint URL: ")
        rewrittenurl = input()
        match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', rewrittenurl)
        if match:
            if match.group(1) == 'v1':
                decodev1(rewrittenurl)
            elif match.group(1) == 'v2':
                decodev2(rewrittenurl)
            else:
                print('Unrecognized version in: ', rewrittenurl)
        else:
            print('No valid URL found in input: ', rewrittenurl)

        menuChoice = 0

    if menuChoice == "3":
        print("\n --------------------------------- ")
        print(" R E P U T A T I O N     C H E C K ")
        print(" --------------------------------- ")

        try:
            ip = input(" Enter IP: ")
            url = 'https://www.abuseipdb.com/check/' + ip
            response = requests.get(url)
            content = BeautifulSoup(response.text, 'lxml')

            links = content.findAll('b')
            links2 = content.findAll('td')
            links3 = content.findAll('time')

            # REGEX
            report_count = str(links[6])
            report_count = report_count.split('<b>')[-1]
            report_count = report_count.split('</b>')[0]
            abuse_conf = str(links[7])
            abuse_conf = abuse_conf.split('<b>')[-1]
            abuse_conf = abuse_conf.split('</b>')[0]
            city = str(links2[5])
            city = city.split('<td>')[-1]
            city = city.split('</td>')[0]
            city = re.sub(r"(?<=[a-z])\r?\n", "", city)
            country = (str(links2[4]))
            country = country.split('src="/img/blank.gif"/>')[-1]
            country = country.split('</td>')[0]
            country = re.sub(r"(?<=[a-z])\r?\n", "", country)
            time1 = str(links3[0])
            time1 = time1.split('</time>')[0]
            time1 = time1.split('">')[-1]
            time2 = str(links[10])
            time2 = time2.split('</time>')[0]
            time2 = time2.split('">')[-1]

            print(" Country: " + country)
            print(" City: " + city)
            print(" IP Reported: " + report_count + " times")
            print(" Abuse Confidence: " + abuse_conf)
            print(" First Reported: " + time1)
            print(" Last Reported: " + time2)
        except:
            print(" IP not valid")

        menuChoice = 0

    if menuChoice == "4":
        dnsMenuChoice = 0
        while int(dnsMenuChoice) == 0:
            print("\n --------------------------------- ")
            print(" R E V E R S E    D N S    T O O L ")
            print(" --------------------------------- ")
            print(" What would you like to do? ")
            print(" OPTION 1: Reverse DNS Lookup")
            print(" OPTION 2: Get Website IP ")
            print(" OPTION 0: Exit")
            dnsMenuChoice = input()

            if dnsMenuChoice == "1":
                d = input(" Enter IP to check: ")
                try:
                    s = socket.gethostbyaddr(d)
                    print('\n ' + s[0])
                except:
                    print(" Hostname not found")

            if dnsMenuChoice == "2":
                d = input(" Enter Domain Name to check: ")
                d = re.sub("http://", "", d)
                d = re.sub("https://", "", d)
                try:
                    s = socket.gethostbyname(d)
                    print('\n ' + s)
                except:
                    print("Website not found")

            if dnsMenuChoice == "0":
                menuChoice = 0
                break

            menuChoice = 0

    if menuChoice == "5":
        hashMenuChoice = 0
        while int(hashMenuChoice) == 0:
            print("\n --------------------------------- ")
            print(" H A S H I N G   F U N C T I O N S ")
            print(" --------------------------------- ")
            print(" What would you like to do? ")
            print(" OPTION 1: Hash a file")
            print(" OPTION 2: Check a hash for known malicious activity")
            print(" OPTION 0: Exit")
            hashMenuChoice = input("")

            if hashMenuChoice == "1":
                root = Tk()
                root.filename = filedialog.askopenfilename(initialdir="/", title="Select file")
                hasher = hashlib.md5()
                with open(root.filename, 'rb') as afile:
                    buf = afile.read()
                    hasher.update(buf)
                print(" MD5 Hash: " + hasher.hexdigest())
                hashMenuChoice = 0

            if hashMenuChoice == "2":
                count = 0
                # VT Hash Checker
                fileHash = input("Enter Hash of file: ")
                url = 'https://www.virustotal.com/vtapi/v2/file/report'

                params = {'apikey': API_KEY, 'resource': fileHash}
                response = requests.get(url, params=params)

                try:    # EAFP
                    result = response.json()
                    try:
                        if result['positives'] != 0:
                            print("Malware Detection")
                            for key, value in result['scans'].items():
                                if value['detected'] == True:
                                    count = count + 1
                            print("VirusTotal Rank: " + str(count) + " detections found")
                    except:
                        print("No Malware Detected")

                except:
                    print("Invalid API Key")
                    hashMenuChoice = 0

            if hashMenuChoice == "0":
                menuChoice = 0
                break

    if (menuChoice == "0"):
        break