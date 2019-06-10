"""
Small Script developed to aid SOC analysts with sanitising and decoding urls, perform
dns / reverse dns lookups and automate reputation checks from ipdb.com via webscraping

Author: Connor Jackson

Contribuitors: Aaron J Copley for his ProofPoint Decoder code
    Proofpoint URL Decoder code: https://gist.github.com/aaronjcopley/65a5198bf7b35361fdd315e786be9b9d
"""

import urllib.parse
import html.parser
import re
import socket
from bs4 import BeautifulSoup
import requests
import sys
import lxml

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
    print(" OPTION 0: Exit Tool")

    menuChoice = input()
    print(menuChoice)

    if menuChoice == "1":
        print("\n --------------------------------- ")
        print("\n U R L   S A N I T I S E   T O O L ")
        print("\n --------------------------------- ")
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
        print("\n P R O O F P O I N T D E C O D E R ")
        print("\n --------------------------------- ")
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
        print("\n R E P U T A T I O N     C H E C K ")
        print("\n --------------------------------- ")

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
            print("\n R E V E R S E    D N S    T O O L ")
            print("\n --------------------------------- ")
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

    if (menuChoice == "0"):
        break







