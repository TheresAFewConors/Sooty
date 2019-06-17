
import hashlib
import html.parser
import re
import socket
import urllib.parse
from urllib.parse import unquote
import requests
from ipwhois import IPWhois
from os import system, name
from bs4 import BeautifulSoup
from tkinter import *
from tkinter import filedialog

API_KEY = 'Enter API Key Here'
menuChoice = 0

def switchMenu(choice):
    if choice == '1':
        urlSanitise()
    if choice == '2':
        decoderMenu()
    if choice == '3':
        repChecker()
    if choice == '4':
        dnsMenu()
    if choice == '5':
        hashMenu()

    if choice == '0':
        exit()

def clear():
    # for windows
    if name == 'nt':
        _ = system('cls')
    # for everything else
    else:
        _ = system('clear')

def decoderSwitch(choice):
    if choice == '1':
        proofPointDecoder()
    if choice == '2':
        urlDecoder()
    if choice == '0':
        mainMenu()

def dnsSwitch(choice):
    if choice == '1':
        reverseDnsLookup()
    if choice == '2':
        dnsLookup()
    if choice == '3':
        whoIs()

    if choice == '0':
        mainMenu()

def hashSwitch(choice):
    if choice == '1':
        hashFile()
    if choice == '2':
        hashRating()
    if choice == '3':
        hashAndFileUpload()
    if choice == '0':
        mainMenu()

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

def mainMenu():
    clear()
    print("\n --------------------------------- ")
    print("\n           S  O  O  T  Y           ")
    print("\n --------------------------------- ")
    print(" What would you like to do? ")
    print("\n OPTION 1: Sanitise URL For emails ")
    print(" OPTION 2: Decoders (PP, URL) ")
    print(" OPTION 3: Reputation Checker")
    print(" OPTION 4: DNS Tools")
    print(" OPTION 5: Hashing Function")
    print(" OPTION 0: Exit Tool")
    switchMenu(input())

def urlSanitise():
    print("\n --------------------------------- ")
    print(" U R L   S A N I T I S E   T O O L ")
    print(" --------------------------------- ")
    print("Enter URL to sanitize: ")
    url = input()
    x = re.sub("\.", "[.]", url)
    x = re.sub("http://", "hxxp://", x)
    x = re.sub("https://", "hxxps://", x)
    input("\n" + x)
    mainMenu()

def decoderMenu():
    print("\n --------------------------------- ")
    print("           D E C O D E R S        ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: ProofPoint Decoder")
    print(" OPTION 2: URL Decoder")
    print(" OPTION 0: Exit to Main Menu")
    decoderSwitch(input())

def proofPointDecoder():
    rewrittenurl = input(" Enter ProofPoint Link: ")
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

    mainMenu()

def urlDecoder():
    url = input('Enter url: ')
    decodedUrl = unquote(url)
    print(decodedUrl)
    mainMenu()

def repChecker():
    print("\n --------------------------------- ")
    print(" R E P U T A T I O N     C H E C K ")
    print(" --------------------------------- ")
    ip = input(" Enter IP / URL: ")

    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': API_KEY, 'ip': ip}
    response = requests.get(url, params=params)
    #print(response.status_code)

    pos = 0
    tot = 0
    if response.status_code == 200:
        try:    # try IP else fall through to URL
            result = response.json()
            for each in result['detected_urls']:
                tot = tot + 1
                pos = pos + each['positives']

            print("\n VirusTotal Report:")
            if tot != 0:
                print("   No of Reportings: " + str(tot))
                print("   Average Score:    " + str(pos / tot))
                print("   VirusTotal Report Link: " + "https://www.virustotal.com/gui/ip-address/" + str(ip))
            else:
                print("   No of Reportings: " + str(tot))
        except:
            try: #EAFP
                url = 'https://www.virustotal.com/vtapi/v2/url/report'
                params = {'apikey': API_KEY, 'resource': ip}
                response = requests.get(url, params=params)
                result = response.json()
                print("\n VirusTotal Report:")
                print("   URL Malicious Reportings: " + str(result['positives']) + "/" + str(result['total']))
                print("   VirusTotal Report Link: " + str(result['permalink']))  # gives URL for report (further info)
            except:
                print(" Not found in database")
    else:
        print(" There's been an error - check your API key, or VirusTotal is possible down")



    TOR_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
    req = requests.get(TOR_URL)
    print("\n TOR Exit Node Report: ")

    if req.status_code == 200:
        tl = req.text.split('\n')
        c = 0
        for i in tl:
            if ip == i:
                print("   " + i + " is a TOR Exit Node")
                c = c+1
        if c == 0:
            print("   No match found")

    else:
        print("   TOR LIST UNREACHABLE")

    mainMenu()

def dnsMenu():
    print("\n --------------------------------- ")
    print("         D N S    T O O L S        ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Reverse DNS Lookup")
    print(" OPTION 2: DNS Lookup")
    print(" OPTION 3: WHOIS Lookup")
    print(" OPTION 0: Exit to Main Menu")
    dnsSwitch(input())

def reverseDnsLookup():
    d = input(" Enter IP to check: ")
    try:
        s = socket.gethostbyaddr(d)
        print('\n ' + s[0])
    except:
        print(" Hostname not found")
    dnsMenu()

def dnsLookup():
    d = input(" Enter Domain Name to check: ")
    d = re.sub("http://", "", d)
    d = re.sub("https://", "", d)
    try:
        s = socket.gethostbyname(d)
        print('\n ' + s)
    except:
        print("Website not found")
    dnsMenu()

def whoIs():
    ip = input('ip: ')
    try:
        w = IPWhois(ip)
        w = w.lookup_whois()

        print("\n WHO IS REPORT \n")
        print(" CIDR:      " + str(w['nets'][0]['cidr']))
        print(" Name:      " + str(w['nets'][0]['name']))
        print(" Handle:    " + str(w['nets'][0]['handle']))
        print(" Range:     " + str(w['nets'][0]['range']))
        print(" Descr:     " + str(w['nets'][0]['description']))
        print(" Country:   " + str(w['nets'][0]['country']))
        print(" State:     " + str(w['nets'][0]['state']))
        print(" City:      " + str(w['nets'][0]['city']))
        print(" Address:   " + str(w['nets'][0]['address']))
        print(" Post Code: " + str(w['nets'][0]['postal_code']))
        print(" Emails:    " + str(w['nets'][0]['emails']))
        print(" Created:   " + str(w['nets'][0]['created']))
        print(" Updated:   " + str(w['nets'][0]['updated']))
    except:
        print(" IP Not Found")
    dnsMenu()

def hashMenu():
    print("\n --------------------------------- ")
    print(" H A S H I N G   F U N C T I O N S ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Hash a file")
    print(" OPTION 2: Check a hash for known malicious activity")
    print(" OPTION 3: Hash a file, check a hash for known malicious activity")
    print(" OPTION 0: Exit to Main Menu")
    hashSwitch(input())

def hashFile():
    root = Tk()
    root.filename = filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    print(" MD5 Hash: " + hasher.hexdigest())
    root.destroy()
    hashMenu()

def hashRating():
    count = 0
    # VT Hash Checker
    fileHash = input(" Enter Hash of file: ")
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': API_KEY, 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
        try:
            if result['positives'] != 0:
                print("\n Malware Detection")
                for key, value in result['scans'].items():
                    if value['detected'] == True:
                        count = count + 1
            print(" VirusTotal Report: " + str(count) + " detections found")
        except:
            print("\n Hash was not found in Malware Database")
    except:
        print("Error: Invalid API Key")
    hashMenu()

def hashAndFileUpload():
    root = Tk()
    root.filename = filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    print(" MD5 Hash: " + hasher.hexdigest())
    fileHash = hasher.hexdigest
    root.destroy()
    count = 0
    # VT Hash Checker
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': API_KEY, 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
        try:
            if result['positives'] != 0:
                print("\n Malware Detection")
                for key, value in result['scans'].items():
                    if value['detected'] == True:
                        count = count + 1
            print(" VirusTotal Report: " + str(count) + " detections found")
        except:
            print("\n Hash was not found in Malware Database")
    except:
        print(" Error: Invalid API Key")
    hashMenu()

if __name__ == '__main__':
    mainMenu()
