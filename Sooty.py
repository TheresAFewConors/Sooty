"""
    Title:      Sooty
    Desc:       The SOC Analysts all-in-one CLI tool to automate and speed up workflow.
    Author:     Connor Jackson
    Version:    1.3.2
    GitHub URL: https://github.com/TheresAFewConors/Sooty
"""

import base64
import hashlib
import html.parser
import re
import json
import time
import os
import socket
import strictyaml
import urllib.parse
import requests
from ipwhois import IPWhois
import tkinter
import tkinter.filedialog

from Modules import iplists
from Modules import phishtank
from Modules import TitleOpen

try:
    import win32com.client
except:
    print('Cant install Win32com package')

versionNo = '1.3.2'

try: 
    f = open("config.yaml", "r")
    configvars = strictyaml.load(f.read())
    f.close()
except FileNotFoundError:
    print("Config.yaml not found. Check the example config file and rename to 'config.yaml'.")

linksFoundList = []
linksRatingList = []
linksSanitized = []
linksDict = {}

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
    if choice == '6':
        phishingMenu()
    if choice == '7':
        urlscanio()
    if choice == '9':
        extrasMenu()
    if choice == '0':
        exit()
    else:
        mainMenu()

def decoderSwitch(choice):
    if choice == '1':
        proofPointDecoder()
    if choice == '2':
        urlDecoder()
    if choice == '3':
        safelinksDecoder()
    if choice == '4':
        unshortenUrl()
    if choice == '5':
        b64Decoder()
    if choice == '6':
        cisco7Decoder()
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
        hashText()
    if choice == '3':
        hashRating()
    if choice == '4':
        hashAndFileUpload()
    if choice == '0':
        mainMenu()

def phishingSwitch(choice):
    if choice == '1':
        analyzePhish()
    if choice == '2':
        analyzeEmailInput()
    if choice == '3':
        emailTemplateGen()
    if choice == '4':
        phishtankModule()
    if choice == '9':
        haveIBeenPwned()
    else:
        mainMenu()

def extrasSwitch(choice):
    if choice == '1':
        aboutSooty()
    if choice == '2':
        contributors()
    if choice == '3':
        extrasVersion()
    if choice == '4':
        wikiLink()
    if choice == '5':
        ghLink()
    else:
        mainMenu()

def decodev1(rewrittenurl):
    match = re.search(r'u=(.+?)&k=', rewrittenurl)
    if match:
        urlencodedurl = match.group(1)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        url = html.unescape(htmlencodedurl)
        url = re.sub("http://", "", url)
        if url not in linksFoundList:
            linksFoundList.append(url)

def decodev2(rewrittenurl):
    match = re.search(r'u=(.+?)&[dc]=', rewrittenurl)
    if match:
        specialencodedurl = match.group(1)
        trans = str.maketrans('-_', '%/')
        urlencodedurl = specialencodedurl.translate(trans)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        url = html.unescape(htmlencodedurl)
        url = re.sub("http://", "", url)
        if url not in linksFoundList:
            linksFoundList.append(url)

def titleLogo():
    TitleOpen.titleOpen()
    os.system('cls||clear')

def mainMenu():
    print("\n --------------------------------- ")
    print("\n           S  O  O  T  Y           ")
    print("\n --------------------------------- ")
    print(" What would you like to do? ")
    print("\n OPTION 1: Sanitise URL For emails ")
    print(" OPTION 2: Decoders (PP, URL, SafeLinks) ")
    print(" OPTION 3: Reputation Checker")
    print(" OPTION 4: DNS Tools")
    print(" OPTION 5: Hashing Function")
    print(" OPTION 6: Phishing Analysis")
    print(" OPTION 7: URL scan")
    print(" OPTION 9: Extras")
    print(" OPTION 0: Exit Tool")
    switchMenu(input())

def urlSanitise():
    print("\n --------------------------------- ")
    print(" U R L   S A N I T I S E   T O O L ")
    print(" --------------------------------- ")
    url = str(input("Enter URL to sanitize: ").strip())
    x = re.sub(r"\.", "[.]", url)
    x = re.sub("http://", "hxxp://", x)
    x = re.sub("https://", "hxxps://", x)
    print("\n" + x)
    mainMenu()

def decoderMenu():
    print("\n --------------------------------- ")
    print("           D E C O D E R S        ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: ProofPoint Decoder")
    print(" OPTION 2: URL Decoder")
    print(" OPTION 3: Office SafeLinks Decoder")
    print(" OPTION 4: URL unShortener")
    print(" OPTION 5: Base64 Decoder")
    print(" OPTION 6: Cisco Password 7 Decoder")
    print(" OPTION 0: Exit to Main Menu")
    decoderSwitch(input())

def proofPointDecoder():
    print("\n --------------------------------- ")
    print(" P R O O F P O I N T D E C O D E R ")
    print(" --------------------------------- ")
    rewrittenurl = str(input(" Enter ProofPoint Link: ").strip())
    match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', rewrittenurl)
    if match:
        if match.group(1) == 'v1':
            decodev1(rewrittenurl)
            for each in linksFoundList:
                print('\n Decoded Link: %s' % each)
        elif match.group(1) == 'v2':
            decodev2(rewrittenurl)
            for each in linksFoundList:
                print('\n Decoded Link: %s' % each)
        else:
            print('Unrecognized version in: ', rewrittenurl)
    else:
        print(' No valid URL found in input: ', rewrittenurl)

    mainMenu()

def urlDecoder():
    print("\n --------------------------------- ")
    print("       U R L   D E C O D E R      ")
    print(" --------------------------------- ")
    url = str(input(' Enter URL: ').strip())
    decodedUrl = urllib.parse.unquote(url)
    print(decodedUrl)
    mainMenu()

def safelinksDecoder():
    print("\n --------------------------------- ")
    print(" S A F E L I N K S   D E C O D E R  ")
    print(" --------------------------------- ")
    url = str(input(' Enter URL: ').strip())
    dcUrl = urllib.parse.unquote(url)
    dcUrl = dcUrl.replace('https://nam02.safelinks.protection.outlook.com/?url=', '')
    print(dcUrl)
    mainMenu()

def urlscanio():    
    print("\n --------------------------------- ")
    print("\n        U R L S C A N . I O        ")
    print("\n --------------------------------- ")
    url_to_scan = str(input('\nEnter url: ').strip())
    
    headers = {
        'Content-Type': 'application/json',
        'API-Key': configvars.data['URLSCAN_IO_KEY'],
        }

    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data='{"url": "%s", "public": "on" }' % url_to_scan).json()

    try:
        if 'successful' in response['message']:
            print('\nNow scanning %s. Check back in around 1 minute.' % url_to_scan)
            uuid_variable = str(response['uuid']) # uuid, this is the factor that identifies the scan
            time.sleep(45) # sleep for 45 seconds. The scan takes awhile, if we try to retrieve the scan too soon, it will return an error.
            scan_results = requests.get('https://urlscan.io/api/v1/result/%s/' % uuid_variable).json() # retrieving the scan using the uuid for this scan

            task_url = scan_results['task']['url']
            verdicts_overall_score = scan_results['verdicts']['overall']['score']
            verdicts_overall_malicious = scan_results['verdicts']['overall']['malicious']
            task_report_URL = scan_results['task']['reportURL']

            print("\nurlscan.io Report:")
            print("\nURL: " + task_url)
            print("\nOverall Verdict: " + str(verdicts_overall_score))
            print("Malicious: " + str(verdicts_overall_malicious))
            print("urlscan.io: " + str(scan_results['verdicts']['urlscan']['score']))
            if scan_results['verdicts']['urlscan']['malicious']:
                print("Malicious: " + str(scan_results['verdicts']['urlscan']['malicious'])) # True
            if scan_results['verdicts']['urlscan']['categories']:
                print("Categories: ")
            for line in scan_results['verdicts']['urlscan']['categories']:
                print("\t"+ str(line)) # phishing
            for line in scan_results['verdicts']['engines']['verdicts']:
                print(str(line['engine']) + " score: " + str(line['score'])) # googlesafebrowsing
                print("Categories: ")
                for item in line['categories']:
                    print("\t" + item) # social_engineering
            print("\nSee full report for more details: " + str(task_report_URL))
            print('')
        else:
            print(response['message'])
    except:
        print(' Error reaching URLScan.io')

def unshortenUrl():
    print("\n --------------------------------- ")
    print("   U R L   U N S H O R T E N E R  ")
    print(" --------------------------------- ")
    link = str(input(' Enter URL: ').strip())
    req = requests.get(str('https://unshorten.me/s/' + link))
    print(req.text)

    decoderMenu()

def b64Decoder():
    url = str(input(' Enter URL: ').strip())

    try:
        b64 = str(base64.b64decode(url))
        a = re.split("'", b64)[1]
        print(" B64 String:     " + url)
        print(" Decoded String: " + a)
    except:
        print(' No Base64 Encoded String Found')

    decoderMenu()

def cisco7Decoder():
    pw = input(' Enter Cisco Password 7: ').strip()

    key = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
    0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
    0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42]

    try:
        # the first 2 characters of the password are the starting index in the key array
        index = int(pw[:2],16)

        # the remaining values are the characters in the password, as hex bytes
        pw_text = pw[2:]
        pw_hex_values = [pw_text[start:start+2] for start in range(0,len(pw_text),2)]

        # XOR those values against the key values, starting at the index, and convert to ASCII
        pw_chars = [chr(key[index+i] ^ int(pw_hex_values[i],16)) for i in range(0,len(pw_hex_values))]

        pw_plaintext = ''.join(pw_chars)
        print("Password: " + pw_plaintext)

    except Exception as e:
        print(e)

    decoderMenu()

def repChecker():
    print("\n --------------------------------- ")
    print(" R E P U T A T I O N     C H E C K ")
    print(" --------------------------------- ")
    rawInput = input("Enter IP, URL or Email Address: ").split()
    ip = str(rawInput[0])

    s = re.findall(r'\S+@\S+', ip)
    if s:
        print(' Email Detected...')
        analyzeEmail(''.join(s))
    else:

        whoIsPrint(ip)
        wIP = socket.gethostbyname(ip)

        print("\n VirusTotal Report:")
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': configvars.data['VT_API_KEY'], 'ip': wIP}
        response = requests.get(url, params=params)

        pos = 0
        tot = 0
        if response.status_code == 200:
            try:    # try IP else fall through to URL
                result = response.json()
                for each in result['detected_urls']:
                    tot = tot + 1
                    pos = pos + each['positives']

                if tot != 0:
                    print("   No of Reportings: " + str(tot))
                    print("   Average Score:    " + str(pos / tot))
                    print("   VirusTotal Report Link: " + "https://www.virustotal.com/gui/ip-address/" + str(ip))
                else:
                    print("   No of Reportings: " + str(tot))
            except:
                try: #EAFP
                    url = 'https://www.virustotal.com/vtapi/v2/url/report'
                    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': wIP}
                    response = requests.get(url, params=params)
                    result = response.json()
                    print("\n VirusTotal Report:")
                    print("   URL Malicious Reportings: " + str(result['positives']) + "/" + str(result['total']))
                    print("   VirusTotal Report Link: " + str(result['permalink']))  # gives URL for report (further info)
                except:
                    print(" Not found in database")
        else:
            print(" There's been an error - check your API key, or VirusTotal is possible down")

        try:
            TOR_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
            req = requests.get(TOR_URL)
            print("\n TOR Exit Node Report: ")
            if req.status_code == 200:
                tl = req.text.split('\n')
                c = 0
                for i in tl:
                    if wIP == i:
                        print("  " + i + " is a TOR Exit Node")
                        c = c+1
                if c == 0:
                    print("  " + wIP + " is NOT a TOR Exit Node")
            else:
                print("   TOR LIST UNREACHABLE")
        except Exception as e:
            print("There is an error with checking for Tor exit nodes:\n" + str(e))


        print("\n Checking BadIP's... ")
        try:
            BAD_IPS_URL = 'https://www.badips.com/get/info/' + wIP
            response = requests.get(BAD_IPS_URL)
            if response.status_code == 200:
                result = response.json()

                sc = result['Score']['ssh']
                print("  " + str(result['suc']))
                print("  Score: " + str(sc))
            else:
                print('  Error reaching BadIPs')
        except:
            print('  IP not found')

        print("\n ABUSEIPDB Report:")
        try:
            AB_URL = 'https://api.abuseipdb.com/api/v2/check'
            days = '180'

            querystring = {
                'ipAddress': wIP,
                'maxAgeInDays': days
            }

            headers = {
                'Accept': 'application/json',
                'Key': configvars.data['AB_API_KEY']
            }
            response = requests.request(method='GET', url=AB_URL, headers=headers, params=querystring)
            if response.status_code == 200:
                req = response.json()

                print("   IP:          " + str(req['data']['ipAddress']))
                print("   Reports:     " + str(req['data']['totalReports']))
                print("   Abuse Score: " + str(req['data']['abuseConfidenceScore']) + "%")
                print("   Last Report: " + str(req['data']['lastReportedAt']))
            else:
                print("   Error Reaching ABUSE IPDB")
        except:
                print('   IP Not Found')
        
        print("\n\nChecking against IP blacklists: ")
        iplists.main(rawInput)

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
    d = str(input(" Enter IP to check: ").strip())
    try:
        s = socket.gethostbyaddr(d)
        print('\n ' + s[0])
    except:
        print(" Hostname not found")
    dnsMenu()

def dnsLookup():
    d = str(input(" Enter Domain Name to check: ").strip())
    d = re.sub("http://", "", d)
    d = re.sub("https://", "", d)
    try:
        s = socket.gethostbyname(d)
        print('\n ' + s)
    except:
        print("Website not found")
    dnsMenu()

def whoIs():
    ip = str(input(' Enter IP / Domain: ').strip())
    whoIsPrint(ip)

    dnsMenu()

def whoIsPrint(ip):
    try:
        w = IPWhois(ip)
        w = w.lookup_whois()
        addr = str(w['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n WHO IS REPORT:")
        print("  CIDR:      " + str(w['nets'][0]['cidr']))
        print("  Name:      " + str(w['nets'][0]['name']))
       # print("  Handle:    " + str(w['nets'][0]['handle']))
        print("  Range:     " + str(w['nets'][0]['range']))
        print("  Descr:     " + str(w['nets'][0]['description']))
        print("  Country:   " + str(w['nets'][0]['country']))
        print("  State:     " + str(w['nets'][0]['state']))
        print("  City:      " + str(w['nets'][0]['city']))
        print("  Address:   " + addr)
        print("  Post Code: " + str(w['nets'][0]['postal_code']))
       # print("  Emails:    " + str(w['nets'][0]['emails']))
        print("  Created:   " + str(w['nets'][0]['created']))
        print("  Updated:   " + str(w['nets'][0]['updated']))
        c = 0
    except:
        print("\n  IP Not Found - Checking Domains")
        ip = re.sub('https://', '', ip)
        ip = re.sub('http://', '', ip)
        try:
            if c == 0:
                s = socket.gethostbyname(ip)
                print( '  Resolved Address: %s' % s)
                c = 1
                whoIsPrint(s)
        except:
            print(' IP or Domain not Found')
    return

def hashMenu():
    print("\n --------------------------------- ")
    print(" H A S H I N G   F U N C T I O N S ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Hash a file")
    print(" OPTION 2: Input and hash text")
    print(" OPTION 3: Check a hash for known malicious activity")
    print(" OPTION 4: Hash a file, check a hash for known malicious activity")
    print(" OPTION 0: Exit to Main Menu")
    hashSwitch(input())

def hashFile():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    print(" MD5 Hash: " + hasher.hexdigest())
    root.destroy()
    hashMenu()

def hashText():
    userinput = input(" Enter the text to be hashed: ")
    print(" MD5 Hash: " + hashlib.md5(userinput.encode("utf-8")).hexdigest())
    hashMenu()

def hashRating():
    apierror = False
    # VT Hash Checker
    fileHash = str(input(" Enter Hash of file: ").strip())
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except:
        apierror = True
        print("Error: Invalid API Key")
    
    if not apierror:
        if result['response_code'] == 0:
            print("\n Hash was not found in Malware Database")
        elif result['response_code'] == 1:
            print(" VirusTotal Report: " + str(result['positives']) + "/" + str(result['total']) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        else:
            print("No Reponse")
    hashMenu()

def hashAndFileUpload():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    fileHash = hasher.hexdigest()
    print(" MD5 Hash: " + fileHash)
    root.destroy()
    apierror = False
    # VT Hash Checker
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except:
        apierror = True
        print("Error: Invalid API Key")
    if not apierror:
        if result['response_code'] == 0:
            print("\n Hash was not found in Malware Database")
        elif result['response_code'] == 1:
            print(" VirusTotal Report: " + str(result['positives']) + "/" + str(result['total']) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        else:
            print("No Response")
    hashMenu()

def phishingMenu():
    print("\n --------------------------------- ")
    print("          P H I S H I N G          ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Analyze an Email ")
    print(" OPTION 2: Analyze an Email Address for Known Activity")
    print(" OPTION 3: Generate an Email Template based on Analysis")
    print(" OPTION 4: Analyze an URL with Phishtank")
    print(" OPTION 9: HaveIBeenPwned")
    print(" OPTION 0: Exit to Main Menu")
    phishingSwitch(input())

def analyzePhish():
    try:
        file = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
        with open(file, encoding='Latin-1') as f:
            msg = f.read()

        # Fixes issue with file name / dir name exceptions
        file = file.replace('//', '/')  # dir
        file2 = file.replace(' ', '')   # file name (remove spaces / %20)
        os.rename(file, file2)
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        msg = outlook.OpenSharedItem(file)
    except:
        print(' Error Opening File')

    print("\n Extracting Headers...")
    try:
        print("   FROM:      ", str(msg.SenderName), ", ", str(msg.SenderEmailAddress))
        print("   TO:        ", str(msg.To))
        print("   SUBJECT:   ", str(msg.Subject))
        print("   NameBehalf:", str(msg.SentOnBehalfOfName))
        print("   CC:        ", str(msg.CC))
        print("   BCC:       ", str(msg.BCC))
        print("   Sent On:   ", str(msg.SentOn))
        print("   Created:   ", str(msg.CreationTime))
        s = str(msg.Body)
    except:
        print('   Header Error')
        f.close()

    print("\n Extracting Links... ")
    try:
        match = r"((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))"
        a = re.findall(match, msg.Body, re.M | re.I)
        for b in a:
            match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', b[0])
            if match:
                if match.group(1) == 'v1':
                    decodev1(b[0])
                elif match.group(1) == 'v2':
                    decodev2(b[0])
            else:
                if b[0] not in linksFoundList:
                    linksFoundList.append(b[0])
        if len(a) == 0:
            print(' No Links Found...')
    except:
        print('   Links Error')
        f.close()

    for each in linksFoundList:
        print('   %s' % each)

    print("\n Extracting Emails Addresses... ")
    try:
        match = r'([\w0-9._-]+@[\w0-9._-]+\.[\w0-9_-]+)'
        emailList = list()
        a = re.findall(match, s, re.M | re.I)

        for b in a:
            if b not in emailList:
                emailList.append(b)
                print(" ", b)
            if len(emailList) == 0:
                print('   No Emails Found')

        if len(a) == 0:
            print('   No Emails Found...')
    except:
        print('   Emails Error')
        f.close()

    print("\n Extracting IP's...")
    try:
        ipList = []
        foundIP = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)
        ipList.append(foundIP)

        if not ipList:
            for each in ipList:
                print(each)
        else:
            print('   No IP Addresses Found...')
    except:
        print('   IP error')

    try:
        analyzeEmail(msg.SenderEmailAddress)
    except:
        print('')

    phishingMenu()

def haveIBeenPwned():
    print("\n --------------------------------- ")
    print(" H A V E   I   B E E N   P W N E D  ")
    print(" --------------------------------- ")

    try:
        acc = str(input(' Enter email: ').strip())
        haveIBeenPwnedPrintOut(acc)
    except:
        print('')
    phishingMenu()

def haveIBeenPwnedPrintOut(acc):
    try:
        url = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s' % acc
        userAgent = 'Sooty'
        headers = {'Content-Type': 'application/json', 'hibp-api-key': configvars.data['HIBP_API_KEY'], 'user-agent': userAgent}
        try:
            req = requests.get(url, headers=headers)
            response = req.json()
            lr = len(response)
            if lr != 0:
                print('\n The account has been found in the following breaches: ')
                for each in range(lr):
                    breach = 'https://haveibeenpwned.com/api/v3/breach/%s' % response[each]['Name']
                    breachReq = requests.get(breach, headers=headers)
                    breachResponse = breachReq.json()

                    breachList = []
                    print('\n   Title:        %s' % breachResponse['Title'])
                    print('   Domain:       %s' % breachResponse['Domain'])
                    print('   Breach Date:  %s' % breachResponse['BreachDate'])
                    print('   Pwn Count:    %s' % breachResponse['PwnCount'])
                    for each in breachResponse['DataClasses']:
                        breachList.append(each)
                    print('   Data leaked: %s' % breachList)
        except:
            print(' No Entries found in Database')
    except:
        print('')

def analyzeEmailInput():
    print("\n --------------------------------- ")
    print("    E M A I L   A N A L Y S I S    ")
    print(" --------------------------------- ")
    try:
        email = str(input(' Enter Email Address to Analyze: ').strip())
        analyzeEmail(email)
        phishingMenu()
    except:
        print("   Error Scanning Email Address")

def analyzeEmail(email):

    try:
        url = 'https://emailrep.io/'
        summary = '?summary=true'
        url = url + email + summary
        response = requests.get(url)
        req = response.json()
        emailDomain = re.split('@', email)[1]

        print('\n Email Analysis Report ')
        if response.status_code == 400:
            print(' Invalid Email / Bad Request')
        if response.status_code == 401:
            print(' Unauthorized / Invalid API Key (for Authenticated Requests)')
        if response.status_code == 429:
            print(' Too many requests, ')
        if response.status_code == 200:
            print('   Email:       %s' % req['email'])
            print('   Reputation:  %s' % req['reputation'])
            print('   Suspicious:  %s' % req['suspicious'])
            print('   Spotted:     %s' % req['references'] + ' Times')
            print('   Blacklisted: %s' % req['details']['blacklisted'])
            print('   Last Seen:   %s' % req['details']['last_seen'])
            print('   Known Spam:  %s' % req['details']['spam'])

            print('\n Domain Report ')
            print('   Domain:        @%s' % emailDomain)
            print('   Domain Exists: %s' % req['details']['domain_exists'])
            print('   Domain Rep:    %s' % req['details']['domain_reputation'])
            print('   Domain Age:    %s' % req['details']['days_since_domain_creation'] + ' Days')
            print('   New Domain:    %s' % req['details']['new_domain'])
            print('   Deliverable:   %s' % req['details']['deliverable'])
            print('   Free Provider: %s' % req['details']['free_provider'])
            print('   Disposable:    %s' % req['details']['disposable'])
            print('   Spoofable:     %s' % req['details']['spoofable'])

            print('\n Malicious Activity Report ')
            print('   Malicious Activity: %s' % req['details']['malicious_activity'])
            print('   Recent Activity:    %s' % req['details']['malicious_activity_recent'])
            print('   Credentials Leaked: %s' % req['details']['credentials_leaked'])
            print('   Found in breach:    %s' % req['details']['data_breach'])

            if (req['details']['data_breach']):
                try:
                    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s' % email
                    userAgent = 'Sooty'
                    headers = {'Content-Type': 'application/json', 'hibp-api-key': configvars.data['HIBP_API_KEY'], 'user-agent': userAgent}

                    try:
                        reqHIBP = requests.get(url, headers=headers)
                        response = reqHIBP.json()
                        lr = len(response)
                        if lr != 0:
                            print('\nThe account has been found in the following breaches: ')
                            for each in range(lr):
                                breach = 'https://haveibeenpwned.com/api/v3/breach/%s' % response[each]['Name']
                                breachReq = requests.get(breach, headers=headers)
                                breachResponse = breachReq.json()
                                breachList = []
                                print('   Title:        %s' % breachResponse['Title'])
                                print('   Breach Date:  %s' % breachResponse['BreachDate'])

                                for each in breachResponse['DataClasses']:
                                    breachList.append(each)
                                print('   Data leaked: %s' % breachList,'\n')
                    except:
                        print(' Error')
                except:
                    print(' No API Key Found')
            print('\n Profiles Found ')
            if (len(req['details']['profiles']) != 0):
                profileList = (req['details']['profiles'])
                for each in profileList:
                    print('   - %s' % each)
            else:
                print('   No Profiles Found For This User')

            print('\n Summary of Report: ')
            repSum = req['summary']
            repSum = re.split(r"\.\s*", repSum)
            for each in repSum:
                print('   %s' % each)

    except:
        print(' Error Analyzing Submitted Email')

def virusTotalAnalyze(result, sanitizedLink):
    linksDict['%s' % sanitizedLink] = str(result['positives'])
    #print(str(result['positives']))

def emailTemplateGen():
    print('\n--------------------')
    print('  Phishing Response')
    print('--------------------')

    try:
        file = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
        with open(file, encoding='Latin-1') as f:
            msg = f.read()
        file = file.replace('//', '/')  # dir
        file2 = file.replace(' ', '')  # file name (remove spaces / %20)
        os.rename(file, file2)
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        msg = outlook.OpenSharedItem(file)
    except:
        print(' Error importing email for template generator')

    url = 'https://emailrep.io/'
    email = msg.SenderEmailAddress
    url = url + email
    responseRep = requests.get(url)
    req = responseRep.json()
    f = msg.To.split(' ', 1)[0]

    try:
        match = r"((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))"
        a = re.findall(match, msg.Body, re.M | re.I)
        for b in a:
            match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', b[0])
            if match:
                if match.group(1) == 'v1':
                    decodev1(b[0])
                elif match.group(1) == 'v2':
                    decodev2(b[0])
            else:
                if b[0] not in linksFoundList:
                    linksFoundList.append(b[0])
        if len(a) == 0:
            print(' No Links Found...')
    except:
        print('   Links Error')
        f.close()

    for each in linksFoundList:
        x = re.sub(r"\.", "[.]", each)
        x = re.sub("http://", "hxxp://", x)
        x = re.sub("https://", "hxxps://", x)
        sanitizedLink = x

    if 'API Key' not in configvars.data['VT_API_KEY']:
        try:  # EAFP
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            for each in linksFoundList:
                link = each
                params = {'apikey': configvars.data['VT_API_KEY'], 'resource': link}
                response = requests.get(url, params=params)
                result = response.json()
                if response.status_code == 200:
                    virusTotalAnalyze(result, sanitizedLink)

        except:
            print("\n Threshold reached for VirusTotal: "
                  "\n   60 seconds remaining...")
            time.sleep(15)
            print('   45 seconds remaining...')
            time.sleep(15)
            print('   30 seconds remaining...')
            time.sleep(15)
            print('   15 seconds remaining...')
            time.sleep(15)
            virusTotalAnalyze(result, sanitizedLink)
    else:
        print('No API Key set, results will not show malicious links')

    rc = 'potentially benign'
    threshold = '1'

    if req['details']['spam'] or req['suspicious'] or req['details']['blacklisted'] or req['details']['malicious_activity']:
        rc = 'potentially suspicious'

    for key, value in linksDict.items():
        if int(value) >= int(threshold):
            rc = 'potentially malicious'

    if responseRep.status_code == 200:
        print('\nHi %s,' % f,)
        print('\nThanks for your recent submission.')
        print('\nI have completed my analysis of the submitted mail and have classed it is as %s.' % rc)
        print('\nThe sender has a reputation score of %s,' % req['reputation'], 'for the following reasons: ')

        if req['details']['spam']:
            print(' - The sender has been reported for sending spam in the past.')
        if req['suspicious']:
            print(' - It has been marked as suspicious on reputation checking websites.')
        if req['details']['free_provider']:
            print(' - The sender is using a free provider.')
        if req['details']['days_since_domain_creation'] < 365:
            print(' - The domain is less than a year old.')
        if req['details']['blacklisted']:
            print(' - It has been blacklisted on several sites.')
        if req['details']['data_breach']:
            print(' - Has been seen in data breaches')
        if req['details']['credentials_leaked']:
            print(' - The credentials have been leaked for this address')
        if req['details']['malicious_activity']:
            print(' - This sender has been flagged for malicious activity.')

        malLink = 0     # Controller for mal link text
        for each in linksDict.values():
            if int(threshold) <= int(each):
                malLink = 1

        if malLink == 1:
            print('\nThe following potentially malicious links were found embedded in the body of the mail:')
            for key, value in linksDict.items():
                if int(value) >= int(threshold):
                    print(' - %s' % key)

        print('\nAs such, I would recommend the following: ')

        if 'suspicious' in rc:
            print(' - Delete and Ignore the mail for the time being.')

        if 'malicious' in rc:
            print(' - If you clicked any links or entered information into any displayed webpages let us know asap.')

        if 'spam' in rc:
            print(' - If you were not expecting the mail, please delete and ignore.')
            print(' - We would advise you to use your email vendors spam function to block further mails.')

        if 'task' in rc:
            print(' - If you completed any tasks asked of you, please let us know asap.')
            print(' - If you were not expecting the mail, please delete and ignore.')

        if 'benign' in rc:
            print(' - If you were not expecting this mail, please delete and ignore.')
            print('\nIf you receive further mails from this sender, you can use your mail vendors spam function to block further mails.')

        if 'suspicious' or 'malicious' or 'task' in rc:
            print('\nI will be reaching out to have this sender blocked to prevent the sending of further mails as part of our remediation effort.')
            print('For now, I would recommend to simply delete and ignore this mail.')
            print('\nWe appreciate your diligence in reporting this mail.')

        print('\nRegards,')

def phishtankModule():
    if "phishtank" in configvars.data:
        url = input(' Enter the URL to be checked: ').strip()
        download, appname, api = (
            configvars.data["phishtank"]["download"],
            configvars.data["phishtank"]["appname"],
            configvars.data["phishtank"]["api"],
        )
        phishtank.main(download, appname, api, url)
    else:
        print("Missing configuration for phishtank in the config.yaml file.")

def extrasMenu():
    print("\n --------------------------------- ")
    print("            E X T R A S            ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: About SOOTY ")
    print(" OPTION 2: Contributors ")
    print(" OPTION 3: Version")
    print(" OPTION 4: Wiki")
    print(" OPTION 5: GitHub Repo")
    print(" OPTION 0: Exit to Main Menu")
    extrasSwitch(input())

def aboutSooty():
    print(' SOOTY is a tool developed and targeted to help automate some tasks that SOC Analysts perform.')
    extrasMenu()

def contributors():
    print(' CONTRIBUTORS')
    print(" Aaron J Copley for his code to decode ProofPoint URL's")
    print(" James Duarte for adding a hash and auto-check option to the hashing function ")
    print(" mrpnkt for adding the missing whois requirement to requirements.txt")
    print(" Gurulhu for adding the Base64 Decoder to the Decoders menu.")
    print(" AndThenEnteredAlex for adding the URLScan Function from URLScan.io")
    print(" Eric Kelson for fixing pywin32 requirement not necessary on Linux systems in requirements.txt.")
    print(" Jenetiks for removing and tidying up duplicate imports that had accumulated over time.")
    print(" Nikosch86 for fixing an issue with Hexdigest not storing hashes correctly")
    print(" Naveci for numerous bug fixes, QoL improvements, and Cisco Password 7 Decoding, and introduced a workflow to helps with issues in future. Phishtank support has now also been added.")
    print(" Paralax for fixing typos in the readme")
    print(" MrMeeseeks2014 fox fixing a bug relating to hash uploads")
    extrasMenu()

def extrasVersion():
    print(' Current Version: ' + versionNo)
    extrasMenu()

def wikiLink():
    print('\n The Sooty Wiki can be found at the following link:')
    print(' https://github.com/TheresAFewConors/Sooty/wiki')
    extrasMenu()

def ghLink():
    print('\n The Sooty Repo can be found at the following link:')
    print(' https://github.com/TheresAFewConors/Sooty')
    extrasMenu()

if __name__ == '__main__':
    titleLogo()
    mainMenu()
