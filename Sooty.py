"""
    Title:      Sooty
    Desc:       The SOC Analysts all-in-one CLI tool to automate and speed up workflow.
    Author:     Connor Jackson
    Version:    1.26
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
import urllib.parse
from urllib.parse import unquote
import requests
from ipwhois import IPWhois
from tkinter import *
from tkinter import filedialog

try:
    import win32com.client
except:
    print('Cant install package')

versionNo = '1.26'

VT_API_KEY = 'Enter VirusTotal API Key Here'
AB_API_KEY = 'Enter AbuseIPDB API Key Here'
URLSCAN_IO_KEY = 'Enter urlscan.io API Key Here'

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

def decoderSwitch(choice):
    if choice == '1':
        proofPointDecoder()
    if choice == '2':
        urlDecoder()
    if choice == '3':
        safelinksDecoder()
    if choice == '4':
        unshortenEnter()
    if choice == '5':
        b64Decoder()
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

def phishingSwitch(choice):
    if choice == '1':
        analyzePhish()
    if choice == '2':
        analyzeEmail()
    if choice == '9':
        haveIBeenPwned()
    if choice == '0':
        mainMenu()

def extrasSwitch(choice):
    if choice == '1':
        aboutSooty()
    if choice == '2':
        contributors()
    if choice == '3':
        extrasVersion()
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
        #print('Error parsing URLv1')
        print(rewrittenurl)

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
        #print('Error parsing URLv2')
        print(rewrittenurl)

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
    print("Enter URL to sanitize: ")
    url = input()
    x = re.sub("\.", "[.]", url)
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
    print(" OPTION 0: Exit to Main Menu")
    decoderSwitch(input())

def proofPointDecoder():
    print("\n --------------------------------- ")
    print(" P R O O F P O I N T D E C O D E R ")
    print(" --------------------------------- ")
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
        print(' No valid URL found in input: ', rewrittenurl)

    mainMenu()

def urlDecoder():
    print("\n --------------------------------- ")
    print("       U R L   D E C O D E R      ")
    print(" --------------------------------- ")
    url = input(' Enter URL: ')
    decodedUrl = unquote(url)
    print(decodedUrl)
    mainMenu()

def safelinksDecoder():
    print("\n --------------------------------- ")
    print(" S A F E L I N K S   D E C O D E R  ")
    print(" --------------------------------- ")
    url = input(' Enter URL: ')
    dcUrl = unquote(url)
    dcUrl = dcUrl.replace('https://nam02.safelinks.protection.outlook.com/?url=', '')
    print(dcUrl)
    mainMenu()

def urlscanio():
    print("\n --------------------------------- ")
    print("\n        U R L S C A N . I O        ")
    print("\n --------------------------------- ")
    url_to_scan = str(input('\nEnter url: '))
    print('\nNow scanning %s. Check back in around 1 minute.' % url_to_scan)

    headers = {
        'Content-Type': 'application/json',
        'API-Key': URLSCAN_IO_KEY,
        }
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data='{"url": "%s", "public": "on" }' % url_to_scan).json()
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

def unshortenEnter():
    print("\n --------------------------------- ")
    print("   U R L   U N S H O R T E N E R  ")
    print(" --------------------------------- ")
    link = input(' Enter: ')
    urlUnshortener(link)
    decoderMenu()

def urlUnshortener(link):
    url = 'https://unshorten.me/s/'

    final = str(url) + str(link)
    req = requests.get(str(final))
    us_url = req.content
    us_url = str(us_url).split("b'")[-1]
    us_url = str(us_url).strip("'\\n'")
    print(us_url)
    return

def b64Decoder():
    url = input(' Enter URL: ')

    try:
        b64 = str(base64.b64decode(url))
        a = re.split("'", b64)[1]
        print(" B64 String:     " + url)
        print(" Decoded String: " + a)
    except:
        print(' No Base64 Encoded String Found')

    decoderMenu()

def repChecker():
    print("\n --------------------------------- ")
    print(" R E P U T A T I O N     C H E C K ")
    print(" --------------------------------- ")
    ip = input(" Enter IP / URL: ")

    whoIsPrint(ip)

    print("\n VirusTotal Report:")
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': VT_API_KEY, 'ip': ip}
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
                params = {'apikey': VT_API_KEY, 'resource': ip}
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
                print("  " + i + " is a TOR Exit Node")
                c = c+1
        if c == 0:
            print("  " + ip + " is NOT a TOR Exit Node")
    else:
        print("   TOR LIST UNREACHABLE")


    print("\n Checking BadIP's... ")
    try:
        BAD_IPS_URL = 'https://www.badips.com/get/info/' + ip
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
            'ipAddress': ip,
            'maxAgeInDays': days
        }

        headers = {
            'Accept': 'application/json',
            'Key': AB_API_KEY
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
    ip = input(' Enter IP / Domain: ')
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
    except:
        print(" IP Not Found - Checking Domains")
        ip = re.sub('https://', '', ip)
        ip = re.sub('http://', '', ip)
        try:
            s = socket.gethostbyname(ip)
            print(s)
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

    params = {'apikey': VT_API_KEY, 'resource': fileHash}
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
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
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

    params = {'apikey': VT_API_KEY, 'resource': fileHash}
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
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        except:
            print("\n Hash was not found in Malware Database")
    except:
        print(" Error: Invalid API Key")
    hashMenu()

def phishingMenu():
    print("\n --------------------------------- ")
    print("          P H I S H I N G          ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Analyze an Email ")
    print(" OPTION 2: Analyze an Email Address for Known Activity")
    print(" OPTION 9: HaveIBeenPwned")
    print(" OPTION 0: Exit to Main Menu")
    phishingSwitch(input())

def analyzePhish():
    try:
        #root = Tk()
        file = filedialog.askopenfilename(initialdir="/", title="Select file")
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

    try:
        print("\n Extracting Headers...")
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
        match = "((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))"
        a = re.findall(match, s, re.M | re.I)

        for b in a:
            pp = 'https://urldefense.proofpoint'
            if pp in b[0]:
                match2 = match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', b[0])
                if match2:
                    if match.group(1) == 'v1':
                        decodev1(b[0])
                    elif match.group(1) == 'v2':
                        decodev2(b[0])
                    else:
                        print(' Unrecognized')
            else:
                print(" ", b[0])
    except:
        print('   Links Error')
        f.close()

    print("\n Extracting Emails... ")
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
            print('   No IP Addresses Found')
    except:
        print('   IP error')

    phishingMenu()

def haveIBeenPwned():
    print("\n --------------------------------- ")
    print(" H A V E   I   B E E N   P W N E D  ")
    print(" --------------------------------- ")

    try:
        acc = input(' Enter email: ')
        url = ('https://haveibeenpwned.com/api/v2/breachedaccount/%s' % acc)
        response = requests.get(url)

        if response.status_code == 200:

            response = response.json()
            le = len(response)

            for i in range(le):
                dc = str(response[i]['DataClasses'])
                dc = re.sub('\[(?:[^\]|]*\|)?([^\]|]*)\]', r'\1', dc)
                dc = dc.replace("'", '')

                print("\n")
                print("Name:     " + str(response[i]['Title']))
                print("Domain:   " + str(response[i]['Domain']))
                print("Breached: " + str(response[i]['BreachDate']))
                print("Details:  " + str(dc))
                print("Verified: " + str(response[i]['IsVerified']))
        else:
            print(" Email NOT Found in Database")

    except:
        print(" Unable to reach HaveIBeenPwned")

    mainMenu()

def analyzeEmail():
    print("\n --------------------------------- ")
    print("    E M A I L   A N A L Y S I S    ")
    print(" --------------------------------- ")
    try:
        url = 'https://emailrep.io/'
        print(' Enter Email Address to Analyze: ')
        email = input()
        summary = '?summary=true'
        url = url + email + summary

        response = requests.get(url)
        req = response.json()

        emailDomain = re.split('@', email)[1]

        print('\n Email Analysis Report ')
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

            print('\n Profiles Found ')
            print('   %s' % req['details']['profiles'])

            print('\n Summary of Report: ')
            repSum = req['summary']
            repSum = re.split(r"\.\s*", repSum)
            for each in repSum:
                print('   %s' % each)

    except:
        print(' Error Analyzing Submitted Email')
    phishingMenu()

def extrasMenu():
    print("\n --------------------------------- ")
    print("            E X T R A S            ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: About SOOTY ")
    print(" OPTION 2: Contributors ")
    print(" OPTION 3: Version")
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
    extrasMenu()

def extrasVersion():
    print(' Current Version: ' + versionNo)
    extrasMenu()

if __name__ == '__main__':
    mainMenu()
