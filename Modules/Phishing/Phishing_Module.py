'''
Module: PHISHING MODULE

This section is designed to contain all tools related to phishing.

'''

import re
import requests
import os
import tkinter
import tkinter.filedialog
import time

try:
    import win32com.client
except:
    print('Cant install Win32com package')

from Modules.Decoders import Decoders_Module
from Modules.Phishing import phishtank

linksFoundList = []


def analyzeEmail(email, configvars):
    try:
        url = 'https://emailrep.io/'
        summary = '?summary=true'
        url = url + email + summary
        response = requests.get(url)
        req = response.json()
        emailDomain = re.split('@', email)[1]

        print('\n Email Analysis Report')

        if response.status_code == 400:
            print(' Invalid Email / Bad Request')
        if response.status_code == 401:
            print(' Unauthorized / Invalid API Key (for Authenticated Requests)')
        if response.status_code == 429:
            print(' Too many requests, an API key is required for further use')

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
                    print(' No HaveIBeenPwned API Key Found')
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
                    Decoders_Module.decodev1(b[0])
                elif match.group(1) == 'v2':
                    Decoders_Module.decodev2(b[0])
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

def analyzeEmailInput():
    print("\n --------------------------------- ")
    print("    E M A I L   A N A L Y S I S    ")
    print(" --------------------------------- ")
    try:
        email = str(input(' Enter Email Address to Analyze: ').strip())
        analyzeEmail(email)
    except:
        print("   Error Scanning Email Address")

def emailTemplateGen(configvars):
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
                        Decoders_Module.decodev1(b[0])
                    elif match.group(1) == 'v2':
                        Decoders_Module.decodev2(b[0])
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
            print(each)

        if 'API Key' not in configvars.data['VT_API_KEY']:
            try:  # EAFP
                url = 'https://www.virustotal.com/vtapi/v2/url/report'
                for each in linksFoundList:
                    link = each
                    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': link}
                    response = requests.get(url, params=params)
                    result = response.json()
                    if response.status_code == 200:
                        print(response)
                        print(result)
                        Decoders_Module.linksDict['%s' % sanitizedLink] = str(result['positives'])

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
                Decoders_Module.linksDict['%s' % sanitizedLink] = str(result['positives'])
                #virusTotalAnalyze(result, sanitizedLink)
        else:
            print('No API Key set, results will not show malicious links')

        rc = 'potentially benign'
        threshold = '1'

        if req['details']['spam'] or req['suspicious'] or req['details']['blacklisted'] or req['details']['malicious_activity']:
            rc = 'potentially suspicious'

        for key, value in Decoders_Module.linksDict.items():
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
            for each in Decoders_Module.linksDict.values():
                if int(threshold) <= int(each):
                    malLink = 1

            if malLink == 1:
                print('\nThe following potentially malicious links were found embedded in the body of the mail:')
                for key, value in Decoders_Module.linksDict.items():
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
    except:
        print(' Error importing email for template generator')

def virusTotalAnalyze(result, sanitizedLink):
    Decoders_Module.linksDict['%s' % sanitizedLink] = str(result['positives'])



def haveIBeenPwned(configvars):
    print("\n --------------------------------- ")
    print(" H A V E   I   B E E N   P W N E D  ")
    print(" --------------------------------- ")

    try:
        acc = str(input(' Enter email: ').strip())
        haveIBeenPwnedPrintOut(acc, configvars)
    except:
        print(' Error reaching HaveIBeenPwned Database ')

def haveIBeenPwnedPrintOut(acc, configvars):
    try:
        url = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s' % acc
        userAgent = 'Sooty'
        headers = {'Content-Type': 'application/json', 'hibp-api-key': configvars.data['HIBP_API_KEY'], 'user-agent': userAgent}
        try:
            req = requests.get(url, headers=headers)
            response = req.json()
            lr = len(response)
            if response['statusCode'] == 401:
                print(response['message'])

            if response['statusCode'] == 200:
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
        print(' Error: Unable to reach HaveIBeenPwned Database ')



def phishtankModule(configvars):
    try:
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
    except:
        print(' Unable to reach phishtank.com')
