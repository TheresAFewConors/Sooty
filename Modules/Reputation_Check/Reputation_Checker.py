
import re
import time
import socket
import requests
import Logger
from Modules.Phishing import Phishing_Module
from Modules.DNS_Tools import DNS_Module


def repChecker(configvars):
    print("\n --------------------------------- ")
    print(" R E P U T A T I O N     C H E C K ")
    print(" --------------------------------- ")
    ip = str(input(" Enter IP, URL or Email Address: ").strip())

    Logger.logMsg(Logger.loggerRepCheck, 'Rep check performed on %s' % ip)
    s = re.findall(r'\S+@\S+', ip)
    if s:
        print('   Email Detected...')
        Phishing_Module.analyzeEmail(''.join(s), configvars)
    else:
        DNS_Module.whoIsPrint(ip)
        try:
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
                    print("  Error Reaching ABUSE IPDB")
            except:
                    print('   IP Not Found')
        except:
            print('   Failed to find IP Info')


def urlscanio(configvars):
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
