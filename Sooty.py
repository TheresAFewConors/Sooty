"""
    Title:      Sooty
    Desc:       The SOC Analysts all-in-one CLI tool to automate and speed up workflow.
    Author:     Connor Jackson
    Version:    1.3.2
    GitHub URL: https://github.com/TheresAFewConors/Sooty
"""

import os
import strictyaml

from Modules import TitleOpen

from Modules.Reputation_Check import Reputation_Checker
from Modules.DNS_Tools import DNS_Module
from Modules.Phishing import Phishing_Module
from Modules.Decoders import Decoders_Module
from Modules.Hashing import Hashing_Module
from Modules.Extras import Extras

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
    if choice == '2':
        decoderMenu()
    if choice == '3':
        repMenu()
    if choice == '4':
        dnsMenu()
    if choice == '5':
        hashMenu()
    if choice == '6':
        phishingMenu()
    if choice == '9':
        extrasMenu()
    if choice == '0':
        exit()
    else:
        mainMenu()

def decoderSwitch(choice):
    if choice == '1':
        Decoders_Module.proofPointDecoder()
    if choice == '2':
        Decoders_Module.urlDecoder()
    if choice == '3':
        Decoders_Module.safelinksDecoder()
    if choice == '4':
        Decoders_Module.unshortenUrl()
    if choice == '5':
        Decoders_Module.b64Decoder()
    if choice == '6':
        Decoders_Module.cisco7Decoder()
    if choice == '7':
        Decoders_Module.urlSanitise()
    if choice == '0':
        mainMenu()

def repSwitch(choice):
    if choice == '1':
        Reputation_Checker.repChecker(configvars)
    if choice == '2':
        Reputation_Checker.urlscanio(configvars)
    if choice == '0':
        mainMenu()
    else:
        repMenu()

def dnsSwitch(choice):
    if choice == '1':
        DNS_Module.reverseDnsLookup()
    if choice == '2':
        DNS_Module.dnsLookup()
    if choice == '3':
        DNS_Module.whoIs()
    if choice == '0':
        mainMenu()
    dnsMenu()

def hashSwitch(choice):
    if choice == '1':
        Hashing_Module.hashFile()
    if choice == '2':
        Hashing_Module.hashText()
    if choice == '3':
        Hashing_Module.hashRating(configvars)
    if choice == '4':
        Hashing_Module.hashAndFileUpload(configvars)
    if choice == '0':
        mainMenu()
    hashMenu()

def phishingSwitch(choice):
    if choice == '1':
        Phishing_Module.analyzePhish()
    if choice == '2':
        Phishing_Module.analyzeEmailInput()
    if choice == '3':
        Phishing_Module.emailTemplateGen(configvars)
    if choice == '4':
        Phishing_Module.phishtankModule(configvars)
    if choice == '9':
        Phishing_Module.haveIBeenPwned(configvars)
    if choice == '0':
        mainMenu()
    phishingMenu()

def extrasSwitch(choice):
    if choice == '1':
        Extras.aboutSooty()
    if choice == '2':
        Extras.contributors()
    if choice == '3':
        Extras.extrasVersion(versionNo)
    if choice == '4':
        Extras.wikiLink()
    if choice == '5':
        Extras.ghLink()
    else:
        mainMenu()

def titleLogo():
    TitleOpen.titleOpen()
    os.system('cls||clear')

def mainMenu():
    print("\n --------------------------------- ")
    print("\n           S  O  O  T  Y           ")
    print("\n --------------------------------- ")
    print(" What would you like to do? ")
    print("\n OPTION 1: EMPTY ")
    print(" OPTION 2: Decoders and Link Sanitizers ")
    print(" OPTION 3: Reputation Checker")
    print(" OPTION 4: DNS Tools")
    print(" OPTION 5: Hashing Function")
    print(" OPTION 6: Phishing Analysis")
    print(" OPTION 7: EMPTY ")
    print(" OPTION 9: Extras")
    print(" OPTION 0: Exit Tool")
    switchMenu(input())

def decoderMenu():
    print("\n ----------------------------------- ")
    print(" D E C O D E  A N D  S A N I T I Z E ")
    print(" ----------------------------------- ")
    print(" What would you like to do? ")
    print("\n OPTION 1: ProofPoint Decoder")
    print(" OPTION 2: URL Decoder")
    print(" OPTION 3: Office SafeLinks Decoder")
    print(" OPTION 4: URL unShortener")
    print(" OPTION 5: Base64 Decoder")
    print(" OPTION 6: Cisco Password 7 Decoder")
    print(" OPTION 7: Sanitize links to safely send via email")
    print(" OPTION 0: Exit to Main Menu")
    decoderSwitch(input())

def repMenu():
    print("\n --------------------------------- ")
    print(" R E P   C H E C K I N G   T O O L ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print("\n OPTION 1: Reputation Check")
    print(" OPTION 2: UrlScan.io lookup")
    repSwitch(input())

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

    phishingMenu()

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

if __name__ == '__main__':
    titleLogo()
    mainMenu()
