
import socket
from ipwhois import IPWhois
import re



def reverseDnsLookup():
    d = str(input(" Enter IP to check: ").strip())
    try:
        s = socket.gethostbyaddr(d)
        print('\n ' + s[0])
    except:
        print(" Hostname not found")


def dnsLookup():
    d = str(input(" Enter Domain Name to check: ").strip())
    d = re.sub("http://", "", d)
    d = re.sub("https://", "", d)
    try:
        s = socket.gethostbyname(d)
        print('\n ' + s)
    except:
        print("Website not found")


def whoIs():
    ip = str(input(' Enter IP / Domain: ').strip())
    whoIsPrint(ip)


def whoIsPrint(ip):
    if ip == '':
        print(' No Input Received')
    else:
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
            print("\n  IP Not Found - Checking Domains")
            resolveAddress(ip)
        return

def resolveAddress(ip):
    try:
         s = socket.gethostbyname(ip)
         print('  Resolved Address: %s' % s)
         try:
             whoIsPrint(s)
         except:
             print(' error with addr info')
    except:
        print('  IP or Domain not Found')