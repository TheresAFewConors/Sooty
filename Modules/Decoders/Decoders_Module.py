
import re
import urllib
import html.parser
import requests
import base64



def urlSanitise():
    print("\n --------------------------------- ")
    print(" U R L   S A N I T I S E   T O O L ")
    print(" --------------------------------- ")
    url = str(input("Enter URL to sanitize: ").strip())
    x = re.sub(r"\.", "[.]", url)
    x = re.sub("http://", "hxxp://", x)
    x = re.sub("https://", "hxxps://", x)
    print("\n" + x)

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

def urlDecoder():
    print("\n --------------------------------- ")
    print("       U R L   D E C O D E R      ")
    print(" --------------------------------- ")
    url = str(input(' Enter URL: ').strip())
    decodedUrl = urllib.parse.unquote(url)
    print(decodedUrl)

def safelinksDecoder():
    print("\n --------------------------------- ")
    print(" S A F E L I N K S   D E C O D E R  ")
    print(" --------------------------------- ")
    url = str(input(' Enter URL: ').strip())
    dcUrl = urllib.parse.unquote(url)
    dcUrl = dcUrl.replace('https://nam02.safelinks.protection.outlook.com/?url=', '')
    print(dcUrl)

def unshortenUrl():
    print("\n --------------------------------- ")
    print("   U R L   U N S H O R T E N E R  ")
    print(" --------------------------------- ")
    link = str(input(' Enter URL: ').strip())
    req = requests.get(str('https://unshorten.me/s/' + link))
    print(req.text)


def b64Decoder():
    print("\n --------------------------------- ")
    print("    B A S E 6 4   D E C O D E R    ")
    print(" --------------------------------- ")
    url = str(input(' Enter URL: ').strip())

    try:
        b64 = str(base64.b64decode(url))
        a = re.split("'", b64)[1]
        print(" B64 String:     " + url)
        print(" Decoded String: " + a)
    except:
        print(' No Base64 Encoded String Found')

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


