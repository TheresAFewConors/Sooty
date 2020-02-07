

import hashlib
import tkinter
import tkinter.filedialog
import requests



def hashFile():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    print(" MD5 Hash: " + hasher.hexdigest())
    root.destroy()

def hashText():
    userinput = input(" Enter the text to be hashed: ")
    print(" MD5 Hash: " + hashlib.md5(userinput.encode("utf-8")).hexdigest())

def hashRating(configvars):
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
            print("No Response")


def hashAndFileUpload(configvars):
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


