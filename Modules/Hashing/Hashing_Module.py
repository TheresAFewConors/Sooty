

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
    count = 0
    # VT Hash Checker
    fileHash = str(input(" Enter Hash of file: ").strip())
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
        try:
            if result['positives'] != 0:
                print("\n Malware Detection")
                for value in result['scans'].items():
                    if value['detected'] == True:
                        count = count + 1
            print(" VirusTotal Report: " + str(count) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        except:
            print("\n Hash was not found in Malware Database")
    except:
        print("Error: Invalid API Key")

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
    count = 0
    # VT Hash Checker
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
        try:
            if result['positives'] != 0:
                print("\n Malware Detection")
                for value in result['scans'].items():
                    if value['detected'] == True:
                        count = count + 1
            print(" VirusTotal Report: " + str(count) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        except:
            print("\n Hash was not found in Malware Database")
    except:
        print(" Error: Invalid API Key")

