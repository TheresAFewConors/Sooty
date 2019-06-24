[![Generic badge](https://img.shields.io/badge/Made%20with-Python-blue.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-green.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
[![GitHub contributors](https://img.shields.io/github/contributors/theresafewconors/sooty.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty/graphs/contributors/)
[![Generic badge](https://img.shields.io/badge/Built%20For-SOC%20Analyst's-olive.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
[![HitCount](http://hits.dwyl.io/theresafewconors/sooty.svg)](https://GitHub.com/theresafewconors/sooty)


![](readmeimages/sooty_logo.png)

# Sooty

<!-- The SOC Analysts all-in-one CLI tool to automate and speed up workflow. -->

![](readmeimages/repcheck.gif)

### Sooty can Currently:
  - Sanitise URL's to be safe to send in emails
  - Perform reverse DNS and DNS lookups
  - Perform reputation checks from:
    - [VirusTotal](https://www.virustotal.com)
    - [BadIP's](https://www.badips.com/)
    - [Abuse IPDB](https://www.abuseipdb.com/)
  - Check if an IP address is a TOR exit node
  - Decode Proofpoint URL's and  UTF-8 encoded URLS
  - Get file hashes and compare them against [VirusTotal](https://www.virustotal.com) (see requirements)
  - Perform WhoIs Lookups
  - Check Usernames and Emails against [HaveIBeenPwned](https://haveibeenpwned.com) to see if a breach has occurred.

### Changelog

#### Version 1.1 - The Reputation Update
 - Improved Rep Checker
 - Added HaveIBeenPwned Functionality
 - Added DNS Tools and WhoIs Functionality
 - Added Hash and VirusTotal Checkers
 - Added Abuse IPDB, Tor Exit Node, BadIP's to Reputation Checker
 
#### Version 1.0
 - Initial Release
 - URL and ProofPoint Decoder
 - Initial implementation of Reputation Checker
 - Sanitize links to be safe for email

### RoadMap
  This is an outline of what features *will* be coming in future versions.
  
  #### Version 1.2 - The Phishing Update
    - Add Ability to extract email addresses and URL's from mail.
    - Correlate emails and URL's to see if they have been reported for phishing (PhishTank)
    - Scan email attachments for malicious content, macros, files, scan hashes, etc.
  
  #### Version 1.3 - The Case Update
    - Add a 'New Case' Feature, allowing output of the tool to be output to a txt file.

### Requirements
 - [Python 3.x](https://www.python.org/)
 - To use the Hash comparison with VirusTotal requires an [API key](https://developers.virustotal.com/reference), replace the key `VT_API_KEY` in the code with your own key. The tool will still function without this key, however this feature will not work.
 - To use the Reputation Checker with AbuseIPDB requires an [API Key](https://www.abuseipdb.com/api), replace the key `AB_API_KEY` in the code with your own key. The tool will still function without this key, however this feature will not work.
 
 
### Development

Want to contribute? Great!

  #### Code Contributions
  - New features / requests should start by opening an issue. This helps track new features and prevent crossover.
  - If you wish to work on a feature, leave a comment on the issue page and I will assign you to it.
  - All code modifications, enhancements or additions must be done through a pull request. 
  - Once reviewed and merged, contibutors will be added to the ReadMe



### Contributors:

 - [Aaron J Copley](https://github.com/aaronjcopley) for his code to decode ProofPoint URL's
 - [James Duarte](https://github.com/GarnetSunset) for adding a hash and auto-check option to the hashing function
 - [mrpnkt](https://github.com/mrpnkt) for adding the missing whois requirement to requirements.txt

 ![](readmeimages/vt_hashchecker.gif)
