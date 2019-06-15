[![Generic badge](https://img.shields.io/badge/Made%20with-Python-blue.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-green.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
[![GitHub contributors](https://img.shields.io/github/contributors/theresafewconors/sooty.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty/graphs/contributors/)
[![Generic badge](https://img.shields.io/badge/Built%20For-SOC%20Analyst's-olive.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
[![HitCount](http://hits.dwyl.io/theresafewconors/sooty.svg)](https://GitHub.com/theresafewconors/sooty)




# Sooty

The SOC Analysts all-in-one CLI tool to automate and speed up workflow. 

### Sooty can Currently:
  - Sanitise URL's to be safe to send in emails
  - Perform reverse DNS and DNS lookups
  - Perform reputation checks from [abuseIPDB.com](https://www.abuseipdb.com)
  - Decode Proofpoint URL's and  UTF-8 encoded URLS
  - Get file hashes and compare them against [VirusTotal](https://www.virustotal.com) (see requirements)
 
#### Requirements
 - Python 3.x
 - To use the Hash comparison with VirusTotal requires an [API key](https://developers.virustotal.com/reference), replace the key in the code with your own key.
 
#### Contributors:

 - [Aaron J Copley](https://github.com/aaronjcopley) for his code to decode ProofPoint URL's
 - [James Duarte](https://github.com/GarnetSunset) for adding a hash and auto-check option to the hashing function
