[![Generic badge](https://img.shields.io/badge/Made%20with-Python-blue.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-green.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
[![GitHub contributors](https://img.shields.io/github/contributors/theresafewconors/sooty.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty/graphs/contributors/)
[![Generic badge](https://img.shields.io/badge/Built%20For-SOC%20Analyst's-olive.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
[![HitCount](http://hits.dwyl.io/theresafewconors/sooty.svg)](https://GitHub.com/theresafewconors/sooty)




# Sooty

The SOC Analysts CLI tool to automate and speed up workflow. 

### Sooty can Currently:
  - Sanitises URL's to be safe to send in emails
  - Performs reverse DNS and DNS lookups
  - Performs reputation checks from [abuseIPDB.com](https://www.abuseipdb.com)
  - Decodes Proofpoint URL's
  - Get file hashes and compare them against [VirusTotal](https://www.virustotal.com) (see requirements)
 
#### Requirements
 - Python 3.x
 - To use the Hash comparison with VirusTotal requires an [API key](https://developers.virustotal.com/reference), replace the key in the code with your own key.
 
#### Contributors:

 - [Aaron J Copley](https://github.com/aaronjcopley) for his code to decode ProofPoint URL's
