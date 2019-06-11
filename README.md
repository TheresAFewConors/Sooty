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

[Aaron J Copley](https://github.com/aaronjcopley) for his code to decode ProofPoint URL's
