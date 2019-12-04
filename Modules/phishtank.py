"""
Author: Axel Robbe
Version: 0.1

This script checks URLs against the Phishtank database and allows for the usage of a local database.
Expected script syntax is python phishtank.py <True/False> <user_agent> <api_key> <url>

Example:
python phishtank.py False "test application" some_api_key "https://some.link/"

The True/False switch determines whether to download (True) the database locally or not (False) and use
the web API instead. Please use quotation marks if there are spaces in the user/application name such as
mentioned above. Also, put the full URL in, otherwise their won't be any hits from the online database.
Using a local database can help a lot in accuracy of the report as it will return more results. If there
is an issue with the local DB or retrieving it, the program will fall back to the API.

Open issues (to be fixed in future releases):
- True/False switch needs to be fixed into something better
- Order of arguments should not matter


"""
import requests
import sys
import wget
import os
import time
import urllib
import json


def db_validity(db):
    # Checking if DB exists or is too old
    if db_absent(db) or db_outdated(db) == 1:
        if download_json(db) == False:
            return False
        else:
            return True
    else:
        print("Phishtank database found and up to date.")
        return True


def db_absent(db):
    if os.path.isfile(db):
        return 0
    else:
        return 1


def db_outdated(db):
    seconds = time.time() - os.path.getmtime(db)
    if seconds > 21600:
        os.remove(db)
        print("Database is older than 6 hours. \nRe-downloading Phishtank database:")
        return 1


def download_json(db):
    # Need to redownload DB
    try:
        wget.download("http://data.phishtank.com/data/online-valid.json", db)
        print("Download complete")
        return True

    # In case of failure, passing False through so that the program continues with the API
    except Exception as exc:
        print(
            "The following error occured when downloading: "
            + exc
            + "\nContinuing without a local database."
        )
        return False


def urlcheck_db(db, url, domain):
    related_urls = []
    print("Checking the local database.")

    # Opening the DB
    with open(db) as json_file:
        db = json.load(json_file)

    # Check every entry for a match
    for entry in db:
        if url == entry["url"]:
            # Results do not match 1-to-1 with the API results. Rewriting local DB result here
            result = {
                "url": entry["url"],
                "in_database": True,
                "phish_id": entry["phish_id"],
                "phish_detail_page": entry["phish_detail_url"],
                "verified": entry["verified"],
                "verified_at": entry["verification_time"],
                "valid": entry["online"],
                "target": entry["target"],
            }
            db_hit = True
            # If we have a hit, we can break out of the for loop
            break

        # Related results matching the domain name. This functions only works with local DB
        if domain in entry["url"]:
            related_urls.append(
                {"url": entry["url"], "phish_detail_page": entry["phish_detail_url"]}
            )
            related = True

    # Test if variables exist. If db_hit exist, we have a direct hit. If related exists, we
    # have hits on the domain name.
    if "db_hit" in locals():
        urlReport(result)
    elif "related" in locals():
        print("No direct entries found.\n\nRelated entries:")
        for url in related_urls:
            print(
                "  Details page "
                + url["phish_detail_page"]
                + " for the following URL: "
                + url["url"]
            )
    else:
        print("No results found")


def urlcheck_online(user_agent, api_key, url):
    print("Checking the online database.")
    # Setting up the API request
    try:
        PT_URL = "https://checkurl.phishtank.com/checkurl/"
        querystring = {
            "url": url,
            "format": "json",
            "app_key": api_key,
        }
        headers = {
            "User-Agent": user_agent,
        }
        response = requests.request(
            method="POST", url=PT_URL, headers=headers, data=querystring
        )

        # Checking response from webpage
        if response.status_code == 200:
            reply = response.json()
            urlReport(reply["results"])
        else:
            print("Error reaching PhishTank. Status code " + str(response.status_code))
    except Exception as exc:
        print(exc)


def urlReport(result): # Purely a printing function
    print("\nPhishTank Report:")
    print("   URL:           " + str(result["url"]))
    print("   In Database:   " + str(result["in_database"]))
    if result["in_database"] == True:
        print("   Phish ID:      " + str(result["phish_id"]))
        print("   Phish Details: " + str(result["phish_detail_page"]))
        print("   Verified:      " + str(result["verified"]))
        print("   Verified At:   " + str(result["verified_at"]))
        print("   Online:        " + str(result["valid"]))
    if local_db == True: # This data is not returned from the API
        print("   Target:        " + str(result["target"]))


def main(args):
    # Check if number of expected variables match, otherwise print the documentation.
    if not len(args) == 4:
        print(__doc__)
        return

    # Declare local_db as a global variable - saves a lot in passing args to functions
    global local_db

    # map input to variables
    local_db, user_agent, api_key, url = args[0], args[1], args[2], args[3]
    if "true" in local_db.lower():
        local_db = True
        # Check for the subdirectory's existence
        try:
            os.mkdir("data")
        except Exception:
            pass
        db = "data/phishtank.json"
    else:
        local_db = False
    
    # Test if URL is usable in the search
    valid_url = urllib.parse.urlparse(url)
    if valid_url.scheme == "http" or valid_url.scheme == "https":
        # Test if we want to verify locally and if DB exists and is recent enough.
        if local_db and db_validity(db) == True:
            # Check DB status and then do URL lookup locally
            urlcheck_db(db, url, valid_url.hostname)
        else:
            # Do a URL lookup online
            urlcheck_online(user_agent, api_key, url)
    else:
        print("Not a valid http or https url. Please enter the full URL.")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
