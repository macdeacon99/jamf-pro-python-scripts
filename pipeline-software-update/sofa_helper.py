import os
import shutil
import sys
import json
from dotenv import load_dotenv
import pipeline_software_update as software_run
import requests

load_dotenv()

ONLINE_JSON_URL = os.environ.get("online_json_url")
USER_AGENT = os.environ.get("user_agent")

JSON_CACHE_DIR = os.environ.get("json_cache_dir")
JSON_CACHE = os.environ.get("json_cache")
ETAG_CACHE = os.environ.get("etag_cache")
ETAG_CACHE_TEMP = os.environ.get("etag_cache_temp")

def get_sofa_data() -> str:
    """
    Function to gather OS Version data from the SOFA JSON Feed

    :return: str of OS Versions
    """

    # Logging start
    software_run.logger.info("Getting SOFA data from JSON feed...")

    # Ensure local cache folder exists
    software_run.logger.info("Creating cache directory...")
    os.makedirs(JSON_CACHE_DIR, exist_ok=True)

    # Read the old ETag if it exists
    software_run.logger.info("Reading old ETag if it exists...")
    etag_old = None
    if os.path.exists(ETAG_CACHE):
        with open(ETAG_CACHE, "r") as f:
            etag_old = f.read().strip()

    # Prepare headers
    software_run.logger.info("Preparing headers...")
    headers = {"User-Agent": USER_AGENT}
    if etag_old:
        headers["If-None-Match"] = etag_old

    try:
        # Fetch online JSON with conditional GET
        response = requests.get(ONLINE_JSON_URL, headers=headers, timeout=3)
        if response.status_code == 304:
            software_run.logger.info("Cached ETag matched online ETag - cached JSON file is up to date...")
        elif response.status_code == 200:
            # Save JSON to cache
            with open(JSON_CACHE, "wb") as f:
                f.write(response.content)

            # Save new ETag if provided
            etag_new = response.headers.get("ETag")
            if etag_new:
                with open(ETAG_CACHE_TEMP, "w") as f:
                    f.write(etag_new)
                if etag_old == etag_new:
                    software_run.logger.info("Cached ETag matched online ETag - cached JSON file is up to date...")
                    os.remove(ETAG_CACHE_TEMP)
                else:
                    software_run.logger.info("Cached ETag did not matched online ETag - downloaded new SOFA JSON file...")
                    shutil.move(ETAG_CACHE_TEMP, ETAG_CACHE)
            else:
                software_run.logger.info("No ETag returned - JSON cache updated without ETag")
        else:
            software_run.logger.error("Failed to fetch JSON feed. HTTP Status: %s", response.status_code)
    except requests.RequestException as e:
        software_run.logger.critical("Error fetching JSON feed: %s", e)
        sys.exit(1)

    # Check if the cache file exists
    software_run.logger.info("Loading JSON data...")
    if os.path.exists(JSON_CACHE):
        with open(JSON_CACHE, "r") as f:
            data = json.load(f)  # parse JSON into Python dict
    else:
        software_run.logger.critical("Cached JSON file not found...")
        sys.exit(1)

    return json.dumps(data)

def get_os_data(json_data: str) -> list:
    """
    Function to extract the OS information for the latest and previous OS versions

    :param json_data - String version of the SOFA JSON feed
    :return: list of latest and previous OS information
    """

    # Loading OS data from param
    # os_versions is the first section of the JSON
    # security_releases is the list of the OS releases in the feed
    os_data = json.loads(json_data)

    security_releases = []
    for os_version in os_data["OSVersions"]:
        security_releases.extend(os_version.get("SecurityReleases", []))
    
    os_list = []

    # Loop through the releases and append to a list
    software_run.logger.info("Getting OS Versions and saving to list...")
    for release in security_releases:
        os_list.append({
            "update": release["UpdateName"],
            "release_date": release["ReleaseDate"],
            "days_since_previous_release": release["DaysSincePreviousRelease"]
        }) 
    software_run.logger.debug(f"Got OS versions: {os_list}")
    return os_list

def determine_os_difference(os_data: list) -> bool:
    """
    Function to determine the difference between the latest OS and the previous

    :param os_data - List of the OS versions available in the SOFA feed
    :return: boolean to detemine if this the latest OS is a minor or major update
    """

    # Get the latest and previous OS versions from the os_data list
    latest_version = os_data[0]
    latest_os = latest_version["update"].split()[-1]

    previous_version = os_data[1]
    previous_os = previous_version["update"].split()[-1]

    previous_2_version = os_data[2]
    previous_2_os = previous_2_version["update"].split()[-1]

    # Compate the versions using helper function
    software_run.logger.info("Comparing latest and previous OS to determine if major or minor update...")
    minor = compare_versions(previous_os, latest_os)
    previous_minor = compare_versions(previous_2_os, previous_os)

    software_run.logger.debug(f"This is a minor update: {previous_os} -> {latest_os}") if minor else software_run.logger.debug(f"This is a major update: {previous_os} -> {latest_os}")

    return minor, previous_minor

def version_to_tuple(version_str: str) -> tuple:
    """
    Helper function to convert version number to a tuple

    :param version_str - String of the OS version
    :return: tuple of the OS version split by the '.'
    """

    # Split by '.' and convert each part to int
    return tuple(int(part) for part in version_str.split('.'))   

def compare_versions(previous_os: str, latest_os: str) -> bool:
    """
    Helper function to compare the version numbers to determine if it is a minor or major update

    :param previous_os - String of the previous OS version
    :param previous_os - String of the latest OS version
    :return: boolean to determine if minor update
    """

    # Convert the OS versions to a tuple
    previous_tuple = version_to_tuple(previous_os)
    latest_tuple = version_to_tuple(latest_os)
    
    # Compare first number to determine if major OS update
    if latest_tuple[0] > previous_tuple[0]:
        return False
    # Make sure the OS versions aren't the same
    elif previous_os != latest_os:
        return True
    else:
        software_run.logger.critical("Not able to detect if minor or major update...")
        sys.exit()