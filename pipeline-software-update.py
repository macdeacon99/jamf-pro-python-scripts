import os
from dotenv import load_dotenv
import jamfpy
from pprint import pprint
import requests
import os
import requests
import shutil
import json
from datetime import datetime, timezone, timedelta
import xml.etree.ElementTree as ET
import logging
import sys

######### To-Do #################
# - Implement logging
# - Implement email report
##################################

load_dotenv()

# --- Configuration ---
ONLINE_JSON_URL = os.environ.get("online_json_url")
USER_AGENT = os.environ.get("user_agent")

JSON_CACHE_DIR = os.environ.get("json_cache_dir")
JSON_CACHE = os.environ.get("json_cache")
ETAG_CACHE = os.environ.get("etag_cache")
ETAG_CACHE_TEMP = os.environ.get("etag_cache_temp")

CLIENT_ID       = os.environ.get("client_id")
CLIENT_SECRET   = os.environ.get("client_secret")
JP_URL          = os.environ.get("jamf_url")

sandbox = jamfpy.Tenant(
    fqdn                        = JP_URL,
    auth_method                 = "oauth2",
    client_id                   = CLIENT_ID,
    client_secret               = CLIENT_SECRET,
    token_exp_threshold_mins    = 1
)

logging.basicConfig(
    filename="software_update.log",
    level = logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

def get_sofa_data() -> str:
    """
    Function to gather OS Version data from the SOFA JSON Feed

    :return: str of OS Versions
    """

    # Logging start
    logger.info("Getting SOFA data from JSON feed...")

    # Ensure local cache folder exists
    logger.info("Creating cache directory...")
    os.makedirs(JSON_CACHE_DIR, exist_ok=True)

    # Read the old ETag if it exists
    logger.info("Reading old ETag if it exists...")
    etag_old = None
    if os.path.exists(ETAG_CACHE):
        with open(ETAG_CACHE, "r") as f:
            etag_old = f.read().strip()

    # Prepare headers
    logger.info("Preparing headers...")
    headers = {"User-Agent": USER_AGENT}
    if etag_old:
        headers["If-None-Match"] = etag_old

    try:
        # Fetch online JSON with conditional GET
        response = requests.get(ONLINE_JSON_URL, headers=headers, timeout=3)
        if response.status_code == 304:
            logger.info("Cached ETag matched online ETag - cached JSON file is up to date...")
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
                    logger.info("Cached ETag matched online ETag - cached JSON file is up to date...")
                    os.remove(ETAG_CACHE_TEMP)
                else:
                    logger.info("Cached ETag did not matched online ETag - downloaded new SOFA JSON file...")
                    shutil.move(ETAG_CACHE_TEMP, ETAG_CACHE)
            else:
                logger.info("No ETag returned - JSON cache updated without ETag")
        else:
            logging.error(f"Failed to fetch JSON feed. HTTP Status: {response.status_code}")
    except requests.RequestException as e:
        logging.critical(f"Error fetching JSON feed: {e}")
        sys.exit(1)

    # Check if the cache file exists
    logger.info("Loading JSON data...")
    if os.path.exists(JSON_CACHE):
        with open(JSON_CACHE, "r") as f:
            data = json.load(f)  # parse JSON into Python dict
    else:
        logger.critical("Cached JSON file not found...")
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
    os_versions = os_data["OSVersions"][0]
    security_releases = os_versions.get("SecurityReleases", [])
    os_list = []

    # Loop through the releases and append to a list
    logger.info("Getting OS Versions and saving to list...")
    for release in security_releases:
        os_list.append({
            "update": release["UpdateName"],
            "release_date": release["ReleaseDate"],
            "days_since_previous_release": release["DaysSincePreviousRelease"]
        }) 
    
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

    # Compate the versions using helper function
    logger.info("Comparing latest and previous OS to determine if major or minor update...")
    minor = compare_versions(previous_os, latest_os)

    return minor

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
        logger.info("Major update detected...")
        return False
    # Make sure the OS versions aren't the same
    elif previous_os != latest_os:
        logger.info("Minor update detected...")
        return True
    else:
        logger.critical("Not able to detect if minor or major update...")
        sys.exit()
    
def set_deployment_ring(is_minor: bool, os_data: list):
    """
    Function to set the deployment rings that the update will be pushed out to based on
    environment variables.

    :param is_minor - boolean to mark if minor OS update or Major
    :param os_data - list of the OS version data
    :return os_to_update - string of the OS version
    :return deployment_ids - list of IDs of Smart Groups that will be deployed
    :return rings - list of the deployment rings data
    :return release_date - string of the release date of the version being updated to
    """

    logger.info("Setting the deployment rings for update...")
    # Define variables from environment
    delays = {
        True: int(os.environ.get("minor_final_delay")),
        False: int(os.environ.get("major_final_delay")),
    }

    # Getting the data of the OS versions
    latest_os = os_data[0]
    previous_os = os_data[1]

    # Calculate the days since the OS has been released
    days_since = {
        "previous": calculate_days(previous_os["release_date"]),
        "latest": calculate_days(latest_os["release_date"]),
    }

    # Pick the right delay
    final_delay = delays[is_minor]

    # Decide whether to continue or wait
    if days_since["previous"] < final_delay:
        logger.info("Previous update not finished, continuing previous update...")
        os_to_update = previous_os["update"].split()[-1]
        release_date = previous_os["release_date"]
        deployment_ids, rings = calculate_deployment_ids(days_since["previous"], is_minor)
    else:
        logger.info("Previous update finished, continuing...")
        os_to_update = latest_os["update"].split()[-1]
        release_date = latest_os["release_date"]
        deployment_ids, rings = calculate_deployment_ids(days_since["latest"], is_minor)

    return os_to_update, deployment_ids, rings, release_date


def calculate_deployment_ids(days_past: str, is_minor: bool) -> list:
    """
    Helper function to calculate the deployment ids

    :param is_minor - boolean to mark if minor OS update or Major
    :param days_past - str of the amount of days that have past since update released
    :return active_groups - list of the group IDs to be deployed
    :return rings - list of the deployment rings data
    """

    # Define Variables
    rings = [
        {
            "name": "TEST",
            "id": int(os.environ.get("test_ring_id", 0)),  # default to 0
            "minor_delay": int(os.environ.get("test_minor_delay", 0)),
            "major_delay": int(os.environ.get("test_major_delay", 0))
        },
        {
            "name": "FIRST",
            "id": int(os.environ.get("first_ring_id", 0)),
            "minor_delay": int(os.environ.get("first_minor_delay", 0)),
            "major_delay": int(os.environ.get("first_major_delay", 0)),
        },
        {
            "name": "FAST",
            "id": int(os.environ.get("fast_ring_id", 0)),
            "minor_delay": int(os.environ.get("fast_minor_delay", 0)),
            "major_delay": int(os.environ.get("fast_major_delay", 0)),
        },
        {
            "name": "BROAD",
            "id": int(os.environ.get("broad_ring_id", 0)),
            "minor_delay": int(os.environ.get("broad_minor_delay", 0)),
            "major_delay": int(os.environ.get("broad_major_delay", 0)),
        }
    ]

    active_groups = []

     # Always include TEST ring first
    for ring in rings:
        active_groups.append(ring["id"])

        # Pick the right delay based on minor/major
        delay = ring["minor_delay"] if is_minor else ring["major_delay"]

        # If we haven’t reached this ring’s delay yet, stop
        if days_past < delay:
            break

    return active_groups, rings

    
def calculate_days(release_date: str) -> int:
    """
    Helper function to calculate the days since OS release

    :param release_date - string of the release date of the OS version
    :return days_since - int of the amount of days since OS release
    """

    logger.info("Calculating days since OS has been released...")

    # Convert the string to a datetime object
    past_date = datetime.strptime(release_date, "%Y-%m-%dT%H:%M:%SZ")
    past_date = past_date.replace(tzinfo=timezone.utc)  # ensure it's timezone-aware

    # Get current UTC time
    now = datetime.now(timezone.utc)

    # Calculate the difference
    delta = now - past_date

    # Number of days
    days_since = delta.days

    return days_since

def update_smart_groups(os_to_update: str):
    """
    Function to update a smart group of 'Not on the latest OS' so that automation works
    in smart groups to continue to scope only devices that are not on OS that is being updated

    :param os_to_update - string of the OS version that is being pushed
    """

    logger.info("Creating payload to update 'not on latest OS' smart group...")

    # Get group ID for 'Not on latest OS' smart group
    group_id = os.environ.get("not_on_latest_os_id")

    # Get bearer token to use API calls instead of SDK as functionality doesn't work
    token = sandbox.classic.auth.token()

    payload = {
        "name": f"Not on latest OS",
        "criteria": [
            {
                "name": "Operating System Version",
                "andOr": "and",
                "searchType": "less than",
                "value": f"{os_to_update}"
            }
        ]
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": f"Bearer {token}"
    }

    try:
        requests.put(f"{JP_URL}/api/v2/computer-groups/smart-groups/{group_id}", json=payload, headers=headers)
    except requests.RequestException as e:
        logging.critical(f"Error updating Smart Group (Not on Latest OS): {e}")
        sys.exit(1)

def calculate_install_date(groups: list, rings:list, is_minor:bool, release_date: str) -> str:
    """
    Function to calculate the final install date to force update

    :param groups - list of groups ids to calculate which ring is being pushed to
    :param rings - list of rings to get data about length of delay to calculate force date
    :param is_minor - boolean to determine if major or minor version update
    :param release_date - string of the release date of the OS version
    :return install_dt - string of the forced install date
    """

    logger.info("Calculating the force install date...")

    # Parse ISO 8601 date string (with Z at the end for UTC)
    release_dt = datetime.strptime(release_date, "%Y-%m-%dT%H:%M:%SZ")

    # Decide which delay to use based on number of groups and update type
    length = len(groups)
    days = rings[length]["minor_delay"] if is_minor else rings[length]["major_delay"]

    # Add delay
    install_dt = release_dt + timedelta(days=days)

    # Return in format YYYY-MM-DDTHH:MM:SS
    return install_dt.strftime("%Y-%m-%dT%H:%M:%S")


def create_deployment_plan(groups: list, os_version: str, install_date: str):
    """
    Function to create Software Update Management Plan via SDK

    :param groups - list of groups ids to calculate which ring is being pushed to
    :param os_version - string of the OS Version to use to update
    :param install_date - string of the force install date
    """

    logger.info("Creating deployment plan...")

    # Get auth token
    token = sandbox.pro.auth.token()

    # Create payload for the Software Update Management Plan
    payload = {
        "group": {
            "objectType": "COMPUTER_GROUP",
            "groupId": f"{groups[len(groups) - 1]}"
        },
        "config": {
            "updateAction": "DOWNLOAD_INSTALL_SCHEDULE",
            "versionType": "SPECIFIC_VERSION",
            "specificVersion": f"{os_version}",
            "forceInstallLocalDateTime": f"{install_date}"
        }
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": f"Bearer {token}"
    }

    # API call to Jamf Pro
    try:
        requests.post(f"{JP_URL}/api/v1/managed-software-updates/plans/group", json=payload, headers=headers)
    except requests.RequestException as e:
        logger.critical(f"API was not able to create Software Update Management Plan: {e}")

def build_policy_scope_xml(group_ids, group_names=None):
    """
    Build XML scope for Jamf policy.
    
    :param group_ids: list of integers (required)
    :param group_names: optional list of strings (same order as group_ids)
    :return: XML string
    """

    logger.info("Creating Policy XML...")

    # Setting XML variables
    policy = ET.Element("policy")
    scope = ET.SubElement(policy, "scope")
    computer_groups = ET.SubElement(scope, "computer_groups")

    # Create the XML Structure
    for i, gid in enumerate(group_ids):
        group_elem = ET.SubElement(computer_groups, "computer_group")
        ET.SubElement(group_elem, "id").text = str(gid)
        if group_names and i < len(group_names):
            ET.SubElement(group_elem, "name").text = group_names[i]

    return ET.tostring(policy, encoding="utf-8").decode("utf-8")

def deploy_swift_dialog(active_groups):
    """
    Updating the Swift Dialog Policy to inform users their update is required
    
    :param active_groups: list of group IDs that is used to modify policy
    """

    logger.info("Deploying Swift Dialog policy to active groups...")

    # Set variable for policy ID
    swift_dialog_policy_id = os.environ.get("swift_policy_id")

    # Build out the XML for the policy
    policy_scope_xml = build_policy_scope_xml(active_groups)

    try:
        response = sandbox.classic.policies.update_by_id(
            target_id = swift_dialog_policy_id,
            updated_configuration = policy_scope_xml
        )
    except:
        logger.critical(f"Updating the Swift Dialog Policy failed: {response.status_code}")

def main():
    json_data = get_sofa_data()
    os_data = get_os_data(json_data)
    is_minor = determine_os_difference(os_data)
    os_to_update, active_groups, rings, release_date = set_deployment_ring(is_minor, os_data)
    install_date = calculate_install_date(active_groups, rings, is_minor, release_date)
    update_smart_groups(os_to_update)
    create_deployment_plan(active_groups, os_to_update, install_date)
    deploy_swift_dialog(active_groups)

if __name__ == "__main__":
    main()