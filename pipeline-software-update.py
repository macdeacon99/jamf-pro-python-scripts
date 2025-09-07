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
from dicttoxml import dicttoxml
import xml.etree.ElementTree as ET
from xml.dom.minidom import parseString

######### To-Do #################
# - Create logic to update Smart Group
# - Create logic to deploy software management plan
# - create logic for Swift Dialog
# - Implement logging
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

def get_sofa_data() -> str:
    # Ensure local cache folder exists
    os.makedirs(JSON_CACHE_DIR, exist_ok=True)

    # Read the old ETag if it exists
    etag_old = None
    if os.path.exists(ETAG_CACHE):
        with open(ETAG_CACHE, "r") as f:
            etag_old = f.read().strip()

    # Prepare headers
    headers = {"User-Agent": USER_AGENT}
    if etag_old:
        headers["If-None-Match"] = etag_old

    try:
        # Fetch online JSON with conditional GET
        response = requests.get(ONLINE_JSON_URL, headers=headers, timeout=3)
        if response.status_code == 304:
            print("Cached ETag matched online ETag - cached JSON file is up to date")
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
                    print("Cached ETag matched online ETag - cached JSON file is up to date")
                    os.remove(ETAG_CACHE_TEMP)
                else:
                    print("Cached ETag did not match online ETag, downloaded new SOFA JSON file")
                    shutil.move(ETAG_CACHE_TEMP, ETAG_CACHE)
            else:
                print("No ETag returned - JSON cache updated without ETag")
        else:
            print(f"Failed to fetch JSON feed. HTTP Status: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error fetching JSON feed: {e}")

    # Check if the cache file exists
    if os.path.exists(JSON_CACHE):
        with open(JSON_CACHE, "r") as f:
            data = json.load(f)  # parse JSON into Python dict

        with open("output.json", "w") as f:
            print(json.dumps(data, indent=4), file=f)  # writes the string representation to the file
    else:
        print("Cached JSON file not found.")

    return json.dumps(data)

def get_os_data(json_data: str) -> list:

    os_data = json.loads(json_data)

    os_versions = os_data["OSVersions"][0]

    security_releases = os_versions.get("SecurityReleases", [])

    os_list = []

    for release in security_releases:
        os_list.append({
            "update": release["UpdateName"],
            "release_date": release["ReleaseDate"],
            "days_since_previous_release": release["DaysSincePreviousRelease"]
        }) 
    
    return os_list

def determine_os_difference(os_data: list) -> bool:
    latest_version = os_data[0]
    latest_os = latest_version["update"].split()[-1]

    previous_version = os_data[1]
    previous_os = previous_version["update"].split()[-1]

    minor = compare_versions(previous_os, latest_os)

    return minor

def version_to_tuple(version_str: str) -> bool:
    # Split by '.' and convert each part to int
    return tuple(int(part) for part in version_str.split('.'))    

def compare_versions(old, new):
    old_tuple = version_to_tuple(old)
    new_tuple = version_to_tuple(new)
    
    # Compare major version (first number)
    if new_tuple[0] > old_tuple[0]:
        return False
    # Compare minor version (second number)
    elif old != new:
        return True
    else:
        return "No significate update"
    
def set_deployment_ring(is_minor: bool, os_data: list):

    # Define variables from environment
    delays = {
        True: int(os.environ.get("minor_final_delay")),
        False: int(os.environ.get("major_final_delay")),
    }

    latest_os = os_data[0]
    previous_os = os_data[1]

    days_since = {
        "previous": calculate_days(previous_os["release_date"]),
        "latest": calculate_days(latest_os["release_date"]),
    }

    # Pick the right delay
    final_delay = delays[is_minor]

    # Decide whether to continue or wait
    if days_since["previous"] < final_delay:
        print("Previous update not finished")
        os_to_update = previous_os["update"].split()[-1]
        release_date = previous_os["release_date"]
        deployment_ids, rings = calculate_deployment_ids(days_since["previous"], is_minor)
    else:
        print("Previous update finished, continuing...")
        os_to_update = latest_os["update"].split()[-1]
        release_date = latest_os["release_date"]
        deployment_ids, rings = calculate_deployment_ids(days_since["latest"], is_minor)

    return os_to_update, deployment_ids, rings, release_date


def calculate_deployment_ids(days_past: dict, is_minor: bool) -> list:
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

    
def calculate_days(release_date: str) -> str:

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

    group_id = os.environ.get("not_on_latest_os_id")

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

    response = requests.put(f"{JP_URL}/api/v2/computer-groups/smart-groups/{group_id}", json=payload, headers=headers)

def calculate_install_date(groups: list, rings:list, is_minor:bool, release_date: str) -> str:
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
    print("creating plan")

    token = sandbox.pro.auth.token()

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

    response = requests.post(f"{JP_URL}/api/v1/managed-software-updates/plans/group", json=payload, headers=headers)

def build_policy_scope_xml(group_ids, group_names=None):
    """
    Build XML scope for Jamf policy.
    
    :param group_ids: list of integers (required)
    :param group_names: optional list of strings (same order as group_ids)
    :return: XML string
    """
    policy = ET.Element("policy")
    scope = ET.SubElement(policy, "scope")
    computer_groups = ET.SubElement(scope, "computer_groups")

    for i, gid in enumerate(group_ids):
        group_elem = ET.SubElement(computer_groups, "computer_group")
        ET.SubElement(group_elem, "id").text = str(gid)
        if group_names and i < len(group_names):
            ET.SubElement(group_elem, "name").text = group_names[i]

    return ET.tostring(policy, encoding="utf-8").decode("utf-8")

def deploy_swift_dialog(active_groups):

    swift_dialog_policy_id = os.environ.get("swift_policy_id")

    policy_scope_xml = build_policy_scope_xml(active_groups)

    response = sandbox.classic.policies.update_by_id(
        target_id = swift_dialog_policy_id,
        updated_configuration = policy_scope_xml
    )

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