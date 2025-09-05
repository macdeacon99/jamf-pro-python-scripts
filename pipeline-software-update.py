import os
from dotenv import load_dotenv
import jamfpy
from pprint import pprint
import requests
import os
import requests
import shutil
import json
from datetime import datetime, timezone

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

global json_data

def get_tenant():
    global sandbox
    sandbox = jamfpy.Tenant(
        fqdn                        = JP_URL,
        auth_method                 = "oauth2",
        client_id                   = CLIENT_ID,
        client_secret               = CLIENT_SECRET,
        token_exp_threshold_mins    = 1
    )

def get_sofa_data():
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

def get_os_data(json_data):

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

def determine_os_difference(os_data):
    latest_version = os_data[0]
    latest_os = latest_version["update"].split()[-1]

    previous_version = os_data[1]
    previous_os = previous_version["update"].split()[-1]

    minor = compare_versions(previous_os, latest_os)

    return minor

def version_to_tuple(version_str):
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
    
def set_deployment_ring(is_minor, os_data):

    # Define some variables from Environment Variables
    MINOR_FINAL_DELAY = os.environ.get("minor_final_delay")
    MAJOR_FINAL_DELAY = os.environ.get("major_final_delay")

    # Check days since previous deployment for update, then scope specific groups
    latest_os = os_data[0]
    previous_os = os_data[1]
    days_since_previous_release = calculate_days(previous_os["release_date"])
    days_since_latest_release = calculate_days(latest_os["release_date"])
    
    if is_minor:
        if days_since_previous_release < int(MINOR_FINAL_DELAY):
            print("Previous update not finished")
            os_to_update = previous_os["update"].split()[-1]
            deployment_ids = calculate_deployment_ids(days_since_previous_release, is_minor)
        else:
            print("Previous update finished, continuing...")
            os_to_update = latest_os["update"].split()[-1]
            deployment_ids = calculate_deployment_ids(days_since_latest_release, is_minor)
    elif not is_minor:
        if days_since_previous_release < int(MAJOR_FINAL_DELAY):
            print("Previous update not finished")
            os_to_update = previous_os["update"].split()[-1]
            deployment_ids = calculate_deployment_ids(days_since_previous_release, is_minor)
        else:
            print("Previous update finished, continuing...")
            os_to_update = latest_os["update"].split()[-1]
            deployment_ids = calculate_deployment_ids(days_since_latest_release, is_minor)
    
    return os_to_update, deployment_ids

def calculate_deployment_ids(days_past, is_minor):
    # Define Variables
    TEST_RING_ID = int(os.environ.get("test_ring_id"))

    FIRST_RING_ID = int(os.environ.get("first_ring_id"))
    FIRST_MINOR_DELAY = int(os.environ.get("first_minor_delay"))
    FIRST_MAJOR_DELAY = int(os.environ.get("first_major_delay"))

    FAST_RING_ID = int(os.environ.get("fast_ring_id"))
    FAST_MINOR_DELAY = int(os.environ.get("fast_minor_delay"))
    FAST_MAJOR_DELAY = int(os.environ.get("fast_major_delay"))

    BROAD_RING_ID = int(os.environ.get("broad_ring_id"))
    BROAD_MINOR_DELAY =int(os.environ.get("broad_minor_delay"))
    BROAD_MAJOR_DELAY = int(os.environ.get("broad_major_delay"))

    if is_minor:
        if days_past < FIRST_MINOR_DELAY:
            # Test Ring
            active_groups = [TEST_RING_ID]
        elif days_past >= FIRST_MINOR_DELAY and days_past < FAST_MINOR_DELAY:
            # First Ring 
            active_groups = [TEST_RING_ID, FIRST_RING_ID]
        elif days_past >= FAST_MINOR_DELAY and days_past < BROAD_MINOR_DELAY:
            # Fast Ring 
            active_groups = [TEST_RING_ID, FIRST_RING_ID, FAST_RING_ID]
        elif days_past >= BROAD_MINOR_DELAY:
            # Broad Ring 
            active_groups = [TEST_RING_ID, FIRST_RING_ID, FAST_RING_ID, BROAD_RING_ID]
    elif not is_minor:
        if days_past < FIRST_MAJOR_DELAY:
            # Test Ring
            active_groups = [TEST_RING_ID]
        elif days_past >= FIRST_MAJOR_DELAY and days_past < FAST_MAJOR_DELAY:
            # First Ring 
            active_groups = [TEST_RING_ID, FIRST_RING_ID]
        elif days_past >= FAST_MAJOR_DELAY and days_past < BROAD_MAJOR_DELAY:
            # Fast Ring 
            active_groups = [TEST_RING_ID, FIRST_RING_ID, FAST_RING_ID]
        elif days_past >= BROAD_MAJOR_DELAY:
            # Broad Ring 
            active_groups = [TEST_RING_ID, FIRST_RING_ID, FAST_RING_ID, BROAD_RING_ID]
    
    return active_groups

    
def calculate_days(release_date):

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

def update_smart_groups():
    print("updating groups")

def create_deployment_plan():
    print("creating plan")

def deploy_swift_dialog():
    print("deploying dialog")

def main():
    get_tenant()
    json_data=get_sofa_data()
    os_data = get_os_data(json_data)
    is_minor = determine_os_difference(os_data)
    os_to_update, active_groups = set_deployment_ring(is_minor, os_data)
    update_smart_groups()
    create_deployment_plan()
    deploy_swift_dialog()

if __name__ == "__main__":
    main()