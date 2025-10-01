import os
import random
from dotenv import load_dotenv
import jamfpy
import jamf_helpers

load_dotenv()

# Jamf Configuration 
JP_URL = os.environ.get("jamf_url")
CLIENT_ID = os.environ.get("client_id")
CLIENT_SECRET = os.environ.get("client_secret")

# Smart Group Configuration
RING_PERC = [ int(os.environ.get("first_group_perc")),
              int(os.environ.get("fast_group_perc")),
              int(os.environ.get("broad_group_perc"))
]

sandbox = jamfpy.Tenant(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    fqdn=JP_URL,
    auth_method="oauth2",
    token_exp_threshold_mins=1
)

# Get device records
def get_device_records() -> list:
    # computers = sandbox.classic.computers.get_all().json()
    # computer_ids = []
    # for computer in computers["computers"]:
    #     computer_ids.append(computer.get("id"))
    # random.shuffle(computer_ids)
    # return computer_ids

    # Only using this for testing purposes with fake computer records in Jamf
    computers = sandbox.classic.computer_groups.get_by_id(221).json()
    computer_ids = []
    for computer in computers["computer_group"]["computers"]:
        computer_ids.append(computer.get("id"))
    random.shuffle(computer_ids)
    return computer_ids

# Determine IDs of devices based on %'s
def calculate_deployment_rings(computer_ids: list) -> list:
    num_comp = len(computer_ids)

    devices_per_group = []
    for perc in RING_PERC:
        perc = (num_comp / 100) * perc
        devices_per_group.append(round(perc))
    devices_per_group[len(devices_per_group) - 1] = num_comp - (devices_per_group[0] + devices_per_group[1])

    device_lists = [[], [], []]
    starting_index = 0
    for i, devices in enumerate(device_lists):
        device_lists[i] = computer_ids[starting_index:devices_per_group[i]]
        starting_index = devices_per_group[i]

    return device_lists


# Create Smart Groups in Jamf
def create_smart_groups(device: list):
    # loop through each list and create a xml for a static group
    # Then using that XML create a static group

    group_information = {
        "first": {"id": os.environ.get("first_group_id"), "index": 0},
        "fast": {"id": os.environ.get("fast_group_id"), "index": 1},
        "broad": {"id": os.environ.get("broad_group_id"), "index": 2}
    }
    
    for group_name, info in group_information.items():
        group_id = info["id"]
        device_list = device[info["index"]]

        xml_body = jamf_helpers.build_static_computer_group_xml(
            name = group_name,
            group_id = group_id,
            computer_ids = device_list
        )

        response = sandbox.classic.computer_groups.update_by_id(
            group_id,
            xml_body
        )

        if response.status_code == 201:
            print(f"{response.status_code} - {group_name} Updated")
        else:
            print(f"{response.status_code} - {response.text}")

def main():
    # Pull All Device Records
    computers_ids = get_device_records()

    devices_list = calculate_deployment_rings(computers_ids)

    create_smart_groups(devices_list)

if __name__ == "__main__":
    main()
