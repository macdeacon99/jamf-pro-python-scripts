import jamfpy
import pipeline_software_update as software_run
import os
import sys
from dotenv import load_dotenv
import helper_functions as helper
import requests

load_dotenv()

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

def update_smart_groups(os_to_update: str):
    """
    Function to update a smart group of 'Not on the latest OS' so that automation works
    in smart groups to continue to scope only devices that are not on OS that is being updated

    :param os_to_update - string of the OS version that is being pushed
    """

    software_run.logger.info("Creating payload to update 'not on latest OS' smart group...")

    # Get group ID for 'Not on latest OS' smart group
    group_id = os.environ.get("not_on_latest_os_id")
    group_name = os.environ.get("not_on_latest_os_name")

    os_to_update = "16"

    group_xml = helper.build_smart_group_xml(
        group_id = group_id,
        group_name = group_name,
        os_version = os_to_update
    )

    try:
        response = sandbox.classic.computer_groups.update_by_id(
            target_id = group_id,
            updated_configuration = group_xml
        )
    except Exception as e:
        software_run.logger.critical(f"Failed to update the smart group: {e}")
        sys.exit(1)

def create_deployment_plan(groups: list, os_version: str, install_date: str):
    """
    Function to create Software Update Management Plan via SDK

    :param groups - list of groups ids to calculate which ring is being pushed to
    :param os_version - string of the OS Version to use to update
    :param install_date - string of the force install date
    """

    software_run.logger.info("Creating deployment plan...")

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
        requests.post(f"{JP_URL}/api/v1/managed-software-updates/plans/group", json=payload, headers=headers, timeout=10)
    except requests.RequestException as e:
        software_run.logger.critical(f"API was not able to create Software Update Management Plan: {e}")
        sys.exit(1)

def deploy_swift_dialog(active_groups):
    """
    Updating the Swift Dialog Policy to inform users their update is required
    
    :param active_groups: list of group IDs that is used to modify policy
    """

    software_run.logger.info("Deploying Swift Dialog policy to active groups...")

    # Set variable for policy ID
    swift_dialog_policy_id = os.environ.get("swift_policy_id")

    # Build out the XML for the policy
    policy_scope_xml = helper.build_policy_scope_xml(active_groups)

    try:
        response = sandbox.classic.policies.update_by_id(
            target_id = swift_dialog_policy_id,
            updated_configuration = policy_scope_xml
        )
    except Exception as e:
        software_run.logger.critical(f"Updating the Swift Dialog Policy failed: {e}")
        sys.exit(1)