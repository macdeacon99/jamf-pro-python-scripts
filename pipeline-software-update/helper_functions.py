import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
import pipeline_software_update as software_run

def calculate_days(release_date: str) -> int:
    """
    Helper function to calculate the days since OS release

    :param release_date - string of the release date of the OS version
    :return days_since - int of the amount of days since OS release
    """

    software_run.logger.info("Calculating days since OS has been released...")

    # Convert the string to a datetime object
    past_date = datetime.strptime(release_date, "%Y-%m-%dT%H:%M:%SZ")
    past_date = past_date.replace(tzinfo=timezone.utc)  # ensure it's timezone-aware

    # Get current UTC time
    now = datetime.now(timezone.utc)

    # Calculate the difference
    delta = now - past_date

    # Number of days
    days_since = delta.days

    software_run.logger.debug(f"{days_since} since OS has been released...")

    return days_since

def set_deployment_ring(is_minor: bool, os_data: list, previous_minor: bool):
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

    software_run.logger.info("Setting the deployment rings for update...")
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

    # Pick the right delay - If major, then previous update must have been a minor update
    # set delays to minor delays
    if not is_minor:
        final_delay = delays[not is_minor]
        software_run.logger.debug(f"Major update, setting the previous update delay as minor: {final_delay}")
    else:
        # Check if previous update was a major update, if it was, set delays to major
        final_delay = delays[is_minor] if previous_minor else delays[not is_minor]
        software_run.logger.debug(f"Minor update, checking if previous update was a major, if so, set delay to appropriate final delay: {final_delay}")


    # Decide whether to continue or wait
    if days_since["previous"] < final_delay:
        software_run.logger.debug(f"Only {days_since["previous"]} days since previous update released...")
        software_run.logger.info("Previous update not finished, continuing previous update...")
        os_to_update = previous_os["update"].split()[-1]
        release_date = previous_os["release_date"]
        deployment_ids, rings = calculate_deployment_ids(days_since["previous"], is_minor)
    else:
        software_run.logger.info("Previous update finished, continuing...")
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
        software_run.logger.debug(f"Adding {ring["name"]} to active rings...")
        active_groups.append(ring["id"])

        # Pick the right delay based on minor/major
        delay = ring["minor_delay"] if is_minor else ring["major_delay"]

        # If we haven’t reached this ring’s delay yet, stop
        if days_past < delay:
            break

    return active_groups, rings

def build_smart_group_xml(group_id: int, group_name: str, os_version: str) -> str:
    """
    Build XML for updating a smart group criteria in Jamf Classic API.
    
    :param group_id: ID of the smart group
    :param group_name: Name of the smart group
    :param os_version: New value for the Operating System Version criteria
    :return: XML string
    """
    software_run.logger.info("Creating Smart Group XML...")

    # Root element
    computer_group = ET.Element("computer_group")

    # Basic group info
    ET.SubElement(computer_group, "id").text = str(group_id)
    ET.SubElement(computer_group, "name").text = group_name
    ET.SubElement(computer_group, "is_smart").text = "true"

    # Site (Jamf requires it, even if it's NONE/-1)
    site = ET.SubElement(computer_group, "site")
    ET.SubElement(site, "id").text = "-1"
    ET.SubElement(site, "name").text = "NONE"

    # Criteria
    criteria = ET.SubElement(computer_group, "criteria")
    ET.SubElement(criteria, "size").text = "1"
    criterion = ET.SubElement(criteria, "criterion")
    ET.SubElement(criterion, "name").text = "Operating System Version"
    ET.SubElement(criterion, "priority").text = "0"
    ET.SubElement(criterion, "and_or").text = "and"
    ET.SubElement(criterion, "search_type").text = "less than"
    ET.SubElement(criterion, "value").text = os_version
    ET.SubElement(criterion, "opening_paren").text = "false"
    ET.SubElement(criterion, "closing_paren").text = "false"

    return ET.tostring(computer_group, encoding="utf-8").decode("utf-8")

def calculate_install_date(groups: list, rings:list, is_minor:bool, release_date: str) -> str:
    """
    Function to calculate the final install date to force update

    :param groups - list of groups ids to calculate which ring is being pushed to
    :param rings - list of rings to get data about length of delay to calculate force date
    :param is_minor - boolean to determine if major or minor version update
    :param release_date - string of the release date of the OS version
    :return install_dt - string of the forced install date
    """

    software_run.logger.info("Calculating the force install date...")

    # Parse ISO 8601 date string (with Z at the end for UTC)
    release_dt = datetime.strptime(release_date, "%Y-%m-%dT%H:%M:%SZ")

    # Decide which delay to use based on number of groups and update type
    length = len(groups)
    days = rings[length - 1]["minor_delay"] if is_minor else rings[length - 1]["major_delay"]

    # Add delay
    install_dt = release_dt + timedelta(days=days)

    software_run.logger.debug(f"Force install date will be: {install_dt}")

    # Return in format YYYY-MM-DDTHH:MM:SS
    return install_dt.strftime("%Y-%m-%dT%H:%M:%S")

def build_policy_scope_xml(group_ids: list, group_names: list = None):
    """
    Build XML scope for Jamf policy.
    
    :param group_ids: list of integers (required)
    :param group_names: optional list of strings (same order as group_ids)
    :return: XML string
    """

    software_run.logger.info("Creating Policy XML...")

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
