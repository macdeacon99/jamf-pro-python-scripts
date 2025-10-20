import re
import xml.etree.ElementTree as ET
from xml.dom import minidom

def rename_object(resources: dict, naming_standard: dict, object_type: str, known_prefixes: list[str]) -> dict:
    """
    Takes in a name of an object from Jamf Pro and returns a new name in the format of a naming standard.

    Parameters:
      resources              : Name of the object (string).
      naming_standard   : Naming standard to follow (string).
      object_type       : The type of object being passed to the function (string).

    Returns:
      A string of the new name following the naming standard
    """

    clean_type = object_type.lower()

    for resource in resources:

        old_name = resource.get("name")
        clean_name = old_name.lower()

        rules = naming_standard.get(clean_type)
        if not rules:
            raise ValueError(f"No naming standard defined for object type: {clean_type}")
        
        name_no_prefix = remove_existing_prefix(clean_name, known_prefixes)
        words = re.split(r"[\s\-\_]+", name_no_prefix)
        base_title = " ".join(words).strip()

        formatted_title = re.sub(r"\s+", rules["separator"], base_title)

        new_name = f"{rules["prefix"]}{formatted_title}"

        if not validate_name(new_name):
            raise ValueError(f"Invalid name generated: {new_name}")
        resource.update({"name": new_name})
    return resources

def remove_existing_prefix(name: str, known_prefixes: list[str]) -> str:
    pattern = r"^(" + "|".join(re.escape(p) for p in known_prefixes) + r")(?=[-_]|$)"
    return re.sub(pattern, "", name, flags=re.IGNORECASE)

def validate_name(name: str, max_length: int = 255) -> bool:
    if len(name) > max_length:
        return False
    if not re.match(r"^[\w\s\-\_]+$", name):
        return False
    return True

def build_policy_xml(
    name: str,
    category: str = "Unknown",
    enabled: bool = True,
    trigger: str = "EVENT",
    all_computers: bool = False,
    computer_groups: list[int] = None,
    packages: list[dict] = None,
    scripts: list[dict] = None,
) -> str:
    """
    Builds Jamf Policy XML for the Classic API.
    
    Args:
        name (str): Name of the policy.
        category (int): Policy category ID.
        enabled (bool): Whether the policy is enabled.
        trigger (str): Trigger event (e.g., 'EVENT', 'RECURRING_CHECKIN', 'LOGIN').
        all_computers (bool): Whether it targets all computers.
        computer_groups (list[int]): List of smart/static group IDs.
        packages (list[dict]): List of package dicts: [{'name': 'Example.pkg', 'action': 'Install'}].
        scripts (list[dict]): List of script dicts: [{'name': 'Script.sh', 'priority': 'Before', 'parameter4': 'value'}].
    
    Returns:
        str: XML string representing the policy.
    """

    # --- Root element ---
    policy = ET.Element("policy")

    # --- General section ---
    general = ET.SubElement(policy, "general")
    ET.SubElement(general, "name").text = name
    ET.SubElement(general, "enabled").text = str(enabled).lower()
    ET.SubElement(general, "trigger").text = trigger

    category_elem = ET.SubElement(general, "category")
    ET.SubElement(category_elem, "name").text = category

    # --- Scope section ---
    scope = ET.SubElement(policy, "scope")
    ET.SubElement(scope, "all_computers").text = str(all_computers).lower()

    if not all_computers and computer_groups:
        cg_elem = ET.SubElement(scope, "computer_groups")
        for group_name in computer_groups:
            group_elem = ET.SubElement(cg_elem, "computer_group")
            ET.SubElement(group_elem, "name").text = group_name

    # --- Packages section ---
    if packages:
        pkgs_elem = ET.SubElement(policy, "packages")
        for pkg in packages:
            pkg_elem = ET.SubElement(pkgs_elem, "package")
            ET.SubElement(pkg_elem, "name").text = pkg.get("name")
            ET.SubElement(pkg_elem, "action").text = pkg.get("action", "Install")

    # --- Scripts section ---
    if scripts:
        scripts_elem = ET.SubElement(policy, "scripts")
        for scr in scripts:
            scr_elem = ET.SubElement(scripts_elem, "script")
            ET.SubElement(scr_elem, "name").text = scr.get("name")
            ET.SubElement(scr_elem, "priority").text = scr.get("priority", "After")

            # Add parameter values dynamically
            for key, val in scr.items():
                if key.startswith("parameter"):
                    ET.SubElement(scr_elem, key).text = val

    # --- Format XML with indentation ---
    rough_string = ET.tostring(policy, encoding="utf-8")
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")