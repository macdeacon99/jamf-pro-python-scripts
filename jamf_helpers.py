import xml.etree.ElementTree as ET
from xml.dom import minidom

def build_static_computer_group_xml(
    name: str,
    computer_ids: list,
    group_id: int | None = None,
    description: str | None = None,
    site_id: int = -1
) -> str:
    """
    Build and return a pretty-printed XML string for a Jamf Pro static computer group.

    Parameters:
      name          : Name of the group (string).
      computer_ids  : Iterable of Jamf computer IDs (integers or strings).
      group_id      : Optional Jamf group ID (useful when updating an existing group).
      description   : Optional description text.
      site_id       : Jamf site id (-1 for global/default).

    Returns:
      A Unicode string containing the XML document (including XML declaration).
    """

    # Root
    root = ET.Element("computer_group")

    # Optional group id (for update operations)
    if group_id is not None:
        id_el = ET.SubElement(root, "id")
        id_el.text = str(group_id)

    # Required fields
    name_el = ET.SubElement(root, "name")
    name_el.text = str(name)

    is_smart_el = ET.SubElement(root, "is_smart")
    is_smart_el.text = "false"  # static group

    # Optional description
    if description:
        desc_el = ET.SubElement(root, "description")
        desc_el.text = str(description)

    # Site block (Jamf expects a site element with id)
    site_el = ET.SubElement(root, "site")
    site_id_el = ET.SubElement(site_el, "id")
    site_id_el.text = str(site_id)

    # Computers container
    computers_el = ET.SubElement(root, "computers")

    # Append each computer as <computer><id>...</id></computer>
    for cid in computer_ids:
        comp_el = ET.SubElement(computers_el, "computer")
        comp_id_el = ET.SubElement(comp_el, "id")
        comp_id_el.text = str(cid)

    # Serialize to string and pretty-print
    rough = ET.tostring(root, encoding="utf-8")
    reparsed = minidom.parseString(rough)
    pretty_xml = reparsed.toprettyxml(indent="  ", encoding="utf-8")

    # toprettyxml returns bytes when encoding provided; decode to str
    return pretty_xml.decode("utf-8")