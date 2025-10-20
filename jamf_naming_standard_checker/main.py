import os
import helpers
import sys
import requests
from dotenv import load_dotenv
import jamfpy

load_dotenv()

JP_URL=os.environ.get("jamf_url")
CLIENT_ID=os.environ.get("client_id")
CLIENT_SECRET=os.environ.get("client_secret")

sandbox = jamfpy.Tenant(
    fqdn=JP_URL,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    auth_method="oauth2",
    token_exp_threshold_mins=1
)

NAMING_STANDARDS = {
    "policy": {
        "prefix": "pcy-",
        "separator": "-",
    },
    "config": {
        "prefix": "mcp-",
        "separator": "_",
    },
    "group": {
        "prefix": "scp-",
        "separator": "-",
    },
    "script": {
        "prefix": "scr",
        "separator": "-"
    }
}

def refine_policies(naming_standard: str, known_prefixes: list[str]):
    policies = sandbox.classic.policies.get_all().json()

    updated_policies = helpers.rename_object(policies.get("policies"),
                                             naming_standard,
                                             "policy",
                                             known_prefixes)

    for policy in updated_policies:

        policy_xml = helpers.build_policy_xml(name=policy.get("name"))

        response = sandbox.classic.policies.update_by_id(
            target_id=policy.get("id"),
            updated_configuration=policy_xml)


def main():
    known_prefixes = ["pcy", "tf", "scr", "app", "mcp", "mca", "scg", "acs", "pse"]

    refine_policies(NAMING_STANDARDS, known_prefixes)


if __name__ == "__main__":
    main()
