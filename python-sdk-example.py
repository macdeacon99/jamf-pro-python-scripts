import os
from dotenv import load_dotenv
import jamfpy
from pprint import pprint

load_dotenv()

CLIENT_ID       = os.environ.get("client_id")
CLIENT_SECRET   = os.environ.get("client_secret")
JP_URL          = os.environ.get("jamf_url")

sandbox = jamfpy.Tenant(
    fqdn                        = JP_URL,
    auth_method                 = "oauth2",
    client_id                   = CLIENT_ID,
    client_secret               = CLIENT_SECRET,
    token_exp_threshold_mins    = 1,
    log_level                   = 10
)

categories = sandbox.classic.categories.get_all()

pprint(categories.json())