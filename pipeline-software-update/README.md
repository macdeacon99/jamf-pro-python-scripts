# Pipeline Software Update Script

This document outlines the setup of how to use this script to fully automate the Software Update process for macOS devices using Jamf Pro.

## Script Overview

This script uses the SOFA Project to get the latest OS versions as they are released and automatically uses the Managed Software Update feature in Jamf Pro via the API to push the update to devices via a deployment ring style deployment.

The following document will outline the script and the environment variables required to use the script
