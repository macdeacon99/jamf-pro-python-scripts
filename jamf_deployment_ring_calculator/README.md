# Jamf Deployment Ring Calculator

A Python utility for creating **deployment rings** in [Jamf Pro](https://www.jamf.com/products/jamf-pro/) using the Jamf Pro API.  
The tool splits your device fleet into **First**, **Fast**, and **Broad** rings based on configurable percentages, then creates or updates static groups in Jamf Pro for rollout scoping.

---

## ✨ Features

- Splits devices into deployment rings by percentage (e.g. 5% → First, 15% → Fast, 80% → Broad).
- Randomizes device assignment to avoid bias.
- Builds valid Jamf Pro XML payloads for static groups.
- Updates existing Jamf Pro static groups via the Classic API.
- Configurable with a environment config file (`.env`).

---

## 📂 Project Structure

The following structure only shows the required files for this project. The overall project has multiple scripts included.

```
jamf_pro_pyhton_scripts/
        ├── jamf_helpers.py
        └──jamf_deployment_ring_calculator/
            ├── init.py
            ├── main.py # Entry point
            ├── jamf_helpers.py # XML builder & Jamf API helpers
            ├── .env # Configuration file (user-editable)
            └── README.md # This file
```

---

## ⚙️ Configuration

All settings are defined in a `.env` file you need to create within the script directory:

```env
# Jamf Pro Settings
client_id="YOUR-CLIENT-ID"
client_secret="YOUR-CLIENT-SECRET"
jamf_url="https://YOUR-JAMF-SITE.jamfcloud.com"

# Deployment Ring Settings - configure to your percentages
first_group_perc=10
fast_group_perc=30
broad_group_perc=60

# Deployment Ring IDs - Configure your static group IDs
first_group_id=217
fast_group_id=220
broad_group_id=218
```

- Jamf Pro Settings: Client ID, Secret and URL for Jamf Pro API
- Deployment Ring Settings: Percentages of each deployment ring
- Deployment Ring IDs: IDs of the Static Groups in Jamf (Set to None if they don't exist yet)

---

## Usage

From the project root, run:

```bash
python -m jamf_deployment_ring_calculator.main
```

This will:

1. Fetch the list of devices from Jamf Pro.
2. Slice devices into **First**, **Fast**, and **Broad** rings.
3. Generate XML payloads for each static group.
4. Update the corresponding groups in Jamf Pro.

## Development

Install dependencies:

**`requirements.txt`**:

```
# Normal PyPI packages
python-dotenv
requests

# From GitHub
git+https://github.com/thejoeker12/jamfpy-python-sdk-jamfpro.git@main
```

```bash
pip install -r requirements.txt
```

Or if you’re using the provided `pyproject.toml`:

```bash
pip install -e .
```

---

## Roadmap

1. Change the script to check for Static Group IDs being set to `None`. If set to `None` then create groups, if not update
2. Add a naming standard to config file and then create in the script
3. Keep up to date

---

## Contributing

PRs and issues welcome! Please open an issue to discuss changes or feature requests before submitting a PR.
