# Deployment Ring Calculator - Requirements

## Problem Statement

Creating deployment rings in **Jamf Pro** currently involves significant manual work and lacks precision. Administrators must manually select or count devices to create static groups or rely on arbitrary identifiers (e.g., UDIDs) to approximate percentage-based deployments. This approach is **inefficient, inconsistent, and prone to human error**, particularly in large-scale environments.

As the organisation transitions to **Configuration as Code (CaC)** practices using **Terraform** and the **Jamf Pro Terraform Provider**, there is a growing need to automate and codify the process of defining deployment rings. The desired outcome is to allow administrators to specify **percentage-based distributions** for deployment rings and automatically generate **Jamf Pro static groups** that reflect those percentages.

However, not all devices should be treated equally during rollouts. Certain users (e.g., executives, VIPs, and critical systems) must always be excluded from early testing rings to avoid unnecessary risk exposure. These devices should be automatically assigned to later-stage (e.g., “Final” or “Production”) rings regardless of the general distribution logic.

Currently, achieving this type of controlled rollout with VIP exclusions requires manual intervention and ongoing maintenance of static groups, which defeats the goal of automation and scalability.

---

## Proposed Solution

Develop a **Python-based automation tool** that:

1. Connects to the **Jamf Pro API** to retrieve the complete managed device inventory.
2. Allows administrators to define **deployment ring percentages** (e.g., 10%, 30%, 60%) for structured rollouts.
3. Supports **priority-based device assignments**, ensuring specific users or groups (e.g., VIPs, executives, business-critical endpoints) are placed in designated rings (e.g., the final “Production” group).
4. Creates or updates **static computer groups** in Jamf Pro to represent each deployment ring.
5. Outputs **Terraform-compatible configuration files** for integration with the Jamf Pro Terraform Provider, maintaining full alignment with CaC principles.
6. Integrates with CI/CD pipelines for automated environment setup and consistent group management.
7. CI/CD Pipeline can use **pre-generated seed** to randomise devices to ensure same devices are placed in groups after each run.

---

## Functional Requirements

### 1. Input Configuration

The tool must accept configuration via CLI or configuration file (YAML/JSON), supporting:

- Jamf Pro instance details (URL, authentication method, API token or credentials).
- Deployment ring definitions, including names and percentage splits e.g.:

```
rings:
    - name: UAT
        percentage: 10
    - name: EarlyAdoption
        percentage: 30
    - name: Production
        percentage: 60
```

- **VIP/Exclusion Lists**, specifying:
  - Device serial numbers, usernames, or Jamf computer IDs that must belong to specific rings.
  - Optionally, a Jamf Smart Group or LDAP group reference containing VIPs.
- Device filtering criteria (e.g., site, department, platform, OS version) if required.

### 2. Data Retrieval

- The tool must query the Jamf Pro API to retrieve:
  - All devices matching the specified filters.
  - Device attributes required for grouping (e.g., serial number, UDID, username, department, site, computer ID).
- The tool must identify and separate VIP/excluded devices based on provided input or API data.

### 3. Ring Calculation

- The tool must:
  - Exclude VIP devices from the general population before performing percentage-based allocation.
  - Distribute remaining devices randomly or deterministically based on the specified ring percentages.
  - Ensure every device appears in exactly one static group.
  - Use a fixed random seed for reproducible distributions.

### 4. Group Creation

- The tool must create or update **static computer groups** in Jamf Pro with names corresponding to each ring.
- Groups must include:
  - Percentage-based members.
  - Manually assigned (VIP/excluded) members where applicable.
- Existing groups should be updated rather than duplicated.

### 5. Terraform Integration

- The tool must generate Terraform configuration files representing:
  - Jamf Pro static groups.
  - Membership assignments (device IDs or serials).
- Output format should be compatible with the Jamf Pro Terraform Provider.
- Optionally, the tool can:
  - Trigger terraform plan or terraform apply.
  - Support a dry-run mode to preview changes.

### 6. VIP Handling

- The tool must support VIP inclusion rules such as:
  - “Always in final ring.”
  - “Never in rings before Early Adoption.”
- These rules should be declarative and version-controlled.
- A configuration example:

```
vip_rules:
    - usernames: ["ceo", "cto", "vp_engineering"]
        assign_to: "Production"
    - departments: ["Executive", "Finance"]
        assign_to: "Production"
```

### 7. Logging & Reporting

- Logs must include:
  - Total devices retrieved.
  - Number of devices assigned per ring.
  - List of VIP devices and their assigned rings.
  - Any skipped or failed assignments.
- A summary report (JSON or text) should be optionally exportable for audit or CI/CD logs.

### 8. Security

- API tokens and credentials must be handled securely via environment variables or credential stores.
- No sensitive data should be written to disk or logs.

### 9. Reproducibility

- The tool must allow a randomisation seed for deterministic output.
- Configuration and ring definitions should be source-controlled and environment-independent.

---

## Non-Functional Requirements

| Category        | Requirement                                                                  |
| --------------- | ---------------------------------------------------------------------------- |
| Language        | Python 3.9+                                                                  |
| Compatibility   | macOS, Linux, Windows                                                        |
| Performance     | Scalable to >10,000 devices                                                  |
| Maintainability | PEP 8 compliant, modular design                                              |
| Extensibility   | Future support for Smart Groups, geography-based rings, or dynamic weighting |
| Documentation   | Comprehensive README, usage examples, and Terraform integration guide        |

## Success Criteria

- Tool creates deployment rings covering 100% of non-VIP devices and correctly places all VIPs in their designated groups.
- Jamf Pro static groups are accurately reflected in Terraform configurations.
- Rollout configurations can be version-controlled and automatically applied via CI/CD.
- Ring creation and updates take minutes, not hours.
- Administrators can confidently perform staged deployments with clear visibility into which devices belong to which ring.
