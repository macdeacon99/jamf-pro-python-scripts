import logging
import jamf_pro_calls
import sofa_helper
import helper_functions as helper


######### To-Do #################
# - Implement email report
# - Create ReadMe.md file
# - Fix get Sofa Data etag
##################################

# --- Configuration ---

logging.basicConfig(
    filename="software_update.log",
    level = logging.DEBUG,
    filemode='w',
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

def main():
    logger.debug("Script starting...")
    json_data = sofa_helper.get_sofa_data()
    os_data = sofa_helper.get_os_data(json_data)
    is_minor, previous_minor = sofa_helper.determine_os_difference(os_data)
    os_to_update, active_groups, rings, release_date = helper.set_deployment_ring(is_minor, os_data, previous_minor)
    install_date = helper.calculate_install_date(active_groups, rings, is_minor, release_date)
    jamf_pro_calls.update_smart_groups(os_to_update)
    jamf_pro_calls.create_deployment_plan(active_groups, os_to_update, install_date)
    jamf_pro_calls.deploy_swift_dialog(active_groups)
    logger.debug("Script finished...")

if __name__ == "__main__":
    main()