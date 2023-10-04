#!/usr/bin/env python
"""
NetFoundry Router Upgrade
"""

import argparse
import logging
import os
import sys
import json
import tarfile
import subprocess
import yaml
from tqdm import tqdm
import semantic_version as sv
import requests
import urllib3

def start_upgrade(requested_version,
                  auto=False,
                  override=False):
    """
    Upgrade
    """
    logging.debug("Starting Upgrade")
    service_list = ["ziti-router", "ziti-tunnel"]
    running_version = get_print_versions(override,requested_version)
    downgrade_check(requested_version, running_version)

    # compare and process if necessary
    if sv.Version(running_version) < sv.Version(requested_version) or override:
        if override:
            print("Override Requested, forcing version: " + requested_version)
        else:
            print("Controller is higher than Local")

        if not auto:
            upgrade = query_yes_no("Would you like to proceed with the upgrade?")
        else:
            upgrade = True

        if upgrade:
            # stop services
            for service in service_list:
                # stop service
                stop_start_services("stop", service)

            # check to make sure systemd is compatible with the version
            check_update_systemd(requested_version)

            # download and extract file
            download_bundle(requested_version)

            for service in service_list:
                # check if service is enabled
                service_enabled = run_cmd(["systemctl", "is-enabled", service])
                if "enabled" in service_enabled.stdout:
                    stop_start_services("start", service)
                    logging.debug("Started Service: %s", service)
            print("Upgraded successfully")
    else:
        print("Already up to date")

def check_update_systemd(ziti_version):
    """
    Check
    """
    binary_list=['router','tunnel']
    if sv.Version(ziti_version) >= sv.Version("0.27.0"):
        logging.debug("Version os 0.27.0 or above..Checking systemd")
        for binary_name in binary_list:
            file_path = "/opt/netfoundry/ziti/ziti-" + binary_name + "/ziti-" + binary_name
            if os.path.isfile(file_path):
                logging.debug("Found older binary for: ziti-%s", binary_name)
                update_systemd_unitfile(binary_name)
                os.remove(file_path)

def downgrade_check(requested_version, running_version):
    """
    Check if this is going from anything above 0.27.0 and attempting to go below.
    """
    if sv.Version(running_version) >= sv.Version("0.27.0"):
        if sv.Version(requested_version) < sv.Version("0.27.0"):
            print("\033[0;31mERROR: Unable to downgrade, version is lower than 0.27.0")
            sys.exit(1)

def download_bundle(ziti_version):
    """
    Download ziti bundle & extract files
    """
    download_url=("https://github.com/openziti/ziti/releases/download/v" + ziti_version +
                  "/ziti-linux-amd64-" + ziti_version + ".tar.gz")
    try:
        print("Downloading bundle")
        file_name="router_upgrade.tar.gz"
        response = requests.get(download_url, stream=True, timeout=120)
        if response.ok:
            total_size = int(response.headers.get("content-length", 0))
            block_size = 1024  # 1 Kibibyte
            status_bar = tqdm(total=total_size, unit="iB", unit_scale=True, desc="Downloading")
            with open(file_name, "wb") as open_file:
                for data in response.iter_content(block_size):
                    status_bar.update(len(data))
                    open_file.write(data)
            status_bar.close()


            logging.debug("Download successful, opening tar file")
            with tarfile.open(file_name) as download_file:
                for member in download_file.getmembers():
                    if member.isreg():
                        member.name = os.path.basename(member.name)
                        if os.path.isfile("/opt/netfoundry/ziti/ziti-router/ziti-router"):
                            if member.name == "ziti-router":
                                logging.debug("Extracting: %s", member.name)
                                download_file.extract(member, "/opt/netfoundry/ziti/ziti-router/")
                        if os.path.isfile("/opt/netfoundry/ziti/ziti-tunnel/ziti-tunnel"):
                            if member.name == "ziti-tunnel":
                                logging.debug("Extracting: %s", member.name)
                                download_file.extract(member, "/opt/netfoundry/ziti/ziti-tunnel/")
                        if member.name == "ziti":
                            logging.debug("Extracting: %s", member.name)
                            download_file.extract(member, "/opt/netfoundry/ziti/")
                            os.chmod('/opt/netfoundry/ziti/ziti', 0o755)
                os.remove(file_name)
                return None
        if response.status_code == 404:
            print("\033[0;31mERROR:\033[0m Unable to find version")
            sys.exit(1)
        else:
            print("\033[0;31mERROR:\033[0m Failed to retrive bundle: ", response.status_code)
            sys.exit(1)
    except OSError as exceptions:
        print("\033[0;31mERROR:\033[0m Unable to download binaries: ", exceptions)
        sys.exit(1)

def exit_gracefully():
    """
    Exit gracefully on Keyboard Interrupt
    """
    print('\nDetected Ctrl+C! exiting script!')
    sys.exit(0)

def extract_controller_ip():
    """
    Get the controller ip from the config
    """
    config_map = {"/opt/netfoundry/ziti/ziti-router/config.yml":"ziti-router",
                "/opt/netfoundry/ziti/ziti-tunnel/ziti-tunnel":"ziti-tunnel"}

    # try to find controller info
    for config, binary in config_map.items():
        if os.path.isfile(config):
            with open(config, "r",encoding='UTF-8') as file:
                if binary == "ziti-router":
                    logging.debug("Trying to open router config")
                    try:
                        yaml_content = yaml.load(file, Loader=yaml.FullLoader)
                        controller_info = yaml_content["ctrl"]["endpoint"]
                        controller_ip = controller_info.split(":")[1]
                        logging.debug("Controller IP: %s", controller_ip)
                    except yaml.YAMLError:
                        logging.debug("Unable to read config format")
                        print("\033[0;31mERROR:\033[0m Unable extract IP from config")
                        sys.exit(1)
                else:
                    try:
                        json_content = json.loads(file.read())
                        controller_info = json_content["ztAPI"]
                        controller_ip = controller_info.split(":")[1].lstrip("/")
                        logging.debug("Controller IP: %s", controller_ip)
                    except json.JSONDecodeError:
                        logging.debug("Unable to read config format")
                        print("\033[0;31mERROR:\033[0m Unable extract IP from config")
                        sys.exit(1)
    return controller_ip

def get_print_versions(override, requested_version):
    """
    Create a version map & print out versions
    """
    binary_map = {
                  "/opt/netfoundry/ziti/ziti-router/ziti-router": "ziti-router",
                  "/opt/netfoundry/ziti/ziti-tunnel/ziti-tunnel": "ziti-tunnel",
                  "/opt/netfoundry/ziti/ziti": "ziti"
                  }
    version_map = {}
    for path, binary_name in binary_map.items():
        logging.debug("Checking binary %s", binary_name)
        if os.path.isfile(path):
            binary_version = run_version_command(binary_name)
            version_map[binary_name]=binary_version
            print(binary_name + " version: " + binary_version)
    if not override:
        print("ControllerVersion: ", requested_version)

    return version_map['ziti']

def get_ziti_controller_version(controller_url):
    """
    Get the Ziti Controller Version by posting against /version endpoint
    """
    response = None
    http_code = 0
    try:
        endpoint_url = controller_url + "/edge/v1/version"
        logging.debug('Attempting to access %s', endpoint_url)
        urllib3.disable_warnings()
        response = requests.get(endpoint_url, verify=False, timeout=30)
        http_code = response.status_code
        logging.debug('HTTP Response STATUS CODE: %s', http_code)
        try:
            result = json.loads(response.text)
            version = result['data']['version'].split("v")[1]
            logging.debug('Found version %s', version)
        except json.decoder.JSONDecodeError:
            print("\033[0;31mERROR:\033[0m Unable to parse response from server")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("\033[0;31mERROR:\033[0m Unable to communicate with controller")
        sys.exit(1)
    return version

def root_check():
    """
    Check to see if this is running as root
    """
    if os.geteuid() >= 1:
        print("\033[0;31mERROR:\033[0m This script must be run with root privileges"
              ", please use sudo or run as root")
        sys.exit(1)

def run_cmd(cmd, cwd="/"):
    """
    Run an OS command
    """
    logging.debug("Running command: %s", cmd)
    try:
        command_output = subprocess.run(cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        check=True,
                                        cwd=cwd,
                                        universal_newlines=True)
        std_output = command_output.stdout.splitlines()
        logging.debug("Standard Output:")
        for line in std_output:
            logging.debug('%s', line)
        err_output = command_output.stderr.splitlines()
        logging.debug("Error Output:")
        for line in err_output:
            logging.debug('%s', line)
        return command_output
    except subprocess.CalledProcessError as error_output:
        logging.debug(error_output)
        return error_output

def run_version_command(binary_name):
    """
    Get the local version of a ziti binary
    """
    #logging.debug("Running %s version command for: ", binary_name)
    if binary_name == "ziti":
        version_output = run_cmd(["/opt/netfoundry/ziti/ziti",
                                             "--version"])
    elif binary_name == "ziti-router":
        version_output = run_cmd(["/opt/netfoundry/ziti/ziti-router/ziti-router",
                                             "version"])
    elif binary_name == "ziti-tunnel":
        version_output = run_cmd(["/opt/netfoundry/ziti/ziti-tunnel/ziti-tunnel",
                                             "version"])
    version = version_output.stdout.split("v")[1]
    #logging.debug("%s version: %s", binary_name, version)
    return version.strip()

def update_systemd_unitfile(binary_name):
    """
    Update systemd unit file to use single binary
    """
    service_unit = "/etc/systemd/system/ziti-" + binary_name + ".service"
    logging.debug("Update systemd unit file")
    print("\033[0;31mWARN:\033[0m Upgraded to 0.27.0 and above. You can't use this program to downgrade to lower versions")
    try:
        with open(service_unit, 'r',encoding='UTF-8') as openfile:
            lines = openfile.readlines()
        # Find the line to update
        for i, line in enumerate(lines):
            if line.startswith('ExecStart='):
                if binary_name == "router":
                    lines[i] = ("ExecStart=/opt/netfoundry/ziti/ziti router run /opt/netfoundry/ziti/ziti-router/config.yml\n")
                if binary_name == "tunnel":
                    lines[i] = 'ExecStart=/opt/netfoundry/ziti/ziti tunnel run\n'
                break
        else:
            print("\033[0;31mERROR:\033[0m Unable to find the line to update")
            sys.exit(1)

        with open(service_unit, 'w',encoding='UTF-8') as openfile:
            openfile.writelines(lines)

    except FileNotFoundError:
        print("\033[0;31mERROR:\033[0m Please check that the file exists and try again.")
    logging.debug("Finished updating file")
    run_cmd(["systemctl", "daemon-reload"])

def stop_start_services(action, service):
    """
    Start ziti-router services
    """
    if action == "start":
        logging.debug("Starting the service: %s", service)
        run_cmd(["systemctl", "restart", service])

    elif action == "stop":
        logging.debug("Stopping the service: %s", service)
        try:
            run_cmd(["systemctl", "stop", service])
        except OSError:
            # shouldn't be here.. but if it is..let's keep going
            logging.debug("Stopping the %s service failed", service)

def query_yes_no(question, default="yes"):
    """This function handles the yes/no questions"""
    valid = {"yes": True, "y": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError(f"invalid default answer: {default}")

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        if choice in valid:
            return valid[choice]
        sys.stdout.write("Please respond with 'yes' or 'no' "
                            "(or 'y' or 'n').\n")

def main():
    """
    Main logic
    """
    __version__ = '1.2.0'
    #  Change log
    #  See https://github.com/netfoundry/edge-router-upgrade/blob/main/CHANGELOG.md

    # argument parser
    parser = argparse.ArgumentParser()
    # arguments
    parser.add_argument('-y', '--yes',
                        dest='auto',
                        action='store_true',
                        help='automatically answer yes to upgrade prompt')
    parser.add_argument('-o', '--override_version',
                        help='override the controller version')
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='enable debug log in log file output')
    parser.add_argument('-v', '--version',
                        action='version',
                        version=__version__)

    # get arguments passed
    args = parser.parse_args()

    # enable debug if requested
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    # define logging information
    logging.basicConfig(format='%(asctime)s-%(levelname)s-%(message)s',
                        datefmt='%Y-%m-%d-%H:%M:%S',
                        level=log_level
                        )

    # run root check
    root_check()

    auto_upgrade = bool(args.auto)

    controller_ip = extract_controller_ip()

    # determine version
    if args.override_version:
        requested_version = args.override_version
        override = True
    else:
        requested_version = get_ziti_controller_version("https://" + controller_ip)
        override = False

    start_upgrade(requested_version,
                  auto_upgrade,
                  override)

    # exit properly
    sys.exit(0)

# main
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit_gracefully()
