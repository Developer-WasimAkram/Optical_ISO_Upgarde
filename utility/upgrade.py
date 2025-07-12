import re
import logging

class UpgradeValidator:
    def __init__(
        self,
        conn,    # SSH connection object
        min_required_gb=1.5,
        iso_package_files=None,  # Changed to list type for multiple files
        scp_source_ip="10.0.10.2",scp_user="admin", scp_password="admin_password"):
        
        # Initialize the UpgradeValidator with connection and parameters
        self.conn = conn
        self.min_required_gb = min_required_gb
        self.iso_package_files = iso_package_files if iso_package_files else ["SMU"]
        self.scp_source_ip = scp_source_ip
        self.scp_user = scp_user
        self.scp_password = scp_password
        self.operation_id = None  # Store the operation ID here

        # Set up logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        
        # Create a file handler for logging
        file_handler = logging.FileHandler("logs/upgrade_validator.log")
        file_handler.setLevel(logging.DEBUG)
        
        # Create a stream handler to print log messages to the console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Set up a formatter for both handlers
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to the logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)



    def validate(self):
        try:
            # Check FPD status
            self._check_fpd_status()

            # Check disk space
            self._check_disk_space()

            # Check if ISO is present, else transfer it
            if not self._check_iso_presence():
                # Attempt to transfer ISO
                if not self._transfer_iso():
                    # Return False if ISO transfer fails, indicating validation failure
                    self.logger.error("ISO transfer failed. Halting further execution.")
                    return False  # Stop execution here if transfer fails

            # Validate package installation
            self._validate_package_installation()

            # Activate installation
            self._activate_installation()
            # Verify activation
            self._verify_activation()
            # Verify commit
            self._verify_commit()
            # Check FPD status after commit
            self._check_fpd_status_after_commit

            return True  # Everything succeeded
        except Exception as e:
            self.logger.error(f"Validation process failed: {str(e)}")
            return False  # Return False if an exception occurs



       

    def _check_fpd_status(self):
        self.logger.info("[CHECK] FPD status...")
        fpd_output = self.conn.send_command("show hw-module location all fpd")
        non_current = [
            line.strip()
            for line in fpd_output.splitlines()
            if re.search(r"\s+(RLOAD REQ|NA)\s+", line)
        ]
        if non_current:
            self.logger.error("[FAIL] FPD entries not ready for upgrade:")
            for line in non_current:
                self.logger.error(f" - {line}")
            raise ValueError("FPD validation failed.")
        self.logger.info("[PASS] All FPD statuses are CURRENT.")

    def _check_disk_space(self):
        self.logger.info("[CHECK] Disk space...")
        media_output = self.conn.send_command("show media location all")
        match = re.search(r"^harddisk:\s+([\d.]+)([GM])", media_output, re.MULTILINE)
        if not match:
            raise ValueError("Could not find 'harddisk:' line in output.")

        value, unit = match.groups()
        value = float(value)
        available_gb = value if unit == 'G' else value / 1024
        self.logger.info(f"[INFO] Available harddisk space: {available_gb:.2f} GB")

        if available_gb < self.min_required_gb:
            self.logger.error(f"[FAIL] Insufficient space: only {available_gb:.2f} GB available.")
            raise ValueError(f"[FAIL] Insufficient space: only {available_gb:.2f} GB available.")
        self.logger.info("[PASS] Sufficient harddisk space available.")

    def _check_iso_presence(self):
        self.logger.info("[CHECK] ISO file presence...")
        self.conn.send_command_timing("run", strip_prompt=False)
        self.conn.send_command_timing("cd /harddisk:", strip_prompt=False)
        ls_output = self.conn.send_command_timing("ls -ltra", strip_prompt=False)

        for iso in self.iso_package_files:
            if iso in ls_output:
                self.logger.info(f"[PASS] ISO file '{iso}' is present on /harddisk:")
                return True
        return False

    def _transfer_iso(self):
        for iso in self.iso_package_files:
            self.logger.info(f"[INFO] ISO file '{iso}' not found. Starting SCP transfer...")

            # Construct SCP command
            scp_cmd = f"scp {self.scp_user}@{self.scp_source_ip}:/harddisk/{iso} ."
            
            try:
                # Send SCP command and capture output
                scp_output = self.conn.send_command_timing(scp_cmd, strip_prompt=False)

                # Check for password prompt
                if "password:" in scp_output.lower():
                    scp_output += self.conn.send_command_timing(self.scp_password, strip_prompt=False)

                # Check for errors like 'No such file' or 'Permission denied'
                if "No such file" in scp_output or "Permission denied" in scp_output:
                    self.logger.error(f"[FAIL] SCP transfer failed:\n{scp_output}")
                    raise RuntimeError(f"[FAIL] SCP transfer failed for ISO '{iso}':\n{scp_output}")

                # Confirm that the file was transferred successfully
                confirm = self.conn.send_command_timing("ls -ltra", strip_prompt=False)
                if iso in confirm:
                    self.logger.info(f"[PASS] ISO file '{iso}' transferred successfully.")
                else:
                    self.logger.error(f"[FAIL] ISO file '{iso}' not found after SCP.")
                    raise FileNotFoundError(f"[FAIL] ISO file '{iso}' not found after SCP.")

            except (RuntimeError, FileNotFoundError) as e:
                # Log and raise any exception encountered during the transfer process
                self.logger.error(f"[ERROR] Transfer process failed for ISO '{iso}': {str(e)}")
                raise e  # Re-raise the exception to stop further execution

    
            

    def _validate_package_installation(self):
        # Step 1: Run the install add command for each ISO package
        for iso in self.iso_package_files:
            install_cmd = f"install add source harddisk:/ {iso}"
            self.logger.info(f"[INFO] Running installation command: {install_cmd}")
            install_output = self.conn.send_command(install_cmd)

            # Step 2: Capture the operation number from the install command output
            self.operation_id = self._capture_operation_id(install_output)  # Save operation ID here
            if not self.operation_id:
                self.logger.error(f"[FAIL] Could not capture operation ID for {iso} from install command output.")
                raise RuntimeError(f"[FAIL] Could not capture operation ID for {iso} from install command output.")
            
            self.logger.info(f"[INFO] Captured operation ID for {iso}: {self.operation_id}")

            # Step 3: Track the installation progress using the show install log
            self._track_installation_progress(self.operation_id)

    def _capture_operation_id(self, install_output):
        """
        Private method to capture the operation number from the installation output.
        
        Args:
            install_output (str): The output from the install add command.
        
        Returns:
            str: The captured operation number, or None if not found.
        """
        match = re.search(r"Install operation (\d+)", install_output)
        if match:
            return match.group(1)
        return None

    def _track_installation_progress(self, operation_id):
        """
        Private method to track installation progress and verify successful completion.
        
        Args:
            operation_id (str): The operation ID captured from the install command.
        
        Returns:
            bool: Returns True if the installation completes successfully, otherwise raises an exception.
        """
        self.logger.info("[INFO] Tracking installation progress...")

        # Use the show install log command to track the installation
        show_log_cmd = f"show install log {operation_id}"
        log_output = self.conn.send_command(show_log_cmd)

        # Search for the specific operation ID in the log output
        if f"Install operation {operation_id} finished successfully" in log_output:
            self.logger.info(f"[PASS] Install operation {operation_id} finished successfully.")
            return True
        
        # If not found or installation not finished, raise an error
        self.logger.error(f"[FAIL] Install operation {operation_id} did not finish successfully.")
        raise RuntimeError(f"[FAIL] Install operation {operation_id} did not finish successfully.")

    def _activate_installation(self):
        """
        Activate the installation using the operation number stored in self.operation_id.
        """
        if not self.operation_id:
            self.logger.error("[FAIL] No operation ID found for activation.")
            raise RuntimeError("[FAIL] No operation ID found for activation.")

        self.logger.info("[INFO] Activating installation...")

        # Run the activation command using the stored operation_id
        activate_cmd = f"install activate id {self.operation_id}"
        
        # Execute the command to activate the installation
        self.logger.info(f"[INFO] Running activation command: {activate_cmd}")
        activate_output = self.conn.send_command(activate_cmd)
        
        # Check the output for success
        if "Install operation will continue in the background" in activate_output:
            self.logger.info(f"[PASS] Installation operation {self.operation_id} activated successfully.")
        else:
            self.logger.error(f"[FAIL] Installation activation failed for operation {self.operation_id}.")
            raise RuntimeError(f"[FAIL] Installation activation failed for operation {self.operation_id}.")
        
        
        
    def _verify_version_in_output(self, output, expected_version):
        """
        Verify if the expected version is present in the output.

        Args:
            output (str): The output of a command, typically a multi-line string.
            expected_version (str): The version to check in the command output.

        Raises:
            RuntimeError: If the expected version is not found.
        """
        self.logger.info(f"[CHECK] Verifying version {expected_version} in the output...")

        # Regular expression to search for the expected version in the output
        pattern = re.compile(r"(\S+)-(\d+\.\d+\.\d+)(?:[^\n]*)")  # Match package names with versions
        found_versions = re.findall(pattern, output)

        # Check if any of the found versions match the expected version
        matching_versions = [pkg for pkg, ver in found_versions if ver == expected_version]
        
        if matching_versions:
            self.logger.info(f"[PASS] Found expected version(s) {expected_version} in the output.")
        else:
            self.logger.error(f"[FAIL] Expected version {expected_version} not found in the output.")
            raise RuntimeError(f"[FAIL] Expected version {expected_version} not found in the output.")
        
        
        
        
    def _verify_activation(self):
        self.logger.info("[CHECK] Verifying activation...")

        # Check active packages
        active_output = self.conn.send_command("show install active summary")
        expected_version = "7.1.1"  # Example version to check
        self._verify_version_in_output(active_output, expected_version)

        # Check active packages in admin mode
        admin_active_output = self.conn.send_command("admin show install active summary")
        self._verify_version_in_output(admin_active_output, expected_version)

    def _verify_commit(self):
        self.logger.info("[CHECK] Verifying commit...")

        # Check committed packages
        committed_output = self.conn.send_command("show install committed")
        expected_version = "7.1.1"  # Example version to check
        self._verify_version_in_output(committed_output, expected_version)

        # Check committed packages in admin mode
        admin_committed_output = self.conn.send_command("admin show install committed")
        self._verify_version_in_output(admin_committed_output, expected_version)

    def _check_fpd_status_after_commit(self):
        """
        Checks the FPD status and triggers an upgrade if needed.
        If reload is required, it triggers a reload command.
        """
        self.logger.info("[CHECK] FPD status...")

        fpd_output = self.conn.send_command("show hw-module location all fpd")
        
        # Check for FPD devices that need upgrade or reload
        upgrade_needed = []
        reload_needed = []
        for line in fpd_output.splitlines():
            if "NEED UPGD" in line:
                upgrade_needed.append(line)
            if "RLOAD REQ" in line:
                reload_needed.append(line)
        
        # Handle FPD upgrade
        if upgrade_needed:
            self.logger.error("[FAIL] The following FPD devices need upgrade:")
            for line in upgrade_needed:
                self.logger.error(f" - {line}")
            self.logger.info("[INFO] Triggering upgrade for FPDs that need upgrade...")
            upgrade_cmd = "hw-module location all fpd all upgrade"
            upgrade_output = self.conn.send_command(upgrade_cmd)
            self.logger.info(f"[INFO] Upgrade command output: {upgrade_output}")

        # Handle FPD reload if required
        if reload_needed:
            self.logger.error("[FAIL] The following FPD devices require reload:")
            for line in reload_needed:
                self.logger.error(f" - {line}")
            self.logger.info("[INFO] Triggering reload for FPDs that require reload...")
            reload_cmd = "admin hw-module location 0/RP0 reload"
            reload_output = self.conn.send_command(reload_cmd)
            self.logger.info(f"[INFO] Reload command output: {reload_output}")

        # After upgrade/reload, verify all devices are in CURRENT state
        self._verify_fpd_current_state()


    def _verify_fpd_current_state(self):
        """
        Verifies that all FPD devices are in CURRENT state after upgrade or reload.
        """
        self.logger.info("[CHECK] Verifying all FPD devices are in CURRENT state...")
        
        fpd_output = self.conn.send_command("show hw-module location all fpd")
        non_current = [
            line.strip()
            for line in fpd_output.splitlines()
            if "NEED UPGD" in line or "RLOAD REQ" in line
        ]
        
        if non_current:
            self.logger.error("[FAIL] The following FPD devices are not in CURRENT state:")
            for line in non_current:
                self.logger.error(f" - {line}")
            raise RuntimeError("[FAIL] FPD devices are not in CURRENT state.")
        
        self.logger.info("[PASS] All FPD devices are in CURRENT state.")
