from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor
import os
import time
import logging
from utility.upgrade import UpgradeValidator

import threading


app = Flask(__name__)
OUTPUT_DIR = "outputs"
LOG_DIR = "logs"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Logger setup
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "automation.log"),
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
    level=logging.INFO
)
logger = logging.getLogger("UpgradeAutomation")



DEVICE_TYPE = "cisco_ios"
MAX_THREADS = 10.   # Maximum number of concurrent threads take from GUI 
device_status = {}


@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Read device IPs from uploaded file
        device_file = request.files['device_ips_file']
        device_data = device_file.read().decode('utf-8')
        devices = device_data.splitlines()

        # Read precheck commands from uploaded file
        precheck_file = request.files['precheck_file']
        precheck_data = precheck_file.read().decode('utf-8')
        precheck = precheck_data.splitlines()

        # Read upgrade commands from uploaded file
        upgrade_file = request.files['upgrade_file']
        upgrade_data = upgrade_file.read().decode('utf-8')
        upgrade = upgrade_data.splitlines()

        # Read postcheck commands from uploaded file
        postcheck_file = request.files['postcheck_file']
        postcheck_data = postcheck_file.read().decode('utf-8')
        postcheck = postcheck_data.splitlines()

        # Initialize device statuses
        for device in devices:
            device_status[device] = {
                'status': 'Queued',
                'precheck': 'Waiting',
                'upgrade': 'Waiting',
                'postcheck': 'Waiting',
                'failure_reason': None
            }

        # Launch background threads after response
        def launch_threads():
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                for device in devices:
                    executor.submit(run_device_task, device, username, password, precheck, upgrade, postcheck)

        threading.Thread(target=launch_threads).start()

        return redirect(url_for('progress'))

    return render_template('upload.html')


@app.route('/progress')
def progress():
    return render_template('progress.html', device_status=device_status)


DEVICE_TYPE = "cisco_xr"
OUTPUT_DIR = "outputs"
device_status = {}


def run_device_task(device, username, password, precheck, upgrade, postcheck):
    try:
        device_status[device]['status'] = 'Connecting'
        connection = ConnectHandler(device_type=DEVICE_TYPE, ip=device, username=username, password=password)
        device_status[device]['status'] = 'Connected'
        logger.info(f"[{device}] Connected successfully.")

        # ▶ PRECHECK
        try:
            logger.info(f"[{device}] Running precheck...")
            device_status[device]['precheck'] = 'Running'

            output_list = []  # List to store the output of each precheck command
            for cmd in precheck:
                logger.info(f"[{device}] Sending precheck command: {cmd}")
                output = connection.send_command(cmd, read_timeout=60)
                logger.info(f"[{device}] Precheck command output:\n{output}")
                output_list.append(f"Command: {cmd}\nOutput:\n{output}\n")

            filename = f"{device}_precheck.txt"
            with open(os.path.join(OUTPUT_DIR, filename), 'w') as f:
                for item in output_list:
                    f.write(item + "\n")
            device_status[device]['precheck'] = filename
            logger.info(f"[{device}] Precheck completed.")

        except Exception as e:
            logger.exception(f"[{device}] Precheck failed.")
            device_status[device]['precheck'] = f"Failed"
            device_status[device]['failure_reason'] = str(e)  # Store failure reason
            device_status[device]['status'] = 'Failed'
            connection.disconnect()
            return

        # ▶ UPGRADE VALIDATION + EXECUTION
        try:
            logger.info(f"[{device}] Validating upgrade requirements...")
            device_status[device]['upgrade'] = 'Running'

            validator = UpgradeValidator(connection)
            if not validator.validate():
                device_status[device]['upgrade'] = f"Failed: Validation"
                device_status[device]['failure_reason'] = "Upgrade validation failed"  # Capture failure reason
                logger.error(f"[{device}] Upgrade validation failed. Halting upgrade.")
                # Upgrade validation failed, mark postcheck as failed
                device_status[device]['postcheck'] = 'Failed'
                return

            logger.info(f"[{device}] Validation passed. Running upgrade...")

            output_list = []  # List to store the output of each upgrade command
            for cmd in upgrade:
                logger.info(f"[{device}] Sending upgrade command: {cmd}")
                output = connection.send_command(cmd, read_timeout=60)
                logger.info(f"[{device}] Upgrade command output:\n{output}")
                output_list.append(f"Command: {cmd}\nOutput:\n{output}\n")

            filename = f"{device}_upgrade.txt"
            with open(os.path.join(OUTPUT_DIR, filename), 'w') as f:
                for item in output_list:
                    f.write(item + "\n")
            device_status[device]['upgrade'] = filename
            logger.info(f"[{device}] Upgrade completed.")

        except Exception as e:
            logger.exception(f"[{device}] Upgrade failed.")
            device_status[device]['upgrade'] = f"Failed"
            device_status[device]['failure_reason'] = str(e)  # Capture failure reason
            print(f"[UPGRADE ERROR] {device}: {e}")
            # Upgrade failed, mark postcheck as failed
            device_status[device]['postcheck'] = 'Failed'
            return

        # ▶ POSTCHECK
        try:
            # If upgrade failed, skip postcheck entirely
            if device_status[device]['upgrade'] == "Failed":
                logger.info(f"[{device}] Skipping postcheck due to upgrade failure.")
                device_status[device]['postcheck'] = 'Failed'
                return

            logger.info(f"[{device}] Running postcheck...")
            device_status[device]['postcheck'] = 'Running'
            output_list = []  # List to store the output of each postcheck command
            for cmd in postcheck:
                logger.info(f"[{device}] Sending postcheck command: {cmd}")
                output = connection.send_command(cmd, read_timeout=60)
                logger.info(f"[{device}] Postcheck command output:\n{output}")
                output_list.append(f"Command: {cmd}\nOutput:\n{output}\n")

            filename = f"{device}_postcheck.txt"
            with open(os.path.join(OUTPUT_DIR, filename), 'w') as f:
                for item in output_list:
                    f.write(item + "\n")
            device_status[device]['postcheck'] = filename
            logger.info(f"[{device}] Postcheck completed.")
        except Exception as e:
            logger.exception(f"[{device}] Postcheck failed.")
            device_status[device]['postcheck'] = f"Failed"
            device_status[device]['failure_reason'] = str(e)  # Capture failure reason
            print(f"[POSTCHECK ERROR] {device}: {e}")

        # Finalize
        connection.disconnect()

        # Do not overwrite main status on upgrade/postcheck errors
        if device_status[device]['status'] == 'Connected':
            device_status[device]['status'] = 'Connected'

    except Exception as e:
        logger.exception(f"[{device}] Connection/setup failed.")
        device_status[device]['status'] = f"Failed: {e}"
        device_status[device]['failure_reason'] = str(e)  # Capture failure reason


      
@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)
        
@app.route('/view/<filename>')
def view_output(filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return "File not found", 404
    with open(filepath, 'r') as f:
        content = f.read()
    return render_template('view_output.html', filename=filename, content=content)
      
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

