import sys
import os
import time
import subprocess

def main():
    """
    This script is designed to be called by the main application to perform an update.
    It waits for the main app to close, replaces the old executable with the new one,
    and then relaunches the application with a flag to confirm success.
    """
    try:
        old_exe_path = sys.argv[1]
        new_exe_path = sys.argv[2]

        # 1. Wait for the main application to exit
        time.sleep(3)

        # 2. Rename the old executable (to be safe)
        backup_path = old_exe_path + ".bak"
        if os.path.exists(backup_path):
            os.remove(backup_path)
        os.rename(old_exe_path, backup_path)

        # 3. Rename the new executable to the original name
        os.rename(new_exe_path, old_exe_path)

        # 4. Relaunch the new executable with a confirmation flag.
        subprocess.Popen([old_exe_path, "--updated"])

    except IndexError:
        log_error("Error: Not enough arguments provided. Usage: python updater.py <old_path> <new_path>")
    except Exception as e:
        log_error(f"An unexpected error occurred during update: {e}")

def log_error(message):
    """Writes an error message to a log file for debugging."""
    with open("updater_error.log", "w") as f:
        f.write(message)

if __name__ == "__main__":
    main()

