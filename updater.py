import sys
import os
import time
import subprocess

def main():
    """
    This script is designed to be called by the main application to perform an update.
    It waits for the main app to close, replaces the old script with the new one,
    and then relaunches the application.
    """
    try:
        old_file_path = sys.argv[1]
        new_file_path = sys.argv[2]

        # 1. Wait for the main application to exit
        time.sleep(2)

        # 2. Replace the old file with the new one
        # On Windows, os.rename can fail if the target exists. os.replace is atomic.
        if sys.platform == "win32":
            os.replace(new_file_path, old_file_path)
        else:
            os.rename(new_file_path, old_file_path)

        # 3. Relaunch the application.
        # Use sys.executable to ensure we use the same python interpreter.
        subprocess.Popen([sys.executable, old_file_path])

    except IndexError:
        log_error("Error: Not enough arguments provided. Usage: python updater.py <old_path> <new_path>")
    except Exception as e:
        log_error(f"An unexpected error occurred: {e}")

def log_error(message):
    """Writes an error message to a log file for debugging."""
    with open("updater_error.log", "w") as f:
        f.write(message)

if __name__ == "__main__":
    main()

