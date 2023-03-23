"""
This script copies files from one directory (e.g., external hard disk) to another while avoiding duplicates,
regardless of the directory structure. It skips files specified in a skip list file and hidden files/folders.
The script also generates a separate shell script to delete duplicate files on the target disk and logs all
actions performed during the file copy process.

Functions:
    - hash_file: Calculate the SHA-256 hash of a file.
    - read_skip_list: Read the skip list file and return a set of file paths to be skipped.
    - copy_files: Copy files from the source directory to the destination directory, avoiding duplicates.
    - delete_duplicates: Generate a shell script to delete duplicate files in the destination directory.
    - log_actions: Print the contents of the log file.
    - main: Main function to execute the script.

Usage:
    Set the paths for source, destination, log file, delete script, and skip list file in the main() function.
    Run the script to copy files, generate the delete script, and log actions.
"""

import fnmatch
import json
import os
import shutil
import hashlib
import shlex
from pathlib import Path
import concurrent.futures


def process_file(src, dst, log, skip_list, progress, progress_lock, root, file):
    source_file = os.path.join(root, file)
    target_file = os.path.join(dst, os.path.relpath(source_file, src))

    # Check if the file is in the skip list
    if any(fnmatch.fnmatch(source_file, pattern) for pattern in skip_list):
        return

    # Check if the file has been processed already
    with progress_lock:
        if source_file in progress:
            return

    # Calculate the file hash and check for duplicates
    file_hash = hash_file(source_file)

    with progress_lock:
        if file_hash in progress.values():
            log.write(f"DUPLICATE: {source_file}\n")
        else:
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            shutil.copy(source_file, target_file)
            log.write(f"COPIED: {source_file} -> {target_file}\n")
            progress[source_file] = file_hash

            # Save progress
            with open(progress_file, "w") as f:
                json.dump(progress, f)


def copy_files(src, dst, log_path, skip_list_path, max_workers=10):
    # Load skip list
    with open(skip_list_path, "r") as f:
        skip_list = f.read().splitlines()

    # Check for progress file and load it
    progress_file = "progress.json"
    progress = {}
    if os.path.exists(progress_file):
        with open(progress_file, "r") as f:
            progress = json.load(f)

    progress_lock = concurrent.futures.thread.Lock()

    # Open the log file for appending
    with open(log_path, "a") as log:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for root, _, files in os.walk(src):
                # Process files concurrently
                futures = [executor.submit(process_file, src, dst, log, skip_list, progress, progress_lock, root, file)
                           for file in files]
                concurrent.futures.wait(futures)



"""
    Calculate the SHA-256 hash of a given file.
    Args:
        file_path (str): Path to the file to be hashed.
    Returns:
        str: The SHA-256 hash of the file.
"""
def hash_file(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


"""
    Read the skip list file and return a set of file paths to be skipped.
    Args:
        skip_list_path (str): Path to the skip list file.
    Returns:
        set: A set of file paths to be skipped.
"""

def read_skip_list(skip_list_path):
    with open(skip_list_path, "r") as skip_list_file:
        skip_list = {line.strip() for line in skip_list_file}
    return skip_list



"""
    Copy files from the source directory to the destination directory, avoiding duplicates
    and skipping files specified in the skip list. Log actions in a log file.
    Args:
        src (str): Path to the source directory.
        dst (str): Path to the destination directory.
        log_path (str): Path to the log file.
        skip_list (set): A set of file paths to be skipped.
"""
def copy_files(src, dst, log_path, skip_list_path):
    # Load skip list
    with open(skip_list_path, "r") as f:
        skip_list = f.read().splitlines()

    # Check for progress file and load it
    progress_file = "progress.json"
    progress = {}
    if os.path.exists(progress_file):
        with open(progress_file, "r") as f:
            progress = json.load(f)

    # Open the log file for appending
    with open(log_path, "a") as log:
        for root, _, files in os.walk(src):
            for file in files:
                source_file = os.path.join(root, file)
                target_file = os.path.join(dst, os.path.relpath(source_file, src))

                # Check if the file is in the skip list
                if any(fnmatch.fnmatch(source_file, pattern) for pattern in skip_list):
                    continue

                # Check if the file has been processed already
                if source_file in progress:
                    continue

                # Calculate the file hash and check for duplicates
                file_hash = hash_file(source_file)
                if file_hash in progress.values():
                    log.write(f"DUPLICATE: {source_file}\n")
                else:
                    os.makedirs(os.path.dirname(target_file), exist_ok=True)
                    shutil.copy(source_file, target_file)
                    log.write(f"COPIED: {source_file} -> {target_file}\n")
                    progress[source_file] = file_hash

                # Save progress
                with open(progress_file, "w") as f:
                    json.dump(progress, f)

"""
    Generate a shell script to delete duplicate files in the destination directory.
    Args:
        dst (str): Path to the destination directory.
        delete_script_path (str): Path to the delete script file.
"""
def delete_duplicates(dst, delete_script_path):
    file_hashes = {}
    with open(delete_script_path, "w") as delete_script:
        delete_script.write("#!/bin/sh\n\n")
        for root, _, files in os.walk(dst):
            for file in files:
                target_file = os.path.join(root, file)
                file_hash = hash_file(target_file)

                if file_hash not in file_hashes:
                    file_hashes[file_hash] = target_file
                else:
                    delete_script.write(f"rm {shlex.quote(target_file)}\n")

def log_actions(log_path):
    with open(log_path, "r") as log_file:
        print(log_file.read())

"""
    Main function to execute the script. Set the paths for source, destination, log file,
    delete script, and skip list. Copy files, generate delete script, and log actions.
"""

def main():
    src = ""
    dst = ""
    log_path = "file_transfer_log.txt"
    delete_script_path = "delete_duplicates.sh"
    skip_list_path = "skip_list.txt"

    skip_list = read_skip_list(skip_list_path)
    copy_files(src, dst, log_path, skip_list_path)
    delete_duplicates(dst, delete_script_path)
    log_actions(log_path)

if __name__ == "__main__":
    main()