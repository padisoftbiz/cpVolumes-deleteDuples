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

import os
import shutil
import hashlib
import shlex
from pathlib import Path

"""
    Calculate the SHA-256 hash of a given file.
    Args:
        file_path (str): Path to the file to be hashed.
    Returns:
        str: The SHA-256 hash of the file.
"""
def hash_file(file_path):
    with open(file_path, "rb") as file:
        file_hash = hashlib.sha256()
        while chunk := file.read(8192):
            file_hash.update(chunk)
    return file_hash.hexdigest()


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
def copy_files(src, dst, log_path, skip_list):
    file_hashes = set()
    src = os.path.abspath(src)
    dst = os.path.abspath(dst)
    with open(log_path, "w") as log_file:
        for root, _, files in os.walk(src):
            for file in files:
                source_file = os.path.join(root, file)
                rel_path = os.path.relpath(root, src)
                target_dir = os.path.normpath(os.path.join(dst, rel_path))
                target_file = os.path.join(target_dir, file)
                relative_source_file = os.path.relpath(source_file, src)

                if file.startswith('.') or any(part.startswith('.') for part in Path(source_file).parts):
                    log_file.write(f"SKIPPED HIDDEN: {source_file}\n")
                    continue

                if relative_source_file in skip_list:
                    log_file.write(f"SKIPPED: {source_file}\n")
                    continue
                
                file_hash = hash_file(source_file)

                if file_hash not in file_hashes:
                    file_hashes.add(file_hash)
                    if not os.path.exists(target_dir):
                        os.makedirs(target_dir)
                    shutil.copy(source_file, target_file)
                    log_file.write(f"COPIED: {source_file} -> {target_file}\n")
                else:
                    log_file.write(f"DUPLICATE: {source_file} -> {target_file}\n")


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
    src = "/Volumes/My Passport"
    dst = "/Volumes/NO NAME"
    log_path = "file_transfer_log.txt"
    delete_script_path = "delete_duplicates.sh"
    skip_list_path = "skip_list.txt"

    skip_list = read_skip_list(skip_list_path)
    copy_files(src, dst, log_path, skip_list)
    delete_duplicates(dst, delete_script_path)
    log_actions(log_path)

if __name__ == "__main__":
    main()
