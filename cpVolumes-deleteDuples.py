"""
This script copies files from one directory (e.g., external hard disk) to another while avoiding duplicates,
regardless of the directory structure. It skips files specified in a skip list file and hidden files/folders.
The script also generates a separate shell script to delete duplicate files on the target disk and logs all
actions performed during the file copy process.

Functions:
    - hash_file: Calculate the SHA-256 hash of a file.
    - read_skip_list: Read the skip list file and return a set of file paths to be skipped.
    - process_file: Process a file, calculating its hash and copying it if it is not a duplicate.
    - copy_files: Copy files from the source directory to the destination directory, avoiding duplicates.
    - delete_duplicates: Generate a shell script to delete duplicate files in the destination directory.
    - log_actions: Print the contents of the log file.
    - main: Main function to execute the script.

Usage:
    Set the paths for source, destination, log file, delete script, and skip list file in the main() function.
    Run the script to copy files, generate the delete script, and log actions.
"""
"""
Tool for copying files from one directory to another while avoiding duplicates, skipping hidden files/folders and
files specified in a skip list, and generating a script to delete duplicate files on the target directory.
"""

"""
This script is designed to copy files from a source directory to a destination directory,
while avoiding copying duplicate files and using a skip list to ignore specific files.
"""
import fnmatch
import json
import os
import shutil
import hashlib
import shlex
import concurrent.futures
import threading
from pathlib import Path
import time
from threading import Event

def load_config(config_file):
    # Load the configuration from a JSON file.
    with open(config_file, "r") as f:
        config = json.load(f)
    return config

def read_skip_list(skip_list_path):
    # Read the skip list file and return a set of patterns to skip.
    with open(skip_list_path, "r") as skip_list_file:
        skip_list = {line.strip() for line in skip_list_file}
    return skip_list

def hash_file(file_path):
    # Calculate the SHA-256 hash of a given file.
    hasher = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def generate_target_hashmap(dst, max_workers):
    # Generate a hashmap of file hashes in the destination directory.
    target_hashmap = {}
    hashmap_lock = threading.Lock()

    def process_target_file(target_file):
        file_hash = hash_file(target_file)
        with hashmap_lock:
            target_hashmap[target_file] = file_hash

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for root, _, files in os.walk(dst):
            for file in files:
                target_file = os.path.join(root, file)
                futures.append(executor.submit(process_target_file, target_file))
        concurrent.futures.wait(futures)

    return target_hashmap

def save_target_hashmap(target_hashmap, hashmap_file, stop_event, hashmap_update_interval):
    # Periodically save the target hashmap to a file.
    update_counter = 0
    while not stop_event.is_set():
        time.sleep(hashmap_update_interval)
        with target_hashmap_lock:
            if update_counter >= config["hashmap_update_threshold"]:
                with open(hashmap_file, "w") as f:
                    target_hashmap_copy = target_hashmap.copy()
                    json.dump(target_hashmap_copy, f)
                update_counter = 0
            else:
                update_counter += 1

def copy_files(src, dst, log_path, skip_list_path, max_workers):
    # Copy files from the source directory to the destination directory, avoiding duplicates and using a skip list.
    with open(skip_list_path, "r") as f:
        skip_list = f.read().splitlines()

    progress_file = config["progress_file"]
    progress = {}
    if os.path.exists(progress_file):
        with open(progress_file, "r") as f:
            progress = json.load(f)

    progress_lock = threading.Lock()

    hashmap_file = config["hashmap_file"]
    if os.path.exists(hashmap_file):
        with open(hashmap_file, "r") as f:
            target_hashmap = json.load(f)
    else:
        with open(log_path, "a") as log:
            log.write("Generating target directory hashmap...\n")
        target_hashmap = generate_target_hashmap(dst, max_workers)
        with open(log_path, "a") as log:
            log.write("Target directory hashmap generated.\n")
        with open(hashmap_file, "w") as f:
            json.dump(target_hashmap, f)

    stop_event = Event()
    hashmap_saving_thread = threading.Thread(target=save_target_hashmap, args=(target_hashmap, hashmap_file, stop_event))
    hashmap_saving_thread.start()

    with open(log_path, "a") as log:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for root, _, files in os.walk(src):
                futures = [executor.submit(process_file, src, dst, log, skip_list, progress, progress_lock, target_hashmap, root, file)
                           for file in files]
                concurrent.futures.wait(futures)

    stop_event.set()
    hashmap_saving_thread.join()


def process_file(src, dst, log, skip_list, progress, progress_lock, target_hashmap, root, file):
    # Process a single file in the source directory.
    global file_counter
    source_file = os.path.join(root, file)
    target_file = os.path.join(dst, os.path.relpath(source_file, src))

    if any(fnmatch.fnmatch(source_file, pattern) for pattern in skip_list):
        return

    with progress_lock:
        if source_file in progress:
            return

    file_hash = hash_file(source_file)

    if target_file in target_hashmap and file_hash == target_hashmap[target_file]:
        return
    with progress_lock:
        if file_hash in progress.values():
            log.write(f"DUPLICATE: {source_file}\n")
        else:
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            shutil.copy(source_file, target_file)
            log.write(f"COPIED: {source_file} -> {target_file}\n")
            progress[source_file] = file_hash
            with target_hashmap_lock:
                target_hashmap[target_file] = file_hash

        with file_counter_lock:
            file_counter += 1
            if file_counter % config["file_update_threshold"] == 0:
                with open(progress_file, "w") as f:
                    json.dump(progress, f)
                log.flush()

def delete_duplicates(dst, delete_script_path):
    # Generate a shell script to delete duplicate files in the destination directory.
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
    # Print the content of the log file.
    with open(log_path, "r") as log_file:
        print(log_file.read())

def main():
    # The main function that orchestrates the entire process.
    global config
    config = load_config("config.json")

    src = config["src"]
    dst = config["dst"]
    log_path = config["log_path"]
    delete_script_path = config["delete_script_path"]
    skip_list_path = config["skip_list_path"]

    skip_list = read_skip_list(skip_list_path)
    copy_files(src, dst, log_path, skip_list_path, config["max_workers"])
    delete_duplicates(dst, delete_script_path)
    log_actions(log_path)

if __name__ == "__main__":
    target_hashmap_lock = threading.Lock()
    file_counter = 0
    file_counter_lock = threading.Lock()
    main()

