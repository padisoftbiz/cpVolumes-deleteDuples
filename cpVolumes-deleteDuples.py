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
import concurrent.futures
import json
import logging
import os
import shutil
import hashlib
import shlex
from pathlib import Path
import threading
from typing import Dict, Set
from threading import Event, Lock

class FileCopier:
    def __init__(self, config_file: str):
        self.config = self.load_config(config_file)
        self.target_hashmap_lock = Lock()
        self.progress_lock = Lock()
        self.file_counter_lock = Lock()
        self.file_counter = 0
        self.target_hashmap: Dict[str, str] = {}
        self.setup_logging()

    def setup_logging(self) -> None:
        logging.basicConfig(filename=self.config.get("log_path", "file_copier.log"),
                            level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def load_config(self, config_file: str) -> Dict:
        try:
            with open(config_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load configuration from {config_file}: {e}")
            raise

    def read_skip_list(self, skip_list_path: str) -> Set[str]:
        try:
            with open(skip_list_path, "r") as file:
                return {line.strip() for line in file}
        except Exception as e:
            logging.error(f"Failed to read skip list from {skip_list_path}: {e}")
            return set()

    @staticmethod
    def hash_file(file_path: str) -> str:
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logging.error(f"Error hashing file {file_path}: {e}")
            return ""

    def generate_target_hashmap(self, dst: str, max_workers: int = 4) -> None:
        def process_target_file(target_file: str) -> None:
            file_hash = self.hash_file(target_file)
            if file_hash:
                with self.target_hashmap_lock:
                    self.target_hashmap[target_file] = file_hash

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for root, _, files in os.walk(dst):
                for file in files:
                    target_file = os.path.join(root, file)
                    futures.append(executor.submit(process_target_file, target_file))
            concurrent.futures.wait(futures)

    def copy_files(self, src: str, dst: str, skip_list_path: str, max_workers: int = 4) -> None:
        skip_list = self.read_skip_list(skip_list_path)
        if not os.path.exists(dst):
            logging.error(f"Destination directory {dst} does not exist.")
            return

        self.generate_target_hashmap(dst, max_workers)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for root, _, files in os.walk(src):
                for file in files:
                    if any(fnmatch.fnmatch(file, pattern) for pattern in skip_list):
                        continue
                    source_file = os.path.join(root, file)
                    target_file = os.path.join(dst, os.path.relpath(source_file, src))
                    executor.submit(self.process_file, source_file, target_file)

    def process_file(self, source_file: str, target_file: str) -> None:
        try:
            file_hash = self.hash_file(source_file)
            if not file_hash or file_hash in self.target_hashmap.values():
                logging.info(f"Skipping duplicate or failed hash file {source_file}")
                return

            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            shutil.copy(source_file, target_file)
            logging.info(f"Copied {source_file} to {target_file}")
            with self.target_hashmap_lock:
                self.target_hashmap[target_file] = file_hash

        except Exception as e:
            logging.error(f"Failed to process file {source_file}: {e}")

    def run(self) -> None:
        if not self.config:
            logging.error("No configuration loaded. Exiting.")
            return

        self.copy_files(self.config["src"], self.config["dst"], self.config["skip_list_path"], self.config["max_workers"])

if __name__ == "__main__":
    try:
        copier = FileCopier("config.json")
        copier.run()
    except Exception as e:
        logging.error(f"An error occurred: {e}")

