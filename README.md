# Copy Files Without Duplicates

This Python script is designed to copy files from one directory (e.g., an external hard disk) to another while avoiding duplicates, regardless of the directory structure. It skips files specified in a skip list file and hidden files/folders. The script also generates a separate shell script to delete duplicate files on the target disk and logs all actions performed during the file copy process.

## Features

- Copy files while avoiding duplicates
- Skip files specified in a skip list file
- Skip hidden files and folders
- Generate a shell script to delete duplicate files on the target disk
- Log all actions performed during the copy process

## Prerequisites

- Python 3.x
- Git (optional, for version control)

## How to Use

1. Download the script or clone the repository.
2. Open the script in your favorite code editor.
3. In the `main()` function, set the paths for the following variables:
   - `src`: Source directory
   - `dst`: Destination directory
   - `log_path`: Log file path
   - `delete_script_path`: Path to the delete script file
   - `skip_list_path`: Path to the skip list file (optional)
4. Save the changes and run the script.

## Skip List

The skip list file should contain one file path per line. These file paths should be relative to the source directory. For example, if your source directory is `/Volumes/SourceDisk` and you want to skip the file `/Volumes/SourceDisk/folder/subfolder/skip.txt`, add the following line to your skip list file:

