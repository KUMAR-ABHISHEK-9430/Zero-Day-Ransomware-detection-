import os

def traverse_recursive(directory):
    try:
        # os.scandir is highly optimized for performance
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    print(f"Folder: {entry.path}")
                    # Recursive function call to dive into the subdirectory
                    traverse_recursive(entry.path)
                elif entry.is_file():
                    print(f"File: {entry.path}")
    except PermissionError:
        # Ignore folders that require admin/root privileges
        pass

traverse_recursive("./my_directory")
