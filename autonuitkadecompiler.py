import os
import logging
import subprocess
import shutil
import inspect
import string
import re

# Set up logging
logging.basicConfig(level=logging.INFO)

# Define required paths (adjust accordingly)
script_dir = os.getcwd()
nuitka_extractor_path = os.path.join(script_dir, "nuitka-extractor", "nuitka-extractor.exe")
seven_zip_path = "C:\\Program Files\\7-Zip\\7z.exe"  # Path to 7z.exe
detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
nuitka_source_code_dir = os.path.join(script_dir, "nuitkasourcecode")
nuitka_dir = os.path.join(script_dir, "nuitka")
general_extracted_dir = os.path.join(script_dir, "general_extracted")

# Ensure output directories exist
os.makedirs(nuitka_source_code_dir, exist_ok=True)
os.makedirs(nuitka_dir, exist_ok=True)
os.makedirs(general_extracted_dir, exist_ok=True)

def is_nuitka_file(file_path):
    """Check if the file is a Nuitka executable using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        result = subprocess.run([detectiteasy_console_path, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for Nuitka executable and OneFile
        if "Nuitka[OneFile]" in result.stdout:
            logging.info(f"File {file_path} is a Nuitka OneFile executable.")
            return "Nuitka OneFile"
        elif "Nuitka" in result.stdout:
            logging.info(f"File {file_path} is a Nuitka executable.")
            return "Nuitka"
        else:
            logging.info(f"File {file_path} is not a Nuitka executable.")

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return None
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return None

    return None

def scan_directory_for_executables(directory):
    """Recursively scan a directory for .exe files and check if they are Nuitka executables."""
    found_executables = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.exe'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
    return found_executables

def extract_all_files_with_7z(file_path):
    try:
        counter = 1
        base_output_dir = os.path.join(general_extracted_dir, os.path.splitext(os.path.basename(file_path))[0])

        # Ensure output directory is unique
        while os.path.exists(f"{base_output_dir}_{counter}"):
            counter += 1

        output_dir = f"{base_output_dir}_{counter}"
        os.makedirs(output_dir, exist_ok=True)

        logging.info(f"Attempting to extract file {file_path} into {output_dir}...")

        # Run the 7z extraction
        command = [seven_zip_path, "x", file_path, f"-o{output_dir}", "-y", "-snl", "-spe"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            logging.error(f"7z extraction failed with return code {result.returncode}: {result.stderr}")
            return []

        logging.info(f"7z extraction successful for {file_path}.")

        # Gather all files in the output directory after extraction
        extracted_files = []
        for root, _, files in os.walk(output_dir):
            for name in files:
                extracted_files.append(os.path.join(root, name))

        if not extracted_files:
            logging.warning(f"No files were extracted from {file_path}.")
        else:
            logging.info(f"Extracted {len(extracted_files)} files from {file_path}.")

        return extracted_files

    except Exception as ex:
        logging.error(f"Error during 7z extraction: {ex}")
        return []

def clean_text(input_text):
    """
    Remove non-printable ASCII control characters from the input text.

    :param input_text: The string to clean.
    :return: Cleaned text with control characters removed.
    """
    # Remove non-printable characters (ASCII 0-31 and 127)
    cleaned_text = re.sub(r'[\x00-\x1F\x7F]+', '', input_text)
    return cleaned_text

def scan_rsrc_directory(extracted_files):
    """
    Look for files whose paths contain .rsrc\\RCDATA and process them.
    Extract the last 11 lines of these files, clean them, and save them for further processing.

    :param extracted_files: List of files extracted by 7z.
    :param nuitka_source_code_dir: Directory to save the cleaned last lines.
    """
    try:
        for extracted_file in extracted_files:
            # Check if the file path contains .rsrc\RCDATA
            if ".rsrc\\RCDATA" in extracted_file or ".rsrc/RCDATA" in extracted_file:
                logging.info(f"Processing RCDATA file: {extracted_file}")

                # Ensure the path refers to an actual file
                if os.path.isfile(extracted_file):
                    try:
                        # Read the last 11 lines of the file, handling invalid UTF-8 gracefully
                        with open(extracted_file, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                            if lines:
                                # Get the last 11 lines and ensure they are kept intact
                                last_lines = lines[-11:]

                                # Clean each line by removing non-printable characters
                                last_lines_cleaned = [clean_text(line.strip()) for line in last_lines]

                                # Do not log the actual content of the last lines, just a message
                                logging.info(f"Extracted and cleaned last 11 lines from {extracted_file}.")

                                # Save the last lines to a uniquely named file
                                base_name = os.path.splitext(os.path.basename(extracted_file))[0]
                                save_path = os.path.join(nuitka_source_code_dir, f"{base_name}_last_lines.txt")
                                counter = 1
                                while os.path.exists(save_path):
                                    save_path = os.path.join(
                                        nuitka_source_code_dir, f"{base_name}_last_lines_{counter}.txt"
                                    )
                                    counter += 1

                                # Write each cleaned line to the file separately
                                with open(save_path, "w", encoding="utf-8") as save_file:
                                    for line in last_lines_cleaned:
                                        save_file.write(line + '\n')
                                logging.info(f"Saved last 11 lines from {extracted_file} to {save_path}")
                            else:
                                logging.info(f"File {extracted_file} is empty.")
                    except Exception as ex:
                        logging.error(f"Error reading file {extracted_file}: {ex}")
                else:
                    logging.warning(f"Path {extracted_file} is not a valid file.")
            else:
                logging.debug(f"Skipping non-RCDATA file: {extracted_file}")

    except Exception as ex:
        logging.error(f"Error during RCDATA file scanning: {ex}")

def extract_nuitka_file(file_path, nuitka_type):
    """
    Detect Nuitka type, extract Nuitka executable content, and scan for additional Nuitka executables.

    :param file_path: Path to the Nuitka executable file.
    :param nuitka_type: Type of Nuitka executable ("Nuitka OneFile" or "Nuitka").
    """
    try:  
        if nuitka_type == "Nuitka OneFile":
            logging.info(f"Nuitka OneFile executable detected in {file_path}")
            
            # Find the next available directory number for OneFile extraction
            folder_number = 1
            while os.path.exists(os.path.join(nuitka_dir, f"OneFile_{folder_number}")):
                folder_number += 1
            nuitka_output_dir = os.path.join(nuitka_dir, f"OneFile_{folder_number}")
            
            os.makedirs(nuitka_output_dir, exist_ok=True)

            logging.info(f"Extracting Nuitka OneFile {file_path} to {nuitka_output_dir}")
            
            # Use nuitka_extractor for OneFile extraction
            command = [nuitka_extractor_path, "-output", nuitka_output_dir, file_path]
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode == 0:
                logging.info(f"Successfully extracted Nuitka OneFile: {file_path} to {nuitka_output_dir}")
                
                # Scan the extracted directory for additional Nuitka executables
                logging.info(f"Scanning extracted directory for additional Nuitka executables...")
                found_executables = scan_directory_for_executables(nuitka_output_dir)
                
                # Process any found normal Nuitka executables
                for exe_path, exe_type in found_executables:
                    if exe_type == "Nuitka":
                        logging.info(f"Found normal Nuitka executable in extracted files: {exe_path}")
                        extract_nuitka_file(exe_path, exe_type)
            else:
                logging.error(f"Failed to extract Nuitka OneFile: {file_path}. Error: {result.stderr}")
        
        elif nuitka_type == "Nuitka":
            logging.info(f"Nuitka executable detected in {file_path}")
            
            # Use enhanced 7z extraction
            extracted_files = extract_all_files_with_7z(file_path)

            if extracted_files:
                logging.info(f"Successfully extracted files from Nuitka executable: {file_path}")
                # Scan for RSRC/RCDATA resources
                scan_rsrc_directory(extracted_files)
            else:
                logging.error(f"Failed to extract normal Nuitka executable: {file_path}")
        
        else:
            logging.info(f"No Nuitka content found in {file_path}")
    
    except Exception as ex:
        logging.error(f"Error extracting Nuitka file: {ex}")

# Main script logic to ask for the user input (file path)
if __name__ == "__main__":
    file_path = input("Enter the path to the Nuitka executable file: ")

    # Check if the provided file exists
    if os.path.exists(file_path):
        nuitka_type = is_nuitka_file(file_path)
        if nuitka_type:
            extract_nuitka_file(file_path, nuitka_type)
        else:
            logging.info("The file is not a Nuitka executable.")
    else:
        logging.error(f"The file {file_path} does not exist.")