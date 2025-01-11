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
        # Run the DIE console command to analyze the file
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        result = subprocess.run([detectiteasy_console_path, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for Nuitka executable and OneFile
        if "Packer: Nuitka[OneFile]" in result.stdout:
            logging.info(f"File {file_path} is a Nuitka OneFile executable.")
            return "Nuitka OneFile"
        elif "Packer: Nuitka" in result.stdout:
            logging.info(f"File {file_path} is a Nuitka executable.")
            return "Nuitka"
        else:
            logging.info(f"File {file_path} is not a Nuitka executable. Result: {result.stdout}")

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return None
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return None

    return None

def scan_directory_for_executables(directory):
    """Recursively scan a directory for .dll and .exe files and check if they are Nuitka executables, then check other files."""
    found_executables = []
    
    # First, look for .dll files
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.dll'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))

    # Then, look for .exe files
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.exe'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
    
    # Finally, check other files (non .exe and non .dll) for Nuitka executability
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if not file.lower().endswith(('.exe', '.dll')):  # Skip .exe and .dll files
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                else:
                    # Optionally log files that are not Nuitka executables
                    logging.info(f"Found file that is not a Nuitka executable: {file_path}")

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

# Function to scan code for links (domains, IPs, URLs)
def scan_code_for_links(code):
    """
    Scan a given string of code for domains, IP addresses, URLs, and Discord webhook/Discord invite URLs.
    """
    try:
        # Regular expressions for different patterns
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        url_pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        discord_webhook_pattern = r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
        discord_invite_pattern = r'https://discord\.gg/[A-Za-z0-9]+'

        # Perform scans
        ip_matches = re.findall(ip_pattern, code)
        domain_matches = re.findall(domain_pattern, code)
        url_matches = re.findall(url_pattern, code)
        discord_webhook_matches = re.findall(discord_webhook_pattern, code)
        discord_invite_matches = re.findall(discord_invite_pattern, code)

        # Logging the findings
        if ip_matches:
            logging.info(f"IP addresses detected: {ip_matches}")
        if domain_matches:
            logging.info(f"Domains detected: {domain_matches}")
        if url_matches:
            logging.info(f"URLs detected: {url_matches}")
        if discord_webhook_matches:
            logging.warning(f"Discord webhook URLs detected: {discord_webhook_matches}")
        if discord_invite_matches:
            logging.info(f"Discord invite links detected: {discord_invite_matches}")

    except Exception as ex:
        logging.error(f"Error scanning code for links: {ex}")

def scan_rsrc_directory(extracted_files):
    """
    Scans all files in the extracted_files list for .rsrc\\RCDATA, extracts
    the full content, cleans it, and performs scans for domains, URLs, 
    IP addresses, and Discord webhooks.

    :param extracted_files: List of files extracted by 7z.
    """
    try:
        for extracted_file in extracted_files:
            # Check if the file path contains .rsrc\RCDATA
            if ".rsrc\\RCDATA" in extracted_file or ".rsrc/RCDATA" in extracted_file:
                logging.info(f"Processing RCDATA file: {extracted_file}")

                # Ensure the path refers to an actual file
                if os.path.isfile(extracted_file):
                    try:
                        # Read the full content of the file, handling invalid UTF-8 gracefully
                        with open(extracted_file, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                            if lines:
                                # Clean each line by removing non-printable characters
                                cleaned_lines = [clean_text(line.strip()) for line in lines]

                                # Save the full cleaned content to a uniquely named file
                                base_name = os.path.splitext(os.path.basename(extracted_file))[0]
                                save_path = os.path.join(nuitka_source_code_dir, f"{base_name}_full_content.txt")
                                counter = 1
                                while os.path.exists(save_path):
                                    save_path = os.path.join(
                                        nuitka_source_code_dir, f"{base_name}_full_content_{counter}.txt"
                                    )
                                    counter += 1

                                # Write all cleaned lines to the file
                                with open(save_path, "w", encoding="utf-8") as save_file:
                                    for line in cleaned_lines:
                                        save_file.write(line + '\n')
                                logging.info(f"Saved full content from {extracted_file} to {save_path}")

                                # Join the full content for scanning purposes
                                rsrc_content = ''.join(lines)

                                # Perform the scans
                                scan_code_for_links(rsrc_content)

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
            
            # Extract the file name (without extension) to include in the folder name
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]
            
            # Find the next available directory number for OneFile extraction
            folder_number = 1
            while os.path.exists(os.path.join(nuitka_dir, f"OneFile_{file_name_without_extension}_{folder_number}")):
                folder_number += 1
                
            # Create the new directory with the executable file name and folder number
            nuitka_output_dir = os.path.join(nuitka_dir, f"OneFile_{file_name_without_extension}_{folder_number}")

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
                for exe_path in found_executables:
                        logging.info(f"Found normal Nuitka executable in extracted files: {exe_path}")
                        exe_type = "Nuitka"
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