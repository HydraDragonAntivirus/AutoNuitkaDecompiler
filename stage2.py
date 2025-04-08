import os
import sys
import io
import logging
import difflib
from datetime import datetime
from pathlib import Path

# Set script directory
script_dir = os.getcwd()

# Define log directories and files (similar to stage1.py)
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

console_log_file = os.path.join(log_directory, "antivirusconsole.log")
application_log_file = os.path.join(log_directory, "antivirus.log")

logging.basicConfig(
    filename=application_log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Set default encoding for I/O streams
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8', errors='ignore')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8', errors='ignore')
sys.stdin = io.TextIOWrapper(sys.stdin.detach(), encoding='utf-8', errors='ignore')

logging.info("Stage2 application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Define paths
# The signatures file containing known signature text (one signature per line)
SIGNATURES_FILE = os.path.join(script_dir, "signatures.txt")
# Directory where stage1.py stored extracted source code files.
EXTRACTED_SOURCE_DIR = os.path.join(script_dir, "nuitkasourcecode")
# Directory to store filtered output files.
FILTERED_OUTPUT_DIR = os.path.join(script_dir, "filtered_sourcecode")
os.makedirs(FILTERED_OUTPUT_DIR, exist_ok=True)

def load_signatures(signature_filepath):
    """
    Load signature lines from a text file.
    Each non-empty line is considered a signature.
    """
    try:
        with open(signature_filepath, "r", encoding="utf-8") as f:
            signatures = [line.strip() for line in f if line.strip()]
        logging.info("Loaded %d signatures from %s", len(signatures), signature_filepath)
        return signatures
    except Exception as ex:
        logging.error("Failed to load signatures from %s: %s", signature_filepath, ex)
        return []

def filter_source_code(source_filepath, signatures, similarity_threshold=0.90):
    """
    Reads a source code file line by line and filters out lines that match any of the provided
    signatures (using difflib for a similarity ratio). If a line’s similarity to any signature is greater
    than the specified threshold, that line is filtered out.

    :param source_filepath: Path to the source code file.
    :param signatures: List of signature strings to check against.
    :param similarity_threshold: Float value (0.0 - 1.0) specifying how similar a line must be to be removed.
    :return: A list of filtered lines.
    """
    filtered_lines = []
    try:
        with open(source_filepath, "r", encoding="utf-8", errors="ignore") as f:
            source_lines = f.readlines()
    except Exception as ex:
        logging.error("Failed to read source file %s: %s", source_filepath, ex)
        return []

    for line in source_lines:
        line_stripped = line.rstrip()
        remove_line = False
        for sig in signatures:
            # Use difflib.SequenceMatcher to compare the line with a signature
            similarity = difflib.SequenceMatcher(None, line_stripped, sig).ratio()
            if similarity >= similarity_threshold:
                remove_line = True
                logging.debug("Filtered out line: %s (similarity %.2f to signature: %s)", line_stripped, similarity, sig)
                break  # No need to check other signatures for this line
        if not remove_line:
            filtered_lines.append(line_stripped)
    return filtered_lines

def process_source_file(source_filepath, signatures):
    """
    Process a single source code file: filter it and save the filtered result into FILTERED_OUTPUT_DIR.
    """
    logging.info("Processing source file: %s", source_filepath)
    filtered_lines = filter_source_code(source_filepath, signatures)
    if not filtered_lines:
        logging.warning("No content remaining after filtering for file %s", source_filepath)
        return None

    # Prepare the output file path; append '.filtered' to the basename.
    base_filename = os.path.basename(source_filepath)
    output_filepath = os.path.join(FILTERED_OUTPUT_DIR, base_filename + ".filtered")
    
    try:
        with open(output_filepath, "w", encoding="utf-8") as out_file:
            for line in filtered_lines:
                out_file.write(line + "\n")
        logging.info("Filtered file saved to %s", output_filepath)
        return output_filepath
    except Exception as ex:
        logging.error("Failed to write filtered file %s: %s", output_filepath, ex)
        return None

def process_source_directory(source_dir, signatures):
    """
    Walk through a directory of source files and process them.
    """
    for root, _, files in os.walk(source_dir):
        for file in files:
            # Process text files only (adjust the file extension check as needed)
            if file.lower().endswith(".txt"):
                filepath = os.path.join(root, file)
                process_source_file(filepath, signatures)

if __name__ == "__main__":
    # Load known signatures from the signatures file
    signatures = load_signatures(SIGNATURES_FILE)
    
    # Ask the user to provide the path to a source file or directory.
    user_input = input("Enter the path to the source code file or directory to be filtered: ").strip()

    if os.path.exists(user_input):
        if os.path.isdir(user_input):
            process_source_directory(user_input, signatures)
        elif os.path.isfile(user_input):
            process_source_file(user_input, signatures)
        else:
            logging.error("The path provided is neither a file nor a directory: %s", user_input)
    else:
        logging.error("The provided path does not exist: %s", user_input)
