import os
import sys
import io
import logging
from datetime import datetime
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.svm import OneClassSVM

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

logging.info("Stage2 (ML-based filtering) application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Define paths
# Directory holding signature files (each signature file can have one or more lines)
SIGNATURES_DIR = os.path.join(script_dir, "signatures")
# Directory where stage1.py stored extracted source code files.
EXTRACTED_SOURCE_DIR = os.path.join(script_dir, "nuitkasourcecode")
# Directory to store the filtered output files.
FILTERED_OUTPUT_DIR = os.path.join(script_dir, "filtered_sourcecode")
os.makedirs(FILTERED_OUTPUT_DIR, exist_ok=True)

def load_signatures_from_dir(signatures_dir):
    """
    Load signature lines from every text file in the signatures directory.
    """
    all_signatures = []
    if not os.path.exists(signatures_dir) or not os.path.isdir(signatures_dir):
        logging.error("Signatures directory does not exist: %s", signatures_dir)
        return all_signatures
    for root, _, files in os.walk(signatures_dir):
        for file in files:
            if file.lower().endswith(".txt"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        lines = [line.strip() for line in f if line.strip()]
                        all_signatures.extend(lines)
                    logging.info("Loaded %d signatures from %s", len(lines), filepath)
                except Exception as ex:
                    logging.error("Error loading signatures from file %s: %s", filepath, ex)
    logging.info("Total signatures loaded: %d", len(all_signatures))
    return all_signatures

def train_signature_model(signatures, model_name="all-MiniLM-L6-v2"):
    """
    Train a one-class SVM on the embeddings of the signature lines.
    We use a pre-trained sentence embedding model to vectorize the signatures.
    """
    try:
        embedder = SentenceTransformer(model_name)
        signature_embeddings = embedder.encode(signatures, show_progress_bar=True)
        # Train one-class SVM without explicit threshold tuning.
        ocsvm = OneClassSVM(gamma='auto').fit(signature_embeddings)
        logging.info("Trained One-Class SVM on %d signature embeddings", len(signature_embeddings))
        return embedder, ocsvm
    except Exception as ex:
        logging.error("Failed to train signature model: %s", ex)
        return None, None

def ml_filter_source_file(source_filepath, embedder, ocsvm):
    """
    Use the trained embedder and One-Class SVM to filter out lines in the source file
    that are similar to known signatures.
    Returns a list of lines not classified as signatures.
    """
    filtered_lines = []
    try:
        with open(source_filepath, "r", encoding="utf-8", errors="ignore") as f:
            source_lines = f.readlines()
    except Exception as ex:
        logging.error("Failed to read source file %s: %s", source_filepath, ex)
        return filtered_lines

    # Process each line individually.
    for line in source_lines:
        line_stripped = line.rstrip()
        if not line_stripped:
            continue
        # Compute embedding for the current line.
        try:
            line_embedding = embedder.encode([line_stripped])
            prediction = ocsvm.predict(line_embedding)  # returns 1 (inlier) or -1 (outlier)
        except Exception as ex:
            logging.error("Error during embedding/prediction for line: %s; error: %s", line_stripped, ex)
            prediction = [-1]

        # If predicted as inlier, it means the line is similar to a known signature.
        if prediction[0] == 1:
            logging.debug("Filtered out ML-detected signature line: %s", line_stripped)
            continue
        else:
            filtered_lines.append(line_stripped)
    return filtered_lines

def process_source_file(source_filepath, embedder, ocsvm):
    """
    Process a single source file using machine learning filtering.
    The filtered file is saved with a '.filtered' suffix.
    """
    logging.info("Processing source file (ML filtering): %s", source_filepath)
    filtered_lines = ml_filter_source_file(source_filepath, embedder, ocsvm)
    if not filtered_lines:
        logging.warning("No content remaining after ML filtering for file %s", source_filepath)
        return None

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

def process_source_directory(source_dir, embedder, ocsvm):
    """
    Process all source files in a directory.
    """
    for root, _, files in os.walk(source_dir):
        for file in files:
            # Here we assume the source code files are text files.
            if file.lower().endswith(".txt"):
                filepath = os.path.join(root, file)
                process_source_file(filepath, embedder, ocsvm)

if __name__ == "__main__":
    # Load known signature lines from the signatures directory.
    signatures = load_signatures_from_dir(SIGNATURES_DIR)
    if not signatures:
        logging.error("No signatures loaded. Exiting.")
        sys.exit(1)

    # Train our machine learning model on the signature lines.
    embedder, ocsvm = train_signature_model(signatures)
    if embedder is None or ocsvm is None:
        logging.error("Failed to initialize ML filtering components. Exiting.")
        sys.exit(1)

    # Ask the user for a source file or directory produced by stage1.py.
    user_input = input("Enter the path to the source code file or directory to be filtered: ").strip()

    if os.path.exists(user_input):
        if os.path.isdir(user_input):
            process_source_directory(user_input, embedder, ocsvm)
        elif os.path.isfile(user_input):
            process_source_file(user_input, embedder, ocsvm)
        else:
            logging.error("The path provided is neither a file nor a directory: %s", user_input)
    else:
        logging.error("The provided path does not exist: %s", user_input)
