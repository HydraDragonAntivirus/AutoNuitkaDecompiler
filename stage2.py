import os
import re
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------
# CONFIGURATION & LOGGING
# ---------------------------
SCRIPT_DIR = os.getcwd()
INPUT_SOURCE_DIR = os.path.join(SCRIPT_DIR, "nuitkasourcecode")
FILTERED_OUTPUT_DIR = os.path.join(SCRIPT_DIR, "filtered_sourcecode_wordbased")
os.makedirs(FILTERED_OUTPUT_DIR, exist_ok=True)

log_dir = os.path.join(SCRIPT_DIR, "log")
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(log_dir, "word_filter.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logging.info("Word-based filtering started at %s", datetime.now().isoformat())

# ---------------------------
# PARAMETERS
# ---------------------------
# Threshold: any "word" (alphanumeric and _) of this length or longer triggers removal
WORD_LENGTH_THRESHOLD = 10
# Maximum threads for parallel file processing
MAX_WORKERS = 50

# ---------------------------
# WORD-BASED & COMMENT-BASED FILTERING
# ---------------------------
def filter_file_wordbased(src_path, threshold=WORD_LENGTH_THRESHOLD):
    '''
    Remove lines containing any word of length >= threshold or pure comment lines.
    Comments include:
      - Single-line comments starting with '#'
      - Shebangs or encoding declarations
      - Lines starting with ellipsis '...'
      - Triple-quoted docstring delimiters
    '''
    filtered_lines = []
    # Use double-escaped backslashes to avoid regex warning
    long_word_pattern = re.compile(r"\b\w{%d,}\b" % threshold)
    try:
        with open(src_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_stripped = line.rstrip()
                stripped_leading = line_stripped.lstrip()
                # Drop comment-only lines
                if (stripped_leading.startswith('#') or
                    stripped_leading.startswith('...') or
                    stripped_leading.startswith('"""') or
                    stripped_leading.startswith("'''") ):
                    logging.debug(f"Dropping comment line in {src_path}: {line_stripped}")
                    continue
                # Drop lines with very long words
                if long_word_pattern.search(line_stripped):
                    logging.debug(f"Dropping long-word line in {src_path}: {line_stripped}")
                    continue
                filtered_lines.append(line_stripped)
    except Exception as e:
        logging.error(f"Error reading {src_path}: {e}")
    return filtered_lines


def process_file(src_path):
    '''Process a single file and write filtered output.'''  # noqa: E501
    rel = os.path.relpath(src_path, SCRIPT_DIR)
    logging.info(f"Processing {rel}")
    filtered = filter_file_wordbased(src_path)
    if not filtered:
        logging.warning(f"No content after filtering: {rel}")
        return
    base_name = os.path.splitext(os.path.basename(src_path))[0]
    out_path = os.path.join(FILTERED_OUTPUT_DIR, base_name + ".txt")
    try:
        with open(out_path, 'w', encoding='utf-8') as wf:
            wf.write("\n".join(filtered))
        logging.info(f"Wrote filtered file: {os.path.relpath(out_path, SCRIPT_DIR)}")
    except Exception as e:
        logging.error(f"Error writing {out_path}: {e}")


def process_directory(input_dir, max_workers=MAX_WORKERS):
    '''Walk directory, process all .txt and .py files in parallel.'''
    targets = []
    for root, _, files in os.walk(input_dir):
        for fn in files:
            if fn.lower().endswith(('.txt', '.py')):
                targets.append(os.path.join(root, fn))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_file, p): p for p in targets}
        for fut in as_completed(futures):
            src = futures[fut]
            try:
                fut.result()
            except Exception as e:
                logging.error(f"Error processing {src}: {e}")


if __name__ == '__main__':
    process_directory(INPUT_SOURCE_DIR)
    logging.info("Word-based filtering completed at %s", datetime.now().isoformat())
    print("Filtering done. See filtered files in:\n", FILTERED_OUTPUT_DIR)