# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
# Nuitka Source Extractor (Standalone)
#
# This is a standalone, non-IDA Pro version of the Nuitka recovery script.
#
# It combines PE RCDATA resource extraction with source code analysis
# to reconstruct Python modules from a Nuitka-compiled executable.
# This version uses the NLTK library for more intelligent filtering of
# extracted source code lines.
#
# To run this script from your terminal:
# 1. Make sure you have the required libraries:
#    pip install pefile nltk
# 2. Run the script with the path to your target executable:
#    python stage1nodaipro.py <path_to_your_file.exe>
# -----------------------------------------------------------------------

# --- Imports ---
import sys
import re
import os
import logging
import pefile
import argparse

# --- NLTK Imports and Setup ---
# NLTK is used for more intelligent filtering of junk lines from the source code.
try:
    import nltk
    from nltk.corpus import words
    from nltk.tokenize import word_tokenize

    # Ensure necessary NLTK data is available, downloading if it's missing.
    try:
        nltk.data.find('tokenizers/punkt')
    except Exception:
        print("NLTK 'punkt' resource not found. Downloading...")
        nltk.download('punkt', quiet=True)

    try:
        nltk.data.find('corpora/words')
    except Exception:
        print("NLTK 'words' resource not found. Downloading...")
        nltk.download('words', quiet=True)
        
    # Create a set of English words for efficient lookup.
    ENGLISH_WORDS = set(words.words())
    NLTK_AVAILABLE = True
    print("NLTK loaded successfully. Using enhanced junk filtering.")

except ImportError:
    print("NLTK is not installed. Falling back to basic junk filtering.")
    print("For better results, please install it: pip install nltk")
    NLTK_AVAILABLE = False
    ENGLISH_WORDS = set()


# --- Configuration and Setup ---
def setup_logging():
    """Configures logging to print to the console."""
    log = logging.getLogger('NuitkaExtractor')
    # Prevent duplicate logs if the script is imported elsewhere
    if log.hasHandlers():
        log.handlers.clear()
        
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    return log

log = setup_logging()

# Global paths will be set in the main function
output_directory = ""
nuitka_source_code_dir = ""
stage2_dir = ""
stage3_dir = ""

def setup_directories(base_path):
    """Sets up the output directories for extracted files."""
    global output_directory, nuitka_source_code_dir, stage2_dir, stage3_dir
    
    output_directory = os.path.join(base_path, "nuitka_extracted_rcdata")
    nuitka_source_code_dir = os.path.join(base_path, "nuitka_extracted_source")
    stage2_dir = os.path.join(nuitka_source_code_dir, "stage2_reconstructed")
    stage3_dir = os.path.join(nuitka_source_code_dir, "stage3_analysis")
    
    os.makedirs(output_directory, exist_ok=True)
    os.makedirs(nuitka_source_code_dir, exist_ok=True)
    os.makedirs(stage2_dir, exist_ok=True)
    os.makedirs(stage3_dir, exist_ok=True)

    log.info(f"RCDATA resources will be extracted to: {output_directory}")
    log.info(f"Reconstructed source code will be saved in: {stage2_dir}")
    log.info(f"Stage 3 analysis will be saved in: {stage3_dir}")


# --- RCDATA and Source Code Extraction ---
def get_resource_name(entry):
    """Gets the resource name, which can be a string or an ID."""
    if hasattr(entry, 'name') and entry.name is not None:
        return str(entry.name)
    return str(entry.id)

def extract_special_rcdata_resource(pe_path):
    """
    Extracts the special RCDATA resource (Type 10, ID 3, Lang 0) from the PE file.
    Returns the path to the extracted file, or None if not found.
    """
    if not os.path.exists(pe_path):
        log.error(f"Input file not found: {pe_path}")
        return None

    log.info(f"Starting RCDATA extraction for: {pe_path}")

    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        log.error(f"Error loading PE file: {e}")
        return None

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        log.error("No PE resources found in this file.")
        return None

    # Navigate the resource directory to find the specific Nuitka resource
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if get_resource_name(resource_type) != "10": continue
        if not hasattr(resource_type, 'directory'): continue
        for resource_id in resource_type.directory.entries:
            if get_resource_name(resource_id) != "3": continue
            if not hasattr(resource_id, 'directory'): continue
            for resource_lang in resource_id.directory.entries:
                if resource_lang.id != 0: continue

                log.info("Found special Nuitka RCDATA resource (10_3_0)!")
                data_rva = resource_lang.data.struct.OffsetToData
                size = resource_lang.data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]

                base_name = os.path.splitext(os.path.basename(pe_path))[0]
                file_name = f"{base_name}_RCDATA_10_3_0.bin"
                output_path = os.path.join(output_directory, file_name)

                try:
                    with open(output_path, "wb") as f:
                        f.write(data)
                    log.info(f"Successfully extracted resource to: {output_path}")
                    return output_path
                except IOError as e:
                    log.error(f"Failed to write extracted resource to disk: {e}")
                    return None

    log.info("The special Nuitka RCDATA resource (10_3_0) was not found.")
    return None

def clean_text(text):
    """Removes non-printable characters from a string."""
    return ''.join(char for char in text if char.isprintable() or char in '\n\r\t')

def split_source_by_u_delimiter(source_code, base_name):
    """
    Parses raw source code and reconstructs modules, keeping only lines that
    are likely to be unobfuscated Python code (heuristic based on 'u' prefix).
    """
    log.info("Reconstructing source code using 'u' delimiter logic (Stage 2)...")

    if not source_code:
        return

    # STEP 1: Split source lines while preserving 'u' tokens.
    # Nuitka uses 'u' as a prefix for unobfuscated strings.
    tokens = []
    for raw_line in source_code.splitlines():
        stripped = (raw_line or "").strip()
        if not stripped:
            continue

        if 'u' in stripped:
            # Split by 'u' but keep it as a delimiter
            parts = re.split(r'(u)', stripped)
            for p in parts:
                if p is not None:
                    p = p.strip()
                    if p:
                        tokens.append(p)
        else:
            tokens.append(stripped)

    # STEP 2: Merge 'u' with the following token to reconstruct the original code.
    merged_tokens = []
    i = 0
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if t == 'u':
            if i + 1 < n:
                merged_tokens.append('u' + tokens[i + 1])
                i += 2
            else:
                if merged_tokens:
                    merged_tokens[-1] += 'u'
                else:
                    merged_tokens.append('u')
                i += 1
        else:
            merged_tokens.append(t)
            i += 1

    final_lines = merged_tokens

    # STEP 3: Group lines by module definitions found in the code.
    module_start_pattern = re.compile(r"^\s*<module\s+['\"]?([^>'\"]+)['\"]?>")

    current_module_name = "initial_code"
    current_module_code = []
    modules = []

    def save_module_file(name, code_lines):
        if not code_lines:
            return
        safe_filename = name.replace('.', '_') + ".py"
        output_filename = f"stage2_{safe_filename}"
        output_path = os.path.join(stage2_dir, output_filename)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("\n".join(code_lines))
            log.info(f"Module saved: {output_path}")
        except IOError as e:
            log.error(f"Failed to write module {output_path}: {e}")

    # Collect all lines and group them into modules
    for line in final_lines:
        match = module_start_pattern.match(line)
        if match:
            if current_module_code:
                modules.append((current_module_name, current_module_code))
            current_module_name = match.group(1)
            current_module_code = []
            continue
        current_module_code.append(line.strip())

    if current_module_code:
        modules.append((current_module_name, current_module_code))

    # After grouping, apply a strict filter: only keep lines starting with 'u'.
    for name, code_lines in modules:
        forced_lines = [l for l in code_lines if l.lower().startswith('u')]
        save_module_file(name, forced_lines)

    log.info("Stage 2 complete: modules reconstructed and filtered.")

def scan_rsrc_file(file_path):
    """
    Scans the extracted resource file for a Python executable marker and
    extracts the source code that follows it.
    """
    if not file_path or not os.path.isfile(file_path):
        log.warning(f"Path {file_path} is not a valid file.")
        return

    try:
        log.info(f"Processing resource file: {file_path}")
        
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        base_name = os.path.splitext(os.path.basename(file_path))[0]

        # Nuitka embeds source after a marker like 'upython.exe' or '\python.exe'
        marker = None
        if "upython.exe" in content:
            marker = "upython.exe"
        elif "\\python.exe" in content:
            marker = "\\python.exe"

        if marker:
            log.info(f"Found marker: {marker}")
            marker_index = content.find(marker)
            source_code_raw = content[marker_index:]
            
            cleaned_source_code = clean_text(source_code_raw)
            
            save_filename = f"{base_name}_source_code_original.txt"
            save_path = os.path.join(nuitka_source_code_dir, save_filename)
            
            with open(save_path, "w", encoding="utf-8") as save_file:
                save_file.write(cleaned_source_code)
            
            log.info(f"Saved raw extracted source code to {save_path}")
            
            # Process the raw code into structured modules
            split_source_by_u_delimiter(cleaned_source_code, base_name)
            scan_code_for_links(cleaned_source_code)
        else:
            log.info(f"No python.exe marker found in {file_path}")

    except Exception as ex:
        log.error(f"Error during file scanning of {file_path}: {ex}")

def scan_code_for_links(code):
    """Scans the provided code string for URLs, IPs, and Discord webhooks."""
    url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    webhook_pattern = re.compile(r'https://discord.com/api/webhooks/\d+/[a-zA-Z0-9_-]+', re.IGNORECASE)
    
    urls = url_pattern.findall(code)
    ips = ip_pattern.findall(code)
    webhooks = webhook_pattern.findall(code)

    if urls: log.info(f"Found URLs: {urls}")
    if ips: log.info(f"Found IP Addresses: {ips}")
    if webhooks: log.info(f"Found Discord Webhooks: {webhooks}")
    if not any([urls, ips, webhooks]):
        log.info("No domains, URLs, IPs, or webhooks found in the source code.")

def run_stage3_analysis():
    """
    Stage 3: Consolidates imports and user-mode code from the reconstructed
    Stage 2 files into a single, more readable Python script.
    """
    log.info("Starting Stage 3: Consolidating imports and user-mode code...")

    import_pattern = re.compile(
        r"from[ \t]+[.\w]+[ \t]+import[ \t]+(?:[\w, ]+|\*|\([\w, \n\r]+\))|import[ \t]+[.\w, ]+"
    )
    
    all_usermode_code = []
    all_imports = set()

    if not os.path.exists(stage2_dir) or not os.listdir(stage2_dir):
        log.warning("Stage 2 directory is empty. Nothing to analyze for Stage 3.")
        return
        
    for filename in sorted(os.listdir(stage2_dir)):
        if not filename.endswith(".py"):
            continue

        file_path = os.path.join(stage2_dir, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Apply strict filtering again to ensure only 'u'-prefixed lines are processed
            lines = content.splitlines()
            forced_lines = [l for l in lines if l.startswith('u')]
            cleaned_content = "\n".join(forced_lines)

            # Extract imports from the cleaned content
            imports_in_file = import_pattern.findall(cleaned_content)
            all_imports.update(imp.strip() for imp in imports_in_file)

            # Remove imports to leave only the user-mode code
            usermode_code = import_pattern.sub('', cleaned_content).strip()

            if usermode_code:
                module_name_from_file = filename.replace("stage2_", "").replace(".py", "")
                header = f"""
# =======================================================================
# User-mode code from module: {module_name_from_file.replace('_', '.')}
# =======================================================================
"""
                all_usermode_code.append(header + usermode_code)
            else:
                log.info(f"No user-mode code found in {filename} after final filtering.")

        except Exception as e:
            log.error(f"Could not analyze file {filename}: {e}")

    # Clean and sort the collected imports
    cleaned_imports = sorted([imp for imp in list(all_imports) if imp])

    # Write the final consolidated Python file
    output_file = os.path.join(stage3_dir, "stage3_usermode_code.py")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# Stage 3: Consolidated User-Mode Code\n")
            f.write("# This file combines all reconstructed modules.\n\n")
            
            f.write("# --- Consolidated & Filtered Imports ---\n")
            if cleaned_imports:
                f.write("\n".join(cleaned_imports))
            f.write("\n\n# --- End of Imports ---\n")

            f.write("\n\n".join(all_usermode_code))
            
        log.info(f"Consolidated code saved to: {output_file}")
    except IOError as e:
        log.error(f"Failed to write consolidated code file: {e}")


# =======================================================================
# Main execution logic
# =======================================================================
def main():
    """
    Main function to parse arguments and run the full recovery process.
    """
    parser = argparse.ArgumentParser(
        description="Extract and reconstruct Python source code from a Nuitka-compiled PE file."
    )
    parser.add_argument("filepath", help="Path to the target PE file (e.g., an .exe).")
    args = parser.parse_args()

    target_file = args.filepath
    if not os.path.isfile(target_file):
        log.error(f"Error: The file '{target_file}' does not exist.")
        return

    # Set up output directories in the same folder as the target file
    base_dir = os.path.dirname(os.path.abspath(target_file))
    setup_directories(base_dir)

    log.info("="*50)
    log.info("Starting Nuitka Source Extractor")
    log.info("="*50)

    # Step 1: Extract the special RCDATA resource from the PE file.
    log.info("[Step 1] Extracting special RCDATA resource...")
    extracted_rsrc_path = extract_special_rcdata_resource(target_file)

    # Step 2: Scan the extracted resource to find and reconstruct source code.
    # This creates the Stage 2 module files.
    if extracted_rsrc_path:
        log.info("[Step 2] Scanning extracted RCDATA for source code...")
        scan_rsrc_file(extracted_rsrc_path)
    else:
        log.error("Aborting: Could not extract the Nuitka data resource.")
        return
        
    # Step 3: Run Stage 3 analysis to consolidate the reconstructed modules.
    log.info("[Step 3] Running Stage 3 analysis on reconstructed files...")
    run_stage3_analysis()

    log.info("="*50)
    log.info("Nuitka Source Extraction Finished.")
    log.info(f"Check the '{stage3_dir}' directory for the final output.")
    log.info("="*50)


if __name__ == "__main__":
    main()
