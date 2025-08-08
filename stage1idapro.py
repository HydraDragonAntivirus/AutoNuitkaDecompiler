# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
# Nuitka United Helpers - MODIFIED
#
# This script combines the functionality of the original nuitka-helpers.py
# with specific PE RCDATA resource extraction and source code analysis,
# including custom import filtering.
# It is designed to be run as an IDA Pro script.
#
# This version has been modified to use the NLTK library for more
# intelligent filtering of extracted source code lines.
#
# To run this script in IDA Pro:
# 1. Open your target file in IDA.
# 2. Go to File -> Script file...
# 3. Select this script.
# 4. The script will perform its analysis.
# -----------------------------------------------------------------------

# --- Imports ---
import sys
import re
import time
import ctypes
import struct
import os
import logging
import pefile

# --- NLTK Imports and Setup ---
# We are adding NLTK to provide more intelligent filtering of junk lines.
try:
    import nltk
    from nltk.corpus import words
    from nltk.tokenize import word_tokenize

    # Ensure that necessary NLTK resources are available, downloading if necessary.
    # This checks if the data is present and downloads it only if missing.
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
    NLTK_AVAILABLE = False


# --- IDA Pro Imports ---
import idc
import idautils
import ida_auto
import ida_bytes
import ida_dbg
import ida_dirtree
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_ida
import ida_idd
import ida_kernwin
import ida_nalt
import ida_name
import ida_typeinf


# --- Configuration and Setup ---
def setup_logging():
    """Configures logging to print to the IDA output window."""
    class IdaLogHandler(logging.Handler):
        def emit(self, record):
            msg = self.format(record)
            # Use a print statement for more reliable output in IDA
            print(msg)

    log = logging.getLogger('NuitkaHelpers')
    # Clear any existing handlers to prevent duplicate logs
    if log.hasHandlers():
        log.handlers.clear()
        
    handler = IdaLogHandler()
    # Simplified formatter to avoid duplicate timestamps from IDA's output window
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    return log

log = setup_logging()

# Define output directories
try:
    # __file__ is the most reliable way to get the current script's path
    script_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    # Fallback if __file__ is not defined (e.g., in an interactive session)
    pe_path = ida_nalt.get_input_file_path()
    if pe_path:
        script_dir = os.path.dirname(pe_path)
    else:
        # Ultimate fallback to the user's home directory
        script_dir = os.path.expanduser("~")

output_directory = os.path.join(script_dir, "nuitka_extracted_rcdata")
nuitka_source_code_dir = os.path.join(script_dir, "nuitka_extracted_source")
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
    """
    Get the resource name, which might be a string or an ID.
    """
    if hasattr(entry, 'name') and entry.name is not None:
        return str(entry.name)
    else:
        return str(entry.id)

def extract_special_rcdata_resource():
    """
    Extracts the special RCDATA resource (Type 10, ID 3, Lang 0) from a PE file.
    Returns the path to the extracted file if successful, otherwise None.
    """
    pe_path = ida_nalt.get_input_file_path()
    if not pe_path or not os.path.exists(pe_path):
        log.error("Could not get the input file path. Is a file loaded in IDA?")
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

    found_resource = False
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if get_resource_name(resource_type) != "10": continue
        if not hasattr(resource_type, 'directory'): continue
        for resource_id in resource_type.directory.entries:
            if get_resource_name(resource_id) != "3": continue
            if not hasattr(resource_id, 'directory'): continue
            for resource_lang in resource_id.directory.entries:
                if resource_lang.id != 0: continue

                log.info("Found special RCDATA resource (10_3_0)!")
                found_resource = True
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
                    ida_kernwin.info(f"Success! Extracted RCDATA to: {output_path}")
                    return output_path
                except IOError as e:
                    log.error(f"Failed to write extracted resource to disk: {e}")
                    return None

    if not found_resource:
        log.info("The special RCDATA resource (10_3_0) was not found in this file.")
    return None

def clean_text(text):
    """Removes non-printable characters from a string."""
    return ''.join(char for char in text if char.isprintable() or char in '\n\r\t')

def is_likely_junk(line):
    """
    MODIFIED: A line is considered JUNK based on the user's specific (reversed) rules.
    This function now returns True for lines that should be DELETED.
    - Rule 1: Lines WITHOUT 'u' are JUNK (delete).
    - Rule 2: Lines WITH 'u' that are part of a recognizable English word are JUNK (delete).
    - Rule 3: Lines WITH 'u' that are part of a meaningless string are NOT JUNK (keep).
    """
    # Rule 1: If a line does NOT contain 'u', it is JUNK.
    if 'u' not in line:
        return True # JUNK, delete.

    # If we are here, the line *does* contain 'u'.
    # Now we check if it's a meaningful word (JUNK) or a meaningless string (NOT JUNK).

    if not NLTK_AVAILABLE:
        # Fallback if NLTK is not available: assume it's a meaningless string to be safe.
        return False # NOT JUNK, keep.

    try:
        # We only check the part after the 'u' for English words.
        word_to_check = line.lstrip('u')
        tokens = word_tokenize(word_to_check.lower())
        for word in tokens:
            # Rule 2: If a word is a real English word, the line is JUNK.
            # We no longer check for 'u' here since we are checking the fragment after it.
            if word.isalpha() and word in ENGLISH_WORDS:
                return True # This is a meaningful word, so it's JUNK.
    except Exception as e:
        log.warning(f"NLTK processing failed for line: {line[:50]}... Error: {e}")
        # On error, keep the line to be safe.
        return False # NOT JUNK, keep.

    # Rule 3: If the line has 'u' but not in any recognizable English word,
    # it means it's a meaningless string, which should be KEPT (NOT JUNK).
    return False # NOT JUNK, keep.


def split_source_by_u_delimiter(source_code, base_name):
    """
    Parses a raw source code block by filtering lines based on the new logic
    and then grouping them into module files.
    This version is improved to handle raw, concatenated u-prefixed strings.
    """
    log.info("Reconstructing source code using custom 'u' delimiter logic (Stage 2)...")

    # --- CORRECTED SPLITTING LOGIC ---
    # The previous logic split the entire block by 'u', which incorrectly
    # handled text that contained 'u' but wasn't a Nuitka construct.
    # The new logic processes the content line by line first, applying the
    # junk filter to each line, and only then looks for module markers.
    
    # First, split the raw source code into actual lines.
    raw_lines = source_code.splitlines()
    
    # Filter out junk lines *before* any other processing.
    # A line is kept if is_likely_junk returns False.
    filtered_lines = [line for line in raw_lines if not is_likely_junk(line.strip())]

    current_module_name = "initial_code"
    current_module_code = []
    
    def save_module_file(name, code_lines):
        """Helper function to save the collected code for a module to a file."""
        # The lines are already filtered, so we just check if there's anything to save.
        if not any(line.strip() for line in code_lines):
            return
            
        safe_filename = name.replace('.', '_') + ".py"
        output_filename = f"stage2_{safe_filename}"
        output_path = os.path.join(stage2_dir, output_filename)
        
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"# Reconstructed from Nuitka analysis\n")
                f.write(f"# Original module name: {name}\n\n")
                f.write("\n".join(code_lines)) # Write the kept lines
            log.info(f"Reconstructed module saved to: {output_path}")
        except IOError as e:
            log.error(f"Failed to write module file {output_path}: {e}")

    # This pattern is now used to find module declarations within the *filtered* lines.
    module_start_pattern = re.compile(r"^\s*u<module\s+['\"]?([^>'\"]+)['\"]?>")

    for line in filtered_lines:
        # The line has already been filtered for junk. We just need to process it.
        stripped_line = line.strip()
        if not stripped_line:
            continue
            
        match = module_start_pattern.match(stripped_line)
        if match:
            # Before starting a new module, save the code of the previous one.
            if current_module_code:
                save_module_file(current_module_name, current_module_code)
            
            # Start a new module.
            current_module_name = match.group(1)
            # The module declaration line itself is not part of the code.
            current_module_code = [] 
        else:
            # Add the line to the current module's code.
            current_module_code.append(stripped_line)
            
    # Save the last module after the loop finishes.
    save_module_file(current_module_name, current_module_code)


def scan_rsrc_file(file_path):
    """
    Given a file path for an rsrcdata resource, this function scans the file 
    for 'upython.exe', extracts the subsequent source code, cleans it, 
    and reconstructs it into separate module files.
    """
    if not file_path or not os.path.isfile(file_path):
        logging.warning(f"Path {file_path} is not a valid file.")
        return

    try:
        logging.info(f"Processing file: {file_path}")
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if "upython.exe" in content:
            marker_index = content.find("upython.exe")
            source_code_raw = content[marker_index + len("upython.exe"):]
            
            cleaned_source_code = clean_text(source_code_raw)
            base_name = os.path.splitext(os.path.basename(file_path))[0]

            save_filename = f"{base_name}_source_code_original.txt"
            save_path = os.path.join(nuitka_source_code_dir, save_filename)
            with open(save_path, "w", encoding="utf-8") as save_file:
                save_file.write(cleaned_source_code)
            logging.info(f"Saved original extracted source code to {save_path}")

            split_source_by_u_delimiter(cleaned_source_code, base_name)
            scan_code_for_links(cleaned_source_code)
        else:
            logging.info(f"Marker 'upython.exe' not found in {file_path}.")

    except Exception as ex:
        logging.error(f"Error during file scanning of {file_path}: {ex}")


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


# --- Start of original nuitka-helpers.py code ---

# =======================================================================
# File: utils.py from original helpers
# =======================================================================
definitions = {}

definitions["loadConstantsBlob"] = """
    void loadConstantsBlob(
        void *tstate,
        void **mod_consts,
        char const *module_name
    );
"""

definitions["Nuitka_Function_New"] = """
    void *Nuitka_Function_New(
        void *c_code,
        void *name,
        void *qualname,
        void *code_object,
        void *defaults,
        void *kw_defaults,
        void *annotations,
        void *module,
        void *doc,
        void *closure,
        size_t closure_given
    );
"""

definitions["modulecode"] = """
    void *module_initfunc(
        void *tstate,
        void *module,
        void *loader_entry
    );
"""


def find_string_xrefs(string):
    xrefs = []
    for s in idautils.Strings():
        try:
            s_str = str(s)
            if s_str == string:
                xrefs.extend(list(idautils.XrefsTo(s.ea)))
        except:
            continue
    return xrefs


def find_sole_string_xref(string):
    xrefs = find_string_xrefs(string)
    if not xrefs:
        raise Exception(f"No xrefs found for string: '{string}'")
    if len(xrefs) > 1:
        log.warning(f"Warning: Found multiple xrefs for '{string}', using the first one.")
    return xrefs[0].frm


def set_type(ea, type_name):
    if type_name in definitions:
        type_def = definitions[type_name]
    else:
        type_def = type_name

    _type = idc.parse_decl(type_def, ida_typeinf.PT_FILE)
    if not _type:
        raise Exception(f"Missing or invalid type definition for '{type_name}'")

    idc.apply_type(ea, _type, ida_typeinf.TINFO_DEFINITE)
    ida_auto.auto_wait()


def set_filtered_name(ea, name, prefix=None):
    invalid_chars = r'[^a-zA-Z0-9._]'
    filtered_name = re.sub(invalid_chars, '_', name)
    
    if prefix:
        filtered_name = f"{prefix}_{filtered_name}"

    if len(filtered_name) > 500:
        filtered_name = filtered_name[:500]

    ida_name.set_name(ea, filtered_name, ida_name.SN_FORCE)
    return filtered_name


def start_debugger():
    log.info("Starting debugger...")
    ida_dbg.load_debugger("win32", 0)
    ida_dbg.start_process()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    log.info("Debugger started and process suspended.")


def stop_debugger():
    log.info("Stopping debugger...")
    ida_dbg.exit_process()
    ida_dbg.wait_for_next_event(ida_dbg.dbg_process_exit, -1)
    log.info("Debugger stopped.")

utils = sys.modules[__name__]


# =======================================================================
# File: recover_modules.py from original helpers
# =======================================================================
def find_entry_point():
    main_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "modulecode___main__")
    if main_ea == ida_idaapi.BADADDR:
        log.info("`modulecode___main__` not found by name, searching via string xrefs to '__main__'.")
        xrefs = utils.find_string_xrefs("__main__")
        if not xrefs:
            log.error("[!] No xrefs to '__main__' found. Cannot locate entry point.")
            return None
        prev_xref = xrefs[0]
        for curr_xref in xrefs[1:]:
            func = ida_funcs.get_func(curr_xref.frm)
            if not func:
                continue
            func_ea = func.start_ea
            name = ida_name.get_name(func_ea)
            if name in ["main", "WinMain"]:
                main_ea = ida_funcs.get_func(prev_xref.frm).start_ea
                utils.set_filtered_name(main_ea, "modulecode___main__")
                utils.set_type(main_ea, "modulecode")
                log.info(f"Entry point `modulecode___main__` found at {hex(main_ea)}.")
                return main_ea
            prev_xref = curr_xref

        main_ea = ida_funcs.get_func(prev_xref.frm).start_ea
        utils.set_filtered_name(main_ea, "modulecode___main__")
        utils.set_type(main_ea, "modulecode")
        log.info(f"[!] Fallback: Using first xref at {hex(main_ea)} as entry point.")
    else:
        log.info(f"Entry point `modulecode___main__` found at {hex(main_ea)}.")
    return main_ea


def find_custom_modules():
    """Locate custom modules & rename them to `modulecode_xxx` (except main module)"""
    log.info("Searching for custom modules...")
    module_data = {}

    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "loadConstantsBlob")
    if ea == ida_idaapi.BADADDR:
        try:
            log.info("`loadConstantsBlob` not found by name, searching via string xref.")
            xref = utils.find_sole_string_xref("Error, corrupted constants object")
            ea = ida_funcs.get_func(xref).start_ea
            utils.set_filtered_name(ea, "loadConstantsBlob")
        except Exception as e:
            log.error(f"Could not find `loadConstantsBlob`: {e}")
            return module_data

    utils.set_type(ea, "loadConstantsBlob")
    log.info(f"`loadConstantsBlob` found at {hex(ea)}.")

    for xref in idautils.XrefsTo(ea):
        func_of_xref = ida_funcs.get_func(xref.frm)
        if not func_of_xref:
            continue

        if args_ea := ida_typeinf.get_arg_addrs(xref.frm):
            try:
                second_arg_ea = args_ea[1]
                third_arg_ea = args_ea[2]

                mod_consts_rva = idc.get_operand_value(second_arg_ea, 1) - ida_nalt.get_imagebase()
                module_name_ea = idc.get_operand_value(third_arg_ea, 1)
                module_name_rva = module_name_ea - ida_nalt.get_imagebase()

                module_name_bytes = ida_bytes.get_strlit_contents(module_name_ea, -1, ida_nalt.STRTYPE_C)
                if module_name_bytes:
                    module_name = module_name_bytes.decode('utf-8')
                    if module_name != ".bytecode":
                        func_ea = func_of_xref.start_ea
                        if module_name != "__main__":
                            new_name = utils.set_filtered_name(func_ea, module_name, prefix="modulecode")
                            module_key = new_name[len("modulecode_"):]
                            utils.set_type(func_ea, "modulecode")
                            module_data[module_key] = (mod_consts_rva, module_name_rva)
                        else:
                             module_data["__main__"] = (mod_consts_rva, module_name_rva)
            except (IndexError, TypeError):
                log.warning(f"Could not get arguments for xref at {hex(xref.frm)}. Skipping.")
                continue
    return module_data

recover_modules = sys.modules[__name__]


# =======================================================================
# File: parse_module_constants.py from original helpers
# =======================================================================
type_mappings = {
    "str": str, "bytes": bytes, "bytearray": bytearray, "int": int,
    "bool": bool, "float": float, "type": type, "NoneType": type(None),
    "None": None, "range": range, "slice": slice, "list": list,
    "tuple": tuple, "set": set, "dict": dict,
}

scalar_data_types = ["str", "bytes", "bytearray", "int", "bool", "float", "type", "NoneType", "module"]
collection_data_types = ["range", "slice", "list", "tuple", "set", "dict"]


def convert_nested_lists_to_tuples(const):
    if type(const) == list:
        return tuple(convert_nested_lists_to_tuples(item) for item in const)
    return const


def comment_range_constant(curr_ea, const):
    try:
        if const[2] == 1:
            ida_bytes.set_cmt(curr_ea, f"range{const[:2]}", 0)
            if const[0] == 0:
                ida_bytes.set_cmt(curr_ea, f"range({const[1]})", 0)
        else:
            ida_bytes.set_cmt(curr_ea, f"range{const}", 0)
    except IndexError:
        ida_bytes.set_cmt(curr_ea, f"range{const}", 0)


def comment_slice_constant(curr_ea, const):
    try:
        const_list = list(const)
        if const_list[0] is None: const_list[0] = ""
        if const_list[1] is None: const_list[1] = ""
        if const_list[2] is None: const_list[2] = ""
        ida_bytes.set_cmt(curr_ea, str(const).replace("None", "").replace(", ", ":"), 0)
    except IndexError:
        ida_bytes.set_cmt(curr_ea, str(const), 0)


def convert_back_collection(collection, index_lst, constant_type):
    i = index_lst[0]
    if len(index_lst) == 1:
        if constant_type == tuple:
            collection[i] = tuple(collection[i])
        elif constant_type == set:
            collection[i] = set(collection[i])
    else:
        convert_back_collection(collection[i], index_lst[1:], constant_type)


def add_item_to_collection(const, collection, stack_depth, tracked_indexes, dict_field):
    temp = collection
    index_lst = []
    if dict_field == "tuple_key":
        stack_depth -= 1

    for i in range(stack_depth - 1):
        if isinstance(temp, dict):
            key = list(temp.keys())[-1]
            index_lst.append(key)
            temp = temp[key]
        elif isinstance(temp, list):
            i = len(temp) - 1
            index_lst.append(i)
            temp = temp[i]

    substitute_collection = False
    original_type = type(const)
    if original_type == set or (original_type == tuple and dict_field != "tuple_key"):
        substitute_collection = True
        const = list(const)

    if isinstance(temp, dict):
        keys = list(temp.keys())
        key = keys[-1] if keys else None
        if dict_field and dict_field.endswith("key"):
            temp[const] = None
        else:
            if key is not None:
                temp[key] = const
                index_lst.append(key)
    elif isinstance(temp, list):
        temp.append(const)
        index_lst.append(len(temp) - 1)

    if substitute_collection:
        tracked_indexes.append((stack_depth, index_lst, original_type))


def parse_module_constant(curr_ea, max_count=1, collection=None, stack_depth=1, tracked_indexes=None, dict_field=None):
    if collection is None: collection = []
    if tracked_indexes is None: tracked_indexes = []

    curr_count = 0
    while curr_count != max_count:
        if not ida_bytes.is_loaded(curr_ea): break
        mod_const = ida_bytes.get_qword(curr_ea)

        if not ida_ida.inf_get_min_ea() <= mod_const <= ida_ida.inf_get_max_ea():
            curr_ea += 8; curr_count += 1; continue

        type_obj_field = mod_const + 8
        if not ida_bytes.is_loaded(type_obj_field): break
        type_obj = ida_bytes.get_qword(type_obj_field)

        tp_name_field = type_obj + 8*3
        if not ida_bytes.is_loaded(tp_name_field): break
        tp_name_ptr = ida_bytes.get_qword(tp_name_field)

        const_type_bytes = ida_bytes.get_strlit_contents(tp_name_ptr, -1, ida_nalt.STRTYPE_C)
        if not const_type_bytes:
             curr_ea += 8; curr_count += 1; continue
        const_type = const_type_bytes.decode()

        ida_bytes.create_qword(curr_ea, 8)
        const = None

        if const_type == "str":
            utils.set_filtered_name(mod_const, "unicode_object")
            length_field, string_field = mod_const + 8*2, mod_const + 8*6
            for i in range(6): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(length_field, "len", 0); ida_bytes.set_cmt(string_field, "str", 0)
            length = ida_bytes.get_qword(length_field)
            string_bytes = ida_bytes.get_strlit_contents(string_field, length, ida_nalt.STRTYPE_C)
            if string_bytes is None:
                if length > 0:
                    wstr_field = mod_const + 8*5
                    wstr_ptr = ida_bytes.get_qword(wstr_field)
                    string_bytes = ida_bytes.get_bytes(wstr_ptr, length * 2)
                    string = string_bytes.decode("utf-16")
                    ida_bytes.create_strlit(wstr_ptr, length * 2, ida_nalt.STRTYPE_C_16)
                else: string = ""
            else:
                string = string_bytes.decode(); ida_bytes.create_strlit(string_field, length, ida_nalt.STRTYPE_C)
            utils.set_filtered_name(curr_ea, string, prefix=const_type); const = string
        elif const_type == "bytes":
            utils.set_filtered_name(mod_const, "bytes_object")
            length_field, bytes_field = mod_const + 8*2, mod_const + 8*4
            for i in range(4): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(length_field, "len", 0); ida_bytes.set_cmt(bytes_field, "bytes", 0)
            length = ida_bytes.get_qword(length_field)
            bytestring = ida_bytes.get_bytes(bytes_field, length)
            if not bytestring: bytestring = b""
            try: bytestring.decode(); ida_bytes.create_strlit(bytes_field, length, ida_nalt.STRTYPE_C)
            except: idc.make_array(bytes_field, length)
            utils.set_filtered_name(curr_ea, str(bytestring)[2:-1], prefix=const_type); const = bytestring
        elif const_type == "bytearray":
            utils.set_filtered_name(mod_const, "bytearray_object")
            size_field, bytearray_field = mod_const + 8*2, mod_const + 8*5
            for i in range(7): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(size_field, "size", 0); ida_bytes.set_cmt(bytearray_field, "bytearray", 0)
            size = ida_bytes.get_qword(size_field)
            bytearray_ptr = ida_bytes.get_qword(bytearray_field)
            byte_array = ida_bytes.get_bytes(bytearray_ptr, size)
            if not byte_array: byte_array = b""
            try: byte_array.decode(); ida_bytes.create_strlit(bytearray_ptr, size, ida_nalt.STRTYPE_C)
            except: idc.make_array(bytearray_ptr, size)
            utils.set_filtered_name(curr_ea, str(byte_array)[2:-1], prefix=const_type); const = bytearray(byte_array)
        elif const_type == "int":
            utils.set_filtered_name(mod_const, "long_object")
            lv_tag_field, ob_digit_field = mod_const + 8*2, mod_const + 8*3
            for i in range(3): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(lv_tag_field, "lv_tag", 0); ida_bytes.set_cmt(ob_digit_field, "ob_digit", 0)
            lv_tag = ctypes.c_long(ida_bytes.get_qword(lv_tag_field)).value
            ndigits = abs(lv_tag)
            PyLong_SHIFT = 30
            ida_bytes.del_items(ob_digit_field, ida_bytes.DELIT_EXPAND); ida_bytes.create_dword(ob_digit_field, 4); idc.make_array(ob_digit_field, ndigits)
            _sum = sum(ida_bytes.get_dword(ob_digit_field + 4*i) * 2**(PyLong_SHIFT*i) for i in range(ndigits))
            if lv_tag < 0: _sum *= -1
            utils.set_filtered_name(curr_ea, f"{_sum}", prefix=const_type); const = _sum
        elif const_type == "bool":
            utils.set_filtered_name(mod_const, "bool_object")
            digit_field = mod_const + 8*3
            for i in range(4): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(digit_field, "bool", 0)
            boolean = True if ida_bytes.get_dword(digit_field) == 1 else False
            utils.set_filtered_name(curr_ea, f"{boolean}", prefix=const_type); const = boolean
        elif const_type == "float":
            utils.set_filtered_name(mod_const, "float_object")
            double_field = mod_const + 8*2
            for i in range(3): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(double_field, "float", 0)
            double = struct.unpack("d", ida_bytes.get_bytes(double_field, 8))[0]
            utils.set_filtered_name(curr_ea, f"{double}", prefix=const_type); const = double
        elif const_type == "range":
            utils.set_filtered_name(mod_const, "range_object")
            start_field, stop_field, step_field = mod_const + 8*2, mod_const + 8*3, mod_const + 8*4
            for i in range(6): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(start_field, "start", 0); ida_bytes.set_cmt(stop_field, "stop", 0); ida_bytes.set_cmt(step_field, "step", 0)
            add_item_to_collection((), collection, stack_depth,  tracked_indexes, dict_field)
            parse_module_constant(start_field, 3, collection, stack_depth + 1, tracked_indexes, dict_field)
        elif const_type == "slice":
            utils.set_filtered_name(mod_const, "slice_object")
            start_field, stop_field, step_field = mod_const + 8*2, mod_const + 8*3, mod_const + 8*4
            for i in range(5): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(start_field, "start", 0); ida_bytes.set_cmt(stop_field, "stop", 0); ida_bytes.set_cmt(step_field, "step", 0)
            add_item_to_collection([], collection, stack_depth,  tracked_indexes, dict_field)
            parse_module_constant(start_field, 3, collection, stack_depth + 1, tracked_indexes, dict_field)
        elif const_type == "list":
            utils.set_filtered_name(mod_const, "list_object")
            size_field, list_field = mod_const + 8*2, mod_const + 8*3
            for i in range(5): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(size_field, "size", 0); ida_bytes.set_cmt(list_field, "list", 0)
            size = ida_bytes.get_qword(size_field)
            list_ptr = ida_bytes.get_qword(list_field)
            utils.set_filtered_name(list_ptr, "ob_item")
            add_item_to_collection([], collection, stack_depth,  tracked_indexes, dict_field)
            parse_module_constant(list_ptr, size, collection, stack_depth + 1,  tracked_indexes, dict_field)
        elif const_type == "tuple":
            utils.set_filtered_name(mod_const, "tuple_object")
            size_field, tuple_field = mod_const + 8*2, mod_const + 8*3
            for i in range(3): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(size_field, "size", 0)
            size = ida_bytes.get_qword(size_field)
            for i in range(size): ida_bytes.set_cmt(tuple_field + 8*i, f"item[{i}]", 0)
            if dict_field == "key":
                tuple_key = convert_nested_lists_to_tuples(parse_module_constant(curr_ea, 1, dict_field="tuple_key_item"))
                dict_field = "tuple_key"
                add_item_to_collection(tuple_key, collection, stack_depth + 1, tracked_indexes, dict_field)
            else:
                add_item_to_collection((), collection, stack_depth, tracked_indexes, dict_field)
            if dict_field != "tuple_key":
                parse_module_constant(tuple_field, size, collection, stack_depth + 1, tracked_indexes, dict_field)
        elif const_type == "set":
            utils.set_filtered_name(mod_const, "set_object")
            size_field, set_field = mod_const + 8*3, mod_const + 8*5
            for i in range(25): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(size_field, "size", 0); ida_bytes.set_cmt(set_field, "set", 0)
            size = ida_bytes.get_qword(size_field)
            set_ptr = ida_bytes.get_qword(set_field)
            utils.set_filtered_name(set_ptr, "table")
            add_item_to_collection(set(), collection, stack_depth, tracked_indexes, dict_field)
            count, entry = 0, set_ptr
            while count < size:
                key_field, hash_field = entry, entry + 8
                if ida_bytes.get_qword(key_field) != 0:
                    ida_bytes.set_cmt(key_field, "entry", 0)
                    parse_module_constant(key_field, 1, collection, stack_depth + 1, tracked_indexes, dict_field)
                    count += 1
                ida_bytes.create_qword(key_field, 8); ida_bytes.create_qword(hash_field, 8); entry += 16
        elif const_type == "dict":
            utils.set_filtered_name(mod_const, "dict_object")
            ma_keys_field, ma_values_field = mod_const + 8*4, mod_const + 8*5
            for i in range(5): ida_bytes.create_qword(mod_const + 8*i, 8)
            add_item_to_collection({}, collection, stack_depth, tracked_indexes, dict_field)
            if ida_bytes.get_qword(ma_values_field) == 0:
                ida_bytes.set_cmt(ma_keys_field, "dict", 0)
                ma_keys = ida_bytes.get_qword(ma_keys_field)
                utils.set_filtered_name(ma_keys, "ma_keys")
                dk_size_field, dk_nentries_field, dk_indices_field = ma_keys + 8, ma_keys + 8*4, ma_keys + 8*5
                ida_bytes.set_cmt(dk_size_field, "dk_size", 0); ida_bytes.set_cmt(dk_nentries_field, "dk_nentries", 0)
                dk_size = ctypes.c_long(ida_bytes.get_qword(ma_keys + 8)).value
                dk_nentries = ida_bytes.get_qword(ma_keys + 8*4)
                if dk_size == -1: curr_ea += 8; curr_count += 1; continue
                for i in range(6): ida_bytes.create_qword(ma_keys + 8*i, 8)
                if dk_size <= 128: index_size = 1
                elif 256 <= dk_size <= 2**15: index_size = 2
                elif 2**16 <= dk_size <= 2**31: index_size = 4
                else: index_size = 8
                hashtable_size = dk_size * index_size
                idc.make_array(dk_indices_field, hashtable_size // 8)
                dk_entries = dk_indices_field + hashtable_size
                for i in range(dk_nentries):
                    hash_field, key_field, value_field = dk_entries + 24*i, dk_entries + 24*i + 8, dk_entries + 24*i + 16
                    ida_bytes.create_qword(hash_field, 8); ida_bytes.set_cmt(key_field, "key", 0); ida_bytes.set_cmt(value_field, "value", 0)
                    parse_module_constant(key_field, 1, collection, stack_depth + 1, tracked_indexes, "key")
                    parse_module_constant(value_field, 1, collection, stack_depth + 1, tracked_indexes, "value")
        elif const_type == "type":
            tp_name_field = mod_const + 8*3
            tp_name = ida_bytes.get_qword(tp_name_field)
            python_type = ida_bytes.get_strlit_contents(tp_name, -1, ida_nalt.STRTYPE_C).decode()
            utils.set_filtered_name(curr_ea, f"{python_type}", prefix=const_type)
            if python_type in type_mappings: const = type_mappings[python_type]
        elif const_type == "NoneType":
            utils.set_filtered_name(curr_ea, "type_None"); const = None
        elif const_type == "module":
            utils.set_filtered_name(mod_const, "module_object")
            module_name_field = mod_const + 8*6
            for i in range(7): ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(module_name_field, "module name", 0)
            name_object = ida_bytes.get_qword(module_name_field)
            utils.set_filtered_name(name_object, "md_name")
            module_name_bytes = ida_bytes.get_strlit_contents(name_object + 8*6, -1, ida_nalt.STRTYPE_C)
            module_name = module_name_bytes.decode() if module_name_bytes else ""
            utils.set_filtered_name(curr_ea, f"{module_name}", prefix=const_type); const = f"module {module_name}"
        else:
            if stack_depth == 1:
                utils.set_filtered_name(curr_ea, f"{const_type}")
                utils.set_filtered_name(mod_const, "object", prefix=const_type)

        if const_type in scalar_data_types:
            add_item_to_collection(const, collection, stack_depth, tracked_indexes, dict_field)

        if stack_depth == 1:
            if const_type in collection_data_types:
                tracked_indexes.sort(reverse=True)
                for item in tracked_indexes:
                    _, index_lst, original_type = item
                    convert_back_collection(collection, index_lst, original_type)
                const = collection[0]
                if const_type == "range": comment_range_constant(curr_ea, const)
                elif const_type == "slice": comment_slice_constant(curr_ea, const)
                else: ida_bytes.set_cmt(curr_ea, f"{const!r}", 0)
                if not (const_type == "dict" and const and next(iter(const)) == "__name__"):
                    utils.set_filtered_name(curr_ea, f"{const!r}", prefix=const_type)
                else:
                    moduledict_name = f"moduledict_{const['__name__']}"
                    utils.set_filtered_name(curr_ea, f"{moduledict_name}")
            else:
                ida_bytes.set_cmt(curr_ea, f"{const!r}", 0)

        curr_ea += 8
        curr_count += 1
    if collection:
        return collection[0]
    return None


def parse_module_constants(curr_ea=None, max_count=None):
    if curr_ea is None: curr_ea = ida_kernwin.get_screen_ea()
    constants = []
    curr_count = 0
    while max_count is None or curr_count < max_count:
        if not ida_bytes.is_loaded(curr_ea) or ida_bytes.get_qword(curr_ea) == 0: break
        constants.append(parse_module_constant(curr_ea))
        curr_ea += 8
        if max_count is not None: curr_count += 1
    return constants


# =======================================================================
# File: recover_functions.py from original helpers
# =======================================================================
def find_nuitka_function_new():
    func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "Nuitka_Function_New")
    if func_ea == ida_idaapi.BADADDR:
        log.info("`Nuitka_Function_New` not found, using heuristics...")
        module_addrs = [recover_modules.find_entry_point()]
        for func in idautils.Functions():
            name = ida_funcs.get_func_name(func)
            if name and name.startswith("modulecode_") and not name.endswith("__main__"):
                module_addrs.append(func)
        
        found = False
        for module_ea in module_addrs:
            if not module_ea: continue
            for item_ea in idautils.FuncItems(module_ea):
                if idc.print_insn_mnem(item_ea) == "call":
                    call_target_ea = idc.get_operand_value(item_ea, 0)
                    target_func = ida_funcs.get_func(call_target_ea)
                    if not (target_func and target_func.start_ea == call_target_ea):
                        continue
                    
                    try:
                        cfunc = ida_hexrays.decompile(target_func)
                        if not cfunc: continue
                        tif, func_data = ida_typeinf.tinfo_t(), ida_typeinf.func_type_data_t()
                        cfunc.get_func_type(tif)
                        tif.get_func_details(func_data)

                        if len(func_data) == 11:
                            ida_typeinf.apply_tinfo(call_target_ea, tif, ida_typeinf.TINFO_GUESSED)
                            ida_auto.auto_wait()
                            arg_addrs = ida_typeinf.get_arg_addrs(item_ea)
                            if not arg_addrs: continue
                            
                            nuitka_func_ea = idc.get_operand_value(arg_addrs[0], 1)
                            nuitka_func = ida_funcs.get_func(nuitka_func_ea)
                            if nuitka_func and nuitka_func.start_ea == nuitka_func_ea:
                                func_ea = call_target_ea
                                found = True
                                utils.set_filtered_name(func_ea, "Nuitka_Function_New")
                                break
                    except ida_hexrays.DecompilationFailure:
                        continue
            if found: break
        
        if not found:
            raise Exception("Failed to find Nuitka_Function_New using heuristics.")

    utils.set_type(func_ea, "Nuitka_Function_New")
    log.info(f"`Nuitka_Function_New` found at {hex(func_ea)}")
    return func_ea


def find_nuitka_functions():
    labelled_funcs = {}
    for func in idautils.Functions():
        name = ida_funcs.get_func_name(func)
        if name and name.startswith("modulecode_"):
            labelled_funcs[name[11:]] = []

    try:
        ea = find_nuitka_function_new()
    except Exception as e:
        log.error(f"Cannot find Nuitka functions: {e}")
        return labelled_funcs

    for xref in idautils.XrefsTo(ea):
        func = ida_funcs.get_func(xref.frm)
        if not func: continue
        module_func_name = ida_name.get_name(func.start_ea)
        if module_func_name and module_func_name.startswith("modulecode_"):
            module_name = module_func_name[11:]
            if args_ea := ida_typeinf.get_arg_addrs(xref.frm):
                try:
                    func_code_ea = idc.get_operand_value(args_ea[0], 1)
                    func_name_ea = idc.get_operand_value(args_ea[1], 1)
                    if ida_name.get_name(func_code_ea):
                        func_name_cmt = ida_bytes.get_cmt(func_name_ea, 0)
                        if func_name_cmt:
                            func_name_str = func_name_cmt.strip("'\"")
                            full_func_name = f"{module_name}.{func_name_str}"
                            utils.set_filtered_name(func_code_ea, full_func_name)
                            if module_name in labelled_funcs:
                                labelled_funcs[module_name].append(ida_name.get_name(func_code_ea))
                except (IndexError, TypeError):
                    continue
    return labelled_funcs


def group_nuitka_functions(labelled_funcs):
    log.info("Grouping functions into folders...")
    try:
        func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        for module_name, funcs in labelled_funcs.items():
            folder_name = module_name.replace(".", "/")
            func_dir.mkdir(folder_name)
            module_func_name = f"modulecode_{module_name}"
            if ida_name.get_name_ea(ida_idaapi.BADADDR, module_func_name) != ida_idaapi.BADADDR:
                func_dir.rename(module_func_name, f"{folder_name}/{module_func_name}")
            for func_name in funcs:
                if ida_name.get_name_ea(ida_idaapi.BADADDR, func_name) != ida_idaapi.BADADDR:
                    func_dir.rename(func_name, f"{folder_name}/{func_name}")
        log.info("Function grouping complete.")
    except Exception as e:
        log.error(f"Failed to group functions: {e}")

recover_functions = sys.modules[__name__]


# =======================================================================
# File: recover_constants.py from original helpers
# =======================================================================
def force_load_constants(module_data):
    log.info("Attempting to force-load constants via Appcall...")
    try:
        loadConstantsBlob = ida_idd.Appcall.loadConstantsBlob
    except AttributeError:
        log.error("`loadConstantsBlob` Appcall not available. Cannot force-load constants.")
        return

    for module_name, (mod_consts_rva, module_name_rva) in module_data.items():
        if module_name == "__main__": continue
        mod_consts = mod_consts_rva + ida_nalt.get_imagebase()
        module_name_ea = module_name_rva + ida_nalt.get_imagebase()
        log.info(f"Loading constants for {module_name}...")
        try:
            loadConstantsBlob(0, mod_consts, module_name_ea)
            time.sleep(0.1)
        except Exception as e:
            log.error(f"Appcall failed for {module_name}: {e}")

    ida_dbg.refresh_debugger_memory()
    log.info("Constant loading finished.")


def parse_all_constants(module_data, log_file="constants.log"):
    log_path = os.path.join(output_directory, log_file)
    log.info(f"Parsing all module constants. Results will be in {log_path}")
    try:
        with open(log_path, "w", encoding='utf-8') as f:
            for module_name, (mod_consts_rva, _) in module_data.items():
                f.write(f"{'-'*30} [modulecode_{module_name}] {'-'*30}\n")
                mod_consts = mod_consts_rva + ida_nalt.get_imagebase()
                try:
                    constants = parse_module_constants(mod_consts)
                    for c in constants:
                        f.write(f"{c!r}\n")
                except Exception as e:
                    f.write(f"[ERROR] Failed to recover constants for {module_name}: {e}\n")
                f.write("\n")
        log.info("Finished parsing all constants.")
    except IOError as e:
        log.error(f"Could not write to constants log file: {e}")


def recover_constants_main():
    log.info("Starting constant recovery process...")
    main_ea = recover_modules.find_entry_point()
    if not main_ea:
        log.error("Cannot recover constants without an entry point.")
        return
    module_data = recover_modules.find_custom_modules()

    ida_dbg.add_bpt(main_ea)
    utils.start_debugger()

    force_load_constants(module_data)
    parse_all_constants(module_data)

    utils.stop_debugger()
    ida_dbg.del_bpt(main_ea)
    ida_auto.auto_wait()
    log.info("Constant recovery process finished.")

recover_constants = sys.modules[__name__]


# =======================================================================
# File: recover_library_code.py from original helpers
# =======================================================================
def load_structs(path=""):
    if not path:
        path = ida_kernwin.ask_file(0, "*.h", "Select C header file for Nuitka structs")
    if path and os.path.exists(path):
        log.info(f"Parsing C header file: {path}")
        idc.parse_decls(path, idc.PT_FILE)
        ida_auto.auto_wait()
    else:
        log.warning("Struct file not provided or not found. Analysis may be incomplete.")


def load_flirt_signature(path=""):
    if not path:
        path = ida_kernwin.ask_file(0, "*.sig", "Select FLIRT signature file")
    if path and os.path.exists(path):
        log.info(f"Applying FLIRT signature: {path}")
        ida_funcs.plan_to_apply_idasgn(path)
        ida_auto.auto_wait()
    else:
        log.warning("FLIRT signature not provided or not found.")

recover_library_code = sys.modules[__name__]


# =======================================================================
# NEW: Stage 3 - User-Mode Code Extraction and Import Consolidation
# =======================================================================
def run_stage3_analysis(module_data):
    """
    MODIFIED: Analyzes Stage 2 files with a more robust method to consolidate
    all unique imports at the top of a new script, followed by all the
    user-defined code from each module. Also includes modules found via
    IDA Pro analysis.
    """
    log.info("Starting Stage 3: Consolidating imports and user-mode code...")

    # Regex to find all standard and 'from' imports, no longer anchored to the start of a line.
    # This will find imports inside functions as well. Handles multi-line imports.
    import_pattern = re.compile(
        r"from[ \t]+[.\w]+[ \t]+import[ \t]+(?:[\w, ]+|\*|\([\w, \n\r]+\))|import[ \t]+[.\w, ]+"
    )
    
    all_usermode_code = []
    all_imports = set()

    # Add IDA-discovered modules first
    if module_data:
        for module_name in module_data.keys():
            if module_name != "__main__":
                # Sanitize the module name before adding
                clean_module_name = module_name.replace('_', '.')
                all_imports.add(f"import {clean_module_name}")
        log.info(f"Added {len(all_imports)} modules from IDA analysis.")

    if not os.path.exists(stage2_dir) or not os.listdir(stage2_dir):
        log.warning("Stage 2 directory is empty. Nothing to analyze for Stage 3.")
        # Still proceed to write the file if we got imports from IDA analysis
    else:
        for filename in sorted(os.listdir(stage2_dir)):
            if not filename.endswith(".py"):
                continue

            file_path = os.path.join(stage2_dir, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Find all import statements in the file using the more flexible regex
                imports_in_file = import_pattern.findall(content)
                all_imports.update(imp.strip() for imp in imports_in_file)

                # Remove the found imports from the content to leave only user-mode code
                usermode_code = import_pattern.sub('', content).strip()

                if usermode_code:
                    module_name_from_file = filename.replace("stage2_", "").replace(".py", "")
                    header = f"""
# =======================================================================
# User-mode code from module: {module_name_from_file.replace('_', '.')}
# =======================================================================
"""
                    all_usermode_code.append(header + usermode_code)
                else:
                    log.info(f"No user-mode code found in {filename} after removing imports.")

            except Exception as e:
                log.error(f"Could not analyze file {filename}: {e}")

    # Clean and sort the collected imports
    cleaned_imports = sorted([imp for imp in list(all_imports) if imp])

    # Write the final consolidated file
    output_file = os.path.join(stage3_dir, "stage3_usermode_code.py")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# Stage 3: Consolidated User-Mode Code\n")
            f.write("# This file contains all unique imports followed by user code from all modules.\n\n")
            
            f.write("# --- Consolidated & Filtered Imports (from text and IDA analysis) ---\n")
            if cleaned_imports:
                f.write("\n".join(cleaned_imports))
            f.write("\n\n# --- End of Imports ---\n")

            f.write("\n\n".join(all_usermode_code))
            
        log.info(f"Consolidated code with all imports moved to top saved to: {output_file}")
    except IOError as e:
        log.error(f"Failed to write consolidated code file: {e}")


# =======================================================================
# Main execution logic
# =======================================================================
def full_recovery():
    """
    This is the main analysis function that runs through all recovery steps.
    """
    ida_kernwin.msg_clear()
    log.info("="*50)
    log.info("Starting Nuitka Full Recovery")
    log.info("="*50)

    # Step 1: Load signatures and type info (optional)
    log.info("[Step 1] Loading library code information (structs/signatures)...")
    # recover_library_code.load_structs()
    # recover_library_code.load_flirt_signature()

    # Step 2: Find all modules
    log.info("[Step 2] Finding modules...")
    main_ea = recover_modules.find_entry_point()
    if not main_ea:
        log.error("Full recovery aborted: Could not find main entry point.")
        return
    module_data = recover_modules.find_custom_modules()
    log.info(f"Found {len(module_data)} custom modules.")

    # Step 3: Recover constants
    log.info("[Step 3] Recovering constants...")
    parse_all_constants(module_data)

    # Step 4: Recover and group functions
    log.info("[Step 4] Finding and grouping Nuitka functions...")
    labelled_funcs = recover_functions.find_nuitka_functions()
    recover_functions.group_nuitka_functions(labelled_funcs)

    # Step 5: Extract special RCDATA resource
    log.info("[Step 5] Extracting special RCDATA resource...")
    extracted_rsrc_path = extract_special_rcdata_resource()

    # Step 6: Scan extracted RCDATA for source code (Creates Stage 2)
    if extracted_rsrc_path:
        log.info("[Step 6] Scanning extracted RCDATA for source code...")
        scan_rsrc_file(extracted_rsrc_path)

    # Step 7: NEW - Run Stage 3 analysis to extract and consolidate code
    log.info("[Step 7] Running Stage 3 analysis on reconstructed files...")
    run_stage3_analysis(module_data)

    log.info("="*50)
    log.info("Nuitka Full Recovery Finished.")
    log.info("="*50)
    ida_kernwin.info("Nuitka analysis complete. Check the output window for logs.")


if __name__ == "__main__":
    ida_auto.auto_wait()
    full_recovery()
