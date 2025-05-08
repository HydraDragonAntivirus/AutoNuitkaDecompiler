import os
import logging
import subprocess
import shutil
import inspect
import string
import re
import ipaddress
import sys
from datetime import datetime
import time
import io
import pefile
import zstandard
from elftools.elf.elffile import ELFFile
import macholib.MachO
import macholib.mach_o
from typing import Optional, Tuple, BinaryIO, Dict, Any
import struct
from pathlib import Path

# Set script directory
script_dir = os.getcwd()

# Define log directories and files
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Separate log files for different purposes
console_log_file = os.path.join(log_directory, "antivirusconsole.log")
application_log_file = os.path.join(log_directory, "antivirus.log")

# Configure logging for application log
logging.basicConfig(
    filename=application_log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Logging for application initialization
logging.info("Application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_json_dir = os.path.join(script_dir, "detectiteasy_json")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
nuitka_source_code_dir = os.path.join(script_dir, "nuitkasourcecode")
nuitka_dir = os.path.join(script_dir, "nuitka")
general_extracted_dir = os.path.join(script_dir, "general_extracted")

# Ensure output directories exist
os.makedirs(nuitka_source_code_dir, exist_ok=True)
os.makedirs(nuitka_dir, exist_ok=True)
os.makedirs(general_extracted_dir, exist_ok=True)

def get_unique_output_path(output_dir: Path, base_name: str, suffix: int = 1) -> Path:
    """
    Generate a unique file path by appending a suffix (e.g., _1, _2) if the file already exists.
    """
    new_path = output_dir / f"{base_name.stem}_{suffix}{base_name.suffix}"

    while new_path.exists():  # If the file exists, increment the suffix
        suffix += 1
        new_path = output_dir / f"{base_name.stem}_{suffix}{base_name.suffix}"

    return new_path

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
    """
    Recursively scan a directory for .exe, .dll, and other files, prioritizing Nuitka executables.
    If an .exe file is found and confirmed as Nuitka, stop further scanning.
    """
    found_executables = []

    # Look for .exe files first
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.exe'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as .exe is found

    # If no .exe found, look for .dll files
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.dll'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as .dll is found

    # If no .exe or .dll found, check other files
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if not file.lower().endswith(('.exe', '.dll')):  # Skip .exe and .dll files
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as Nuitka file is found

    return found_executables

def get_resource_name(entry):
    # Get the resource name, which might be a string or an ID
    if hasattr(entry, 'name') and entry.name is not None:
        return str(entry.name)
    else:
        return str(entry.id)

def extract_rcdata_resource(pe_path):
    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        logging.error(f"Error loading PE file: {e}")
        return None, []

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        logging.error("No resources found in this file.")
        return None, []

    first_rcdata_file = None
    all_extracted_files = []

    output_dir = os.path.join(general_extracted_dir, os.path.splitext(os.path.basename(pe_path))[0])
    os.makedirs(output_dir, exist_ok=True)

    # Bu örnekte özellikle 10_3_0.bin’i bulduğumuz anda döndürüyoruz:
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_name = get_resource_name(resource_type)
        if not hasattr(resource_type, 'directory'):
            continue

        for resource_id in resource_type.directory.entries:
            res_id = get_resource_name(resource_id)
            if not hasattr(resource_id, 'directory'):
                continue

            for resource_lang in resource_id.directory.entries:
                lang_id = resource_lang.id
                data_rva = resource_lang.data.struct.OffsetToData
                size = resource_lang.data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]

                file_name = f"{type_name}_{res_id}_{lang_id}.bin"
                output_path = os.path.join(output_dir, file_name)
                with open(output_path, "wb") as f:
                    f.write(data)

                logging.info(f"Extracted resource saved: {output_path}")
                all_extracted_files.append(output_path)

                # Eğer bu tam istediğimiz isimse, hemen döndür
                if file_name == "10_3_0.bin":
                    logging.info(f"Found target RCData: {output_path}")
                    return output_path, all_extracted_files

                # İlk RCData’yı da istersen ayrı olarak yakalayabilirsin
                if type_name.lower() in ("rcdata", "10") and first_rcdata_file is None:
                    first_rcdata_file = output_path

    if first_rcdata_file is None:
        logging.info("No RCData resource found.")
        return None, all_extracted_files

    logging.info(f"Using first RCData: {first_rcdata_file}")
    return first_rcdata_file, all_extracted_files

def clean_text(input_text):
    """
    Remove non-printable ASCII control characters from the input text.

    :param input_text: The string to clean.
    :return: Cleaned text with control characters removed.
    """
    # Remove non-printable characters (ASCII 0-31 and 127)
    cleaned_text = re.sub(r'[\x00-\x1F\x7F]+', '', input_text)
    return cleaned_text

def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

# Function to scan code for links (domains, IPs, URLs, and Discord links)
def scan_code_for_links(code):
    """
    Scan a given string of code for domains, IP addresses, URLs, and Discord webhook/Discord invite URLs,
    removing duplicates.
    """
    try:
        # Regular expressions for different patterns
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        url_pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        discord_webhook_pattern = r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
        discord_canary_webhook_pattern = r'https://canary\.discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
        discord_invite_pattern = r'https://discord\.gg/[A-Za-z0-9]+'
        telegram_token_pattern = r'\d{9,10}:[A-Za-z0-9_-]{35}'
        telegram_keyword_pattern = r'\b(?:telegram|token)\b'
 
        # Perform scans and store results in sets to automatically remove duplicates
        ip_matches = set(re.findall(ip_pattern, code))
        domain_matches = set(re.findall(domain_pattern, code))
        url_matches = set(re.findall(url_pattern, code))
        discord_webhook_matches = set(re.findall(discord_webhook_pattern, code))
        discord_canary_webhook_matches = set(re.findall(discord_canary_webhook_pattern, code))
        discord_invite_matches = set(re.findall(discord_invite_pattern, code))

        # Telegram token (case-sensitive): run on original code
        telegram_token_matches = re.findall(telegram_token_pattern, code)

        # Telegram keyword (case-insensitive): run with re.IGNORECASE
        telegram_keyword_matches = re.findall(telegram_keyword_pattern, code, flags=re.IGNORECASE)

        # Filter out local IP addresses
        ip_matches = {ip for ip in ip_matches if not is_local_ip(ip)}

        # Logging the findings
        if ip_matches:
            logging.info(f"IP addresses detected (excluding local IPs): {ip_matches}")
        if domain_matches:
            logging.info(f"Domains detected: {domain_matches}")
        if url_matches:
            logging.info(f"URLs detected: {url_matches}")
        if discord_webhook_matches:
            logging.warning(f"Discord webhook URLs detected: {discord_webhook_matches}")
        if discord_canary_webhook_matches:
            logging.warning(f"Discord Canary webhook URLs detected: {discord_canary_webhook_matches}")
        if discord_invite_matches:
            logging.info(f"Discord invite links detected: {discord_invite_matches}")
        if telegram_token_matches and telegram_keyword_matches:
            logging.info(f"Telegram token links detected: {telegram_token_matches}")

    except Exception as ex:
        logging.error(f"Error scanning code for links: {ex}")

def scan_rsrc_files(file_paths):
    """
    Given a list of file paths for rsrcdata resources, this function scans each file 
    and processes only the first file that contains the string 'upython.exe'.
    Once found, it extracts the source code portion starting after 'upython.exe',
    cleans it, saves it to a uniquely named file, and scans the code for domains, 
    URLs, IP addresses, and Discord webhooks.
    
    :param file_paths: List of file paths to be scanned.
    """
    if isinstance(file_paths, str):
        file_paths = [file_paths]

    executable_file = None

    # First, iterate over the file paths to find the one containing 'upython.exe'
    for file_path in file_paths:
        if os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    if "upython.exe" in f.read():
                        executable_file = file_path
                        logging.info(f"Found executable in: {file_path}")
                        break  # Stop at the first match
            except Exception as ex:
                logging.error(f"Error reading file {file_path}: {ex}")
        else:
            logging.warning(f"Path {file_path} is not a valid file.")

    if executable_file is None:
        logging.info("No file containing 'upython.exe' was found.")
        return

    # Process the file that contains 'upython.exe'
    try:
        logging.info(f"Processing file: {executable_file}")
        with open(executable_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        if lines:
            source_index = None
            for i, line in enumerate(lines):
                if "upython.exe" in line:
                    source_index = i
                    break

            if source_index is not None:
                line_with_marker = lines[source_index]
                marker_index = line_with_marker.find("upython.exe")
                remainder = line_with_marker[marker_index + len("upython.exe"):].lstrip()

                source_code_lines = []
                if remainder:
                    source_code_lines.append(remainder)
                source_code_lines.extend(lines[source_index + 1:])

                cleaned_source_code = [clean_text(line.rstrip()) for line in source_code_lines]

                base_name = os.path.splitext(os.path.basename(executable_file))[0]
                save_filename = f"{base_name}_source_code.txt"
                save_path = os.path.join(nuitka_source_code_dir, save_filename)

                # If a file with the same name exists, append a counter
                counter = 1
                while os.path.exists(save_path):
                    save_filename = f"{base_name}_source_code_{counter}.txt"
                    save_path = os.path.join(nuitka_source_code_dir, save_filename)
                    counter += 1

                # Make absolutely sure the parent directory exists
                os.makedirs(os.path.dirname(save_path), exist_ok=True)

                with open(save_path, "w", encoding="utf-8") as save_file:
                    for line in cleaned_source_code:
                        save_file.write(line + "\n")
                logging.info(f"Saved extracted source code from {executable_file} to {save_path}")

                extracted_source_code = ''.join(source_code_lines)
                scan_code_for_links(extracted_source_code)
            else:
                logging.info(f"No line containing 'upython.exe' found in {executable_file}.")
        else:
            logging.info(f"File {executable_file} is empty.")
    except Exception as ex:
        logging.error(f"Error during file scanning of {executable_file}: {ex}")

class FileType:
    UNKNOWN = -1
    ELF = 0
    PE = 1
    MACHO = 2

class CompressionFlag:
    UNKNOWN = -1
    NON_COMPRESSED = 0
    COMPRESSED = 1

class PayloadError(Exception):
    """Custom exception for payload processing errors"""
    pass

class NuitkaPayload:
    MAGIC_KA = b'KA'
    MAGIC_UNCOMPRESSED = ord('X')
    MAGIC_COMPRESSED = ord('Y')
    
    def __init__(self, data: bytes, offset: int, size: int):
        self.data = data
        self.offset = offset
        self.size = size
        self.compression = CompressionFlag.UNKNOWN
        self._validate()
    
    def _validate(self):
        """Validate payload magic and set compression flag"""
        if not self.data.startswith(self.MAGIC_KA):
            raise PayloadError("Invalid Nuitka payload magic")
        
        magic_type = self.data[2]
        if magic_type == self.MAGIC_UNCOMPRESSED:
            self.compression = CompressionFlag.NON_COMPRESSED
        elif magic_type == self.MAGIC_COMPRESSED:
            self.compression = CompressionFlag.COMPRESSED
        else:
            raise PayloadError(f"Unknown compression magic: {magic_type}")
    
    def get_stream(self) -> BinaryIO:
        """Get a file-like object for reading the payload"""
        # Skip the 3-byte magic header
        payload_data = self.data[3:]
        stream = io.BytesIO(payload_data)
        
        if self.compression == CompressionFlag.COMPRESSED:
            try:
                dctx = zstandard.ZstdDecompressor()
                # Create a stream reader with a large read size
                return dctx.stream_reader(stream, read_size=8192)
            except zstandard.ZstdError as ex:
                raise PayloadError(f"Failed to initialize decompression: {str(ex)}")
        return stream

def is_pe_file(file_path):
    """Check if the file at the specified path is a PE (Portable Executable) file using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be PE check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for PE32 or PE64 in the result
        if "PE32" in result.stdout or "PE64" in result.stdout:
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"PE file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a PE file. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

def is_elf_file(file_path):
    """Check if the file at the specified path is an ELF file using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be ELF check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for ELF format in the result
        if "ELF32" in result.stdout or "ELF64" in result.stdout:
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"ELF file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not an ELF file. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

def is_macho_file(file_path):
    """Check if the file at the specified path is a Mach-O file using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be Mach-O check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for Mach-O in the result
        if "Mach-O" in result.stdout:
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"Mach-O file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a Mach-O file. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

class NuitkaExtractor:
    def __init__(self, filepath: str, output_dir: str):
        self.filepath = filepath
        self.output_dir = output_dir
        self.file_type = FileType.UNKNOWN
        self.payload: Optional[NuitkaPayload] = None
    
    def _detect_file_type(self) -> int:
        """Detect the executable file type using Detect It Easy methods"""
        if is_pe_file(self.filepath):
            return FileType.PE
        elif is_elf_file(self.filepath):
            return FileType.ELF
        elif is_macho_file(self.filepath):
            return FileType.MACHO
        return FileType.UNKNOWN

    def _find_pe_resource(self, pe: pefile.PE) -> Tuple[Optional[int], Optional[int]]:
        """Find the Nuitka resource in PE file"""
        try:
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(entry, 'directory'):
                    for entry1 in entry.directory.entries:
                        if entry1.id == 27:  # Nuitka's resource ID
                            if hasattr(entry1, 'directory'):
                                data_entry = entry1.directory.entries[0]
                                if hasattr(data_entry, 'data'):
                                    offset = pe.get_offset_from_rva(data_entry.data.struct.OffsetToData)
                                    size = data_entry.data.struct.Size
                                    return offset, size
        except Exception:
            pass
        return None, None

    def _extract_pe_payload(self) -> Optional[NuitkaPayload]:
        """Extract payload from PE file"""
        try:
            pe = pefile.PE(self.filepath, fast_load=False)
            
            # Find RT_RCDATA resource with ID 27
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                raise PayloadError("No resource directory found")
            
            offset, size = self._find_pe_resource(pe)
            if offset is None or size is None:
                raise PayloadError("No Nuitka payload found in PE resources")
            
            # Read the payload data
            with open(self.filepath, 'rb') as f:
                f.seek(offset)
                payload_data = f.read(size)
                
            return NuitkaPayload(payload_data, offset, size)
            
        except Exception as ex:
            raise PayloadError(f"PE payload extraction failed: {str(ex)}")

    def _extract_elf_payload(self) -> Optional[NuitkaPayload]:
        """Extract payload from ELF file"""
        try:
            with open(self.filepath, 'rb') as f:
                elf = ELFFile(f)
                
                # Find last section to locate appended data
                last_section = max(elf.iter_sections(), 
                                 key=lambda s: s.header.sh_offset + s.header.sh_size)
                
                # Read trailer for payload size
                f.seek(-8, io.SEEK_END)
                payload_size = struct.unpack('<Q', f.read(8))[0]
                
                # Read payload
                payload_offset = last_section.header.sh_offset + last_section.sh_size
                f.seek(payload_offset)
                payload_data = f.read(payload_size)
                
                return NuitkaPayload(payload_data, payload_offset, payload_size)
                
        except Exception as ex:
            raise PayloadError(f"ELF payload extraction failed: {str(ex)}")

    def _extract_macho_payload(self) -> Optional[NuitkaPayload]:
        """Extract payload from Mach-O file"""
        try:
            macho = macholib.MachO.MachO(self.filepath)
            
            for header in macho.headers:
                for cmd in header.commands:
                    if cmd[0].cmd in (macholib.mach_o.LC_SEGMENT, macholib.mach_o.LC_SEGMENT_64):
                        for section in cmd[1].sections:
                            if section[0].decode('utf-8') == 'payload':
                                offset = section[2]
                                size = section[3]
                                
                                with open(self.filepath, 'rb') as f:
                                    f.seek(offset)
                                    payload_data = f.read(size)
                                    return NuitkaPayload(payload_data, offset, size)
                                    
            raise PayloadError("No payload section found in Mach-O file")
            
        except Exception as ex:
            raise PayloadError(f"Mach-O payload extraction failed: {str(ex)}")

    def _read_string(self, stream: BinaryIO, is_wide: bool = False) -> Optional[str]:
        """Read a null-terminated string from the stream"""
        result = bytearray()
        while True:
            char = stream.read(2 if is_wide else 1)
            if not char or char == b'\0' * len(char):
                break
            result.extend(char)
        
        if not result:
            return None
            
        try:
            return result.decode('utf-16-le' if is_wide else 'utf-8')
        except UnicodeDecodeError:
            return None

    def _extract_files(self, stream: BinaryIO):
        """Extract files from the payload stream"""
        total_files = 0
        os.makedirs(self.output_dir, exist_ok=True)

        try:
            while True:
                # Read filename
                filename = self._read_string(stream, is_wide=(self.file_type == FileType.PE))
                if not filename:
                    break

                # Read file flags for ELF
                if self.file_type == FileType.ELF:
                    stream.read(1)  # Skip flags

                # Read file size
                size_data = stream.read(8)
                if not size_data or len(size_data) != 8:
                    break
                    
                file_size = struct.unpack('<Q', size_data)[0]

                # Sanitize output path
                safe_output_dir = str(self.output_dir).replace('..', '__')
                outpath = os.path.join(safe_output_dir, filename)
                os.makedirs(os.path.dirname(outpath), exist_ok=True)

                # Extract file
                try:
                    with open(outpath, 'wb') as f:
                        remaining = file_size
                        while remaining > 0:
                            chunk_size = min(remaining, 8192)
                            data = stream.read(chunk_size)
                            if not data:
                                logging.warning(f"Incomplete read for {filename}")
                                break
                            f.write(data)
                            remaining -= len(data)
                    total_files += 1
                    logging.info(f"[+] Extracted: {filename}")
                except Exception as ex:
                    logging.error(f"Failed to extract {filename}: {ex}")
                    continue

        except Exception as ex:
            logging.error(f"Extraction error: {ex}")

        return total_files

    def extract(self):
        """Main extraction process"""
        try:
            # Detect file type using the new detection methods
            self.file_type = self._detect_file_type()
            if self.file_type == FileType.UNKNOWN:
                raise PayloadError("Unsupported file type")
            
            logging.info(f"[+] Processing: {self.filepath}")
            logging.info(f"[+] Detected file type: {['ELF', 'PE', 'MACHO'][self.file_type]}")

            # Extract payload based on file type
            if self.file_type == FileType.PE:
                self.payload = self._extract_pe_payload()
            elif self.file_type == FileType.ELF:
                self.payload = self._extract_elf_payload()
            else:  # MACHO
                self.payload = self._extract_macho_payload()
            
            if not self.payload:
                raise PayloadError("Failed to extract payload")
            
            logging.info(f"[+] Payload size: {self.payload.size} bytes")
            logging.info(f"[+] Compression: {'Yes' if self.payload.compression == CompressionFlag.COMPRESSED else 'No'}")
            
            # Extract files from payload
            stream = self.payload.get_stream()
            total_files = self._extract_files(stream)
            
            logging.info(f"[+] Successfully extracted {total_files} files to {self.output_dir}")
            
        except PayloadError as ex:
            logging.error(f"[!] {str(ex)}")
        except Exception as ex:
            logging.error(f"[!] Unexpected error: {str(ex)}")

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

            # Use NuitkaExtractor for extraction
            extractor = NuitkaExtractor(file_path, nuitka_output_dir)
            extractor.extract()

            # Scan the extracted directory for additional Nuitka executables
            logging.info(f"Scanning extracted directory for additional Nuitka executables...")
            found_executables = scan_directory_for_executables(nuitka_output_dir)

            # Process any found normal Nuitka executables
            for exe_path, exe_type in found_executables:
                if exe_type == "Nuitka":
                    logging.info(f"Found normal Nuitka executable in extracted files: {exe_path}")
                    extract_nuitka_file(exe_path, exe_type)

        elif nuitka_type == "Nuitka":
            logging.info(f"Nuitka executable detected in {file_path}")

            # Extract the Nuitka executable
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]

            # Use enhanced pefile for RCData Nuitka bytecode extraction
            extracted_files = extract_rcdata_resource(file_path)

            if extracted_files:
                logging.info(f"Successfully extracted bytecode or RCDATA file from Nuitka executable: {file_path}")
                # Scan for RSRC/RCDATA bytecode resources
                scan_rsrc_files(extracted_files)
            else:
                logging.error(f"Failed to extract normal Nuitka executable: {file_path}")

        else:
            logging.info(f"No Nuitka content found in {file_path}")

    except PayloadError as ex:
        logging.error(f"Payload error while extracting Nuitka file: {ex}")
    except Exception as ex:
        logging.error(f"Unexpected error while extracting Nuitka file: {ex}")

# Main script logic to ask for the user input (file path)
if __name__ == "__main__":
    file_path = input("Enter the path to the Nuitka executable file or directory: ").strip()

    # Check if the provided path exists
    if os.path.exists(file_path):
        if os.path.isdir(file_path):
            # Input is a directory; walk through every file in the directory recursively.
            for root, _, files in os.walk(file_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    nuitka_type = is_nuitka_file(full_path)
                    if nuitka_type:
                        logging.info(f"Found Nuitka executable: {full_path} - Type: {nuitka_type}")
                        extract_nuitka_file(full_path, nuitka_type)
                    else:
                        logging.info(f"File {full_path} is not a Nuitka executable.")
        elif os.path.isfile(file_path):
            # Input is a single file; process it directly.
            nuitka_type = is_nuitka_file(file_path)
            if nuitka_type:
                extract_nuitka_file(file_path, nuitka_type)
            else:
                logging.info("The file is not a Nuitka executable.")
    else:
        logging.error(f"The path {file_path} does not exist.")