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

console_log_file = os.path.join(log_directory, "antivirusconsole.log")
application_log_file = os.path.join(log_directory, "antivirus.log")

logging.basicConfig(
    filename=application_log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Set UTF-8 encoding for I/O with error handling
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8', errors='ignore')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8', errors='ignore')
sys.stdin = io.TextIOWrapper(sys.stdin.detach(), encoding='utf-8', errors='ignore')

logging.info("Application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Define directories for resources and outputs
detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_json_dir = os.path.join(script_dir, "detectiteasy_json")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
nuitka_source_code_dir = os.path.join(script_dir, "nuitkasourcecode")
nuitka_dir = os.path.join(script_dir, "nuitka")
general_extracted_dir = os.path.join(script_dir, "general_extracted")
train_dir = os.path.join(script_dir, "train")  # Directory to hold signatures

# Unified signature file path (all signatures will be stored in one file)
UNIFIED_SIGNATURE_FILE = os.path.join(train_dir, "unified_signatures.txt")

for d in (nuitka_source_code_dir, nuitka_dir, general_extracted_dir, train_dir):
    os.makedirs(d, exist_ok=True)

def get_unique_output_path(output_dir: Path, base_name: str, suffix: int = 1) -> Path:
    new_path = output_dir / f"{base_name.stem}_{suffix}{base_name.suffix}"
    while new_path.exists():
        suffix += 1
        new_path = output_dir / f"{base_name.stem}_{suffix}{base_name.suffix}"
    return new_path

def is_nuitka_file(file_path):
    """Check if the file is a Nuitka executable using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        result = subprocess.run([detectiteasy_console_path, file_path],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
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
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} for {file_path}: {ex}")
        return None
    return None

def scan_directory_for_executables(directory):
    """
    Recursively scan a directory for .exe, .dll, .msi, and .kext files,
    prioritizing Nuitka executables.
    If a file is found and confirmed as Nuitka, stop further scanning.
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

    # If no .exe or .dll found, look for .msi files
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.msi'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as .msi is found

    # Check for macOS kernel extensions (.kext files)
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.kext'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as .kext is found

    # If none of the above, check other files
    for root, _, files in os.walk(directory):
        for file in files:
            if not file.lower().endswith(('.exe', '.dll', '.msi', '.kext')):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as a Nuitka file is found

    return found_executables

def get_resource_name(entry):
    if hasattr(entry, 'name') and entry.name is not None:
        return str(entry.name)
    else:
        return str(entry.id)

def extract_rcdata_resource(pe_path):
    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        logging.info(f"Error loading PE file: {e}")
        return None
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        logging.info("No resources found in this file.")
        return None
    first_rcdata_file = None
    all_extracted_files = []
    output_dir = os.path.join(general_extracted_dir, os.path.splitext(os.path.basename(pe_path))[0])
    os.makedirs(output_dir, exist_ok=True)
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
                if type_name.lower() in ("rcdata", "10") and first_rcdata_file is None:
                    first_rcdata_file = output_path
    if first_rcdata_file is None:
        logging.info("No RCData resource found.")
    else:
        logging.info(f"Using RCData resource file: {first_rcdata_file}")
    return first_rcdata_file

def clean_text(input_text):
    cleaned_text = re.sub(r'[\x00-\x1F\x7F]+', '', input_text)
    return cleaned_text

def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def scan_code_for_links(code):
    try:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        url_pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        discord_webhook_pattern = r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
        discord_canary_webhook_pattern = r'https://canary\.discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
        discord_invite_pattern = r'https://discord\.gg/[A-Za-z0-9]+'
        ip_matches = set(re.findall(ip_pattern, code))
        domain_matches = set(re.findall(domain_pattern, code))
        url_matches = set(re.findall(url_pattern, code))
        discord_webhook_matches = set(re.findall(discord_webhook_pattern, code))
        discord_canary_webhook_matches = set(re.findall(discord_canary_webhook_pattern, code))
        discord_invite_matches = set(re.findall(discord_invite_pattern, code))
        ip_matches = {ip for ip in ip_matches if not is_local_ip(ip)}
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
    except Exception as ex:
        logging.error(f"Error scanning code for links: {ex}")

def scan_rsrc_file(file_path, mode=None):
    """
    Scans the provided file for a line containing 'upython.exe', extracts the source code that follows,
    saves the cleaned code, scans it for links, and (if mode is provided) processes its signature.
    """
    try:
        if os.path.isfile(file_path):
            logging.info(f"Processing file: {file_path}")
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
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
                        base_name = os.path.splitext(os.path.basename(file_path))[0]
                        save_path = os.path.join(nuitka_source_code_dir, f"{base_name}_source_code.txt")
                        counter = 1
                        while os.path.exists(save_path):
                            save_path = os.path.join(nuitka_source_code_dir, f"{base_name}_source_code_{counter}.txt")
                            counter += 1
                        with open(save_path, "w", encoding="utf-8") as save_file:
                            for line in cleaned_source_code:
                                save_file.write(line + "\n")
                        logging.info(f"Saved extracted source code from {file_path} to {save_path}")
                        extracted_source_code = ''.join(source_code_lines)
                        scan_code_for_links(extracted_source_code)
                        # Process signature if a mode is specified (train or normal)
                        if mode is not None:
                            process_source_file(save_path, mode)
                    else:
                        logging.info(f"No line containing 'upython.exe' found in {file_path}.")
                else:
                    logging.info(f"File {file_path} is empty.")
            except Exception as ex:
                logging.error(f"Error reading file {file_path}: {ex}")
        else:
            logging.warning(f"Path {file_path} is not a valid file.")
    except Exception as ex:
        logging.error(f"Error during file scanning: {ex}")

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
        payload_data = self.data[3:]
        stream = io.BytesIO(payload_data)
        if self.compression == CompressionFlag.COMPRESSED:
            try:
                dctx = zstandard.ZstdDecompressor()
                return dctx.stream_reader(stream, read_size=8192)
            except zstandard.ZstdError as ex:
                raise PayloadError(f"Failed to initialize decompression: {str(ex)}")
        return stream

def is_pe_file(file_path):
    """Check if the file at the specified path is a PE file using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
        base_name = Path(file_path).with_suffix(".json")
        json_output_path = get_unique_output_path(output_dir, base_name)
        result = subprocess.run([detectiteasy_console_path, "-j", file_path],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        if "PE32" in result.stdout or "PE64" in result.stdout:
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"PE file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a PE file. Result: {result.stdout}")
            return False
    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} for {file_path}: {ex}")
        return False

def is_elf_file(file_path):
    """Check if the file at the specified path is an ELF file using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
        base_name = Path(file_path).with_suffix(".json")
        json_output_path = get_unique_output_path(output_dir, base_name)
        result = subprocess.run([detectiteasy_console_path, "-j", file_path],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        if "ELF32" in result.stdout or "ELF64" in result.stdout:
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"ELF file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not an ELF file. Result: {result.stdout}")
            return False
    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} for {file_path}: {ex}")
        return False

def is_macho_file(file_path):
    """Check if the file at the specified path is a Mach-O file using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
        base_name = Path(file_path).with_suffix(".json")
        json_output_path = get_unique_output_path(output_dir, base_name)
        result = subprocess.run([detectiteasy_console_path, "-j", file_path],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        if "Mach-O" in result.stdout:
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"Mach-O file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a Mach-O file. Result: {result.stdout}")
            return False
    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} for {file_path}: {ex}")
        return False

class NuitkaExtractor:
    def __init__(self, filepath: str, output_dir: str):
        self.filepath = filepath
        self.output_dir = output_dir
        self.file_type = FileType.UNKNOWN
        self.payload: Optional[NuitkaPayload] = None
    
    def _detect_file_type(self) -> int:
        if is_pe_file(self.filepath):
            return FileType.PE
        elif is_elf_file(self.filepath):
            return FileType.ELF
        elif is_macho_file(self.filepath):
            return FileType.MACHO
        return FileType.UNKNOWN

    def _find_pe_resource(self, pe: pefile.PE) -> Tuple[Optional[int], Optional[int]]:
        try:
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(entry, 'directory'):
                    for entry1 in entry.directory.entries:
                        if entry1.id == 27:
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
        try:
            pe = pefile.PE(self.filepath, fast_load=False)
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                raise PayloadError("No resource directory found")
            offset, size = self._find_pe_resource(pe)
            if offset is None or size is None:
                raise PayloadError("No Nuitka payload found in PE resources")
            with open(self.filepath, 'rb') as f:
                f.seek(offset)
                payload_data = f.read(size)
            return NuitkaPayload(payload_data, offset, size)
        except Exception as ex:
            raise PayloadError(f"PE payload extraction failed: {str(ex)}")

    def _extract_elf_payload(self) -> Optional[NuitkaPayload]:
        try:
            with open(self.filepath, 'rb') as f:
                elf = ELFFile(f)
                last_section = max(elf.iter_sections(),
                                   key=lambda s: s.header.sh_offset + s.header.sh_size)
                f.seek(-8, io.SEEK_END)
                payload_size = struct.unpack('<Q', f.read(8))[0]
                payload_offset = last_section.header.sh_offset + last_section.header.sh_size
                f.seek(payload_offset)
                payload_data = f.read(payload_size)
                return NuitkaPayload(payload_data, payload_offset, payload_size)
        except Exception as ex:
            raise PayloadError(f"ELF payload extraction failed: {str(ex)}")

    def _extract_macho_payload(self) -> Optional[NuitkaPayload]:
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
        total_files = 0
        os.makedirs(self.output_dir, exist_ok=True)
        try:
            while True:
                filename = self._read_string(stream, is_wide=(self.file_type == FileType.PE))
                if not filename:
                    break
                if self.file_type == FileType.ELF:
                    stream.read(1)  # Skip ELF file flags
                size_data = stream.read(8)
                if not size_data or len(size_data) != 8:
                    break
                file_size = struct.unpack('<Q', size_data)[0]
                safe_output_dir = str(self.output_dir).replace('..', '__')
                outpath = os.path.join(safe_output_dir, filename)
                os.makedirs(os.path.dirname(outpath), exist_ok=True)
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
        try:
            self.file_type = self._detect_file_type()
            if self.file_type == FileType.UNKNOWN:
                raise PayloadError("Unsupported file type")
            logging.info(f"[+] Processing: {self.filepath}")
            logging.info(f"[+] Detected file type: {['ELF', 'PE', 'MACHO'][self.file_type]}")
            if self.file_type == FileType.PE:
                self.payload = self._extract_pe_payload()
            elif self.file_type == FileType.ELF:
                self.payload = self._extract_elf_payload()
            else:
                self.payload = self._extract_macho_payload()
            if not self.payload:
                raise PayloadError("Failed to extract payload")
            logging.info(f"[+] Payload size: {self.payload.size} bytes")
            logging.info(f"[+] Compression: {'Yes' if self.payload.compression == CompressionFlag.COMPRESSED else 'No'}")
            stream = self.payload.get_stream()
            total_files = self._extract_files(stream)
            logging.info(f"[+] Successfully extracted {total_files} files to {self.output_dir}")
        except PayloadError as ex:
            logging.error(f"[!] {str(ex)}")
        except Exception as ex:
            logging.error(f"[!] Unexpected error: {str(ex)}")

def extract_nuitka_file(file_path, nuitka_type, mode=None):
    """
    Detect and extract Nuitka executable content.
    For Nuitka OneFile executables, extract the payload and then scan the extracted directory
    for additional executables.
    For normal Nuitka executables, extract RCData and scan the extracted source code.
    The optional mode (train/normal) is passed for signature processing.
    """
    try:
        if nuitka_type == "Nuitka OneFile":
            logging.info(f"Nuitka OneFile executable detected in {file_path}")
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]
            folder_number = 1
            while os.path.exists(os.path.join(nuitka_dir, f"OneFile_{file_name_without_extension}_{folder_number}")):
                folder_number += 1
            nuitka_output_dir = os.path.join(nuitka_dir, f"OneFile_{file_name_without_extension}_{folder_number}")
            os.makedirs(nuitka_output_dir, exist_ok=True)
            logging.info(f"Extracting Nuitka OneFile {file_path} to {nuitka_output_dir}")
            extractor = NuitkaExtractor(file_path, nuitka_output_dir)
            extractor.extract()
            logging.info("Scanning extracted directory for additional Nuitka executables...")
            found_executables = scan_directory_for_executables(nuitka_output_dir)
            for exe_path, exe_type in found_executables:
                if exe_type == "Nuitka":
                    logging.info(f"Found normal Nuitka executable in extracted files: {exe_path}")
                    extract_nuitka_file(exe_path, exe_type, mode)
        elif nuitka_type == "Nuitka":
            logging.info(f"Nuitka executable detected in {file_path}")
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]
            extracted_file = extract_rcdata_resource(file_path)
            if extracted_file:
                logging.info(f"Successfully extracted files from Nuitka executable: {file_path}")
                scan_rsrc_file(extracted_file, mode)
            else:
                logging.error(f"Failed to extract normal Nuitka executable: {file_path}")
        else:
            logging.info(f"No Nuitka content found in {file_path}")
    except PayloadError as ex:
        logging.error(f"Payload error while extracting Nuitka file: {ex}")
    except Exception as ex:
        logging.error(f"Unexpected error while extracting Nuitka file: {ex}")

# --- Unified Signature Functions ---

def calculate_signature(source_code: str) -> str:
    """
    Calculate a signature from the source code by tokenizing the content
    and computing frequency counts for each token.
    Returns a semicolon-separated list of token:count pairs.
    """
    tokens = re.findall(r'\b\w+\b', source_code)
    token_freq = {}
    for token in tokens:
        token = token.lower()
        token_freq[token] = token_freq.get(token, 0) + 1
    sorted_items = sorted(token_freq.items())
    signature = ";".join(f"{k}:{v}" for k, v in sorted_items)
    return signature

def load_unified_signatures(unified_file: str) -> Dict[str, str]:
    """
    Load all signatures from the unified signature file.
    Returns a dictionary mapping signature strings to source file paths.
    The file format is one line per signature in the format:
      <source_filename>::<signature>
    """
    signatures = {}
    if os.path.exists(unified_file):
        with open(unified_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("::", 1)
                if len(parts) == 2:
                    source, sig = parts
                    signatures[sig] = source
    return signatures

def save_unified_signature(unified_file: str, source_filename: str, signature: str):
    """
    Append the signature to the unified signature file.
    The entry format is:
      <source_filename>::<signature>
    """
    with open(unified_file, "a", encoding="utf-8") as f:
        f.write(f"{source_filename}::{signature}\n")
    logging.info(f"Saved signature for {source_filename} to {unified_file}")

def process_source_file(file_path: str, mode: str):
    """
    Process an extracted source file by calculating its signature and then
    either training (saving the signature) or performing a normal scan
    (filtering out duplicates based on existing unified signatures).
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        sig = calculate_signature(content)
        logging.info(f"Calculated signature for {file_path}: {sig}")
        unified_signatures = load_unified_signatures(UNIFIED_SIGNATURE_FILE)
        if mode == "train":
            if sig in unified_signatures:
                logging.info(f"Duplicate signature found for {file_path}. Skipping training.")
            else:
                save_unified_signature(UNIFIED_SIGNATURE_FILE, file_path, sig)
        elif mode == "normal":
            if sig in unified_signatures:
                logging.info(f"Duplicate signature detected for {file_path}. Skipping processing.")
            else:
                save_unified_signature(UNIFIED_SIGNATURE_FILE, file_path, sig)
                logging.info(f"Unique signature for {file_path}. Processing normally.")
        else:
            logging.error(f"Unknown mode '{mode}' specified for processing source file.")
    except Exception as ex:
        logging.error(f"Error processing source file {file_path}: {ex}")

# --- Main Script Logic ---

if __name__ == "__main__":
    input_path = input("Enter the path to the Nuitka executable file or directory: ").strip()
    if not os.path.exists(input_path):
        logging.error(f"The path {input_path} does not exist.")
        sys.exit(1)
    mode = input("Enter mode (train/normal): ").strip().lower()
    # If a directory is provided, iterate through all files recursively
    if os.path.isdir(input_path):
        logging.info(f"Processing directory: {input_path} in {mode} mode.")
        for root, _, files in os.walk(input_path):
            for file in files:
                file_full_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_full_path)
                if nuitka_type:
                    logging.info(f"Processing file: {file_full_path}")
                    extract_nuitka_file(file_full_path, nuitka_type, mode)
        logging.info("Directory processing completed.")
    else:
        nuitka_type = is_nuitka_file(input_path)
        if nuitka_type:
            extract_nuitka_file(input_path, nuitka_type, mode)
        else:
            logging.info("The file is not a Nuitka executable.")
