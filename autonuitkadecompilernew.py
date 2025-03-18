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
import argparse

# ---------------------------
# Setup Logging and Directories
# ---------------------------
script_dir = os.getcwd()

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

sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8', errors='ignore')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8', errors='ignore')
sys.stdin = io.TextIOWrapper(sys.stdin.detach(), encoding='utf-8', errors='ignore')

logging.info("Application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ---------------------------
# Define Directories for Extraction
# ---------------------------
detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_json_dir = os.path.join(script_dir, "detectiteasy_json")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
nuitka_source_code_dir = os.path.join(script_dir, "nuitkasourcecode")
nuitka_dir = os.path.join(script_dir, "nuitka")
general_extracted_dir = os.path.join(script_dir, "general_extracted")

os.makedirs(nuitka_source_code_dir, exist_ok=True)
os.makedirs(nuitka_dir, exist_ok=True)
os.makedirs(general_extracted_dir, exist_ok=True)

# ---------------------------
# Original Helper Functions
# ---------------------------
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
        result = subprocess.run([detectiteasy_console_path, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
    """
    found_executables = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.exe'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.dll'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if not file.lower().endswith(('.exe', '.dll')):
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables
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

def scan_rsrc_file(file_path):
    """
    Original function that scans the provided file for 'upython.exe' marker and extracts source code.
    It writes the extracted source to a uniquely named file in nuitka_source_code_dir.
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
                            save_path = os.path.join(
                                nuitka_source_code_dir, f"{base_name}_source_code_{counter}.txt"
                            )
                            counter += 1
                        with open(save_path, "w", encoding="utf-8") as save_file:
                            for line in cleaned_source_code:
                                save_file.write(line + "\n")
                        logging.info(f"Saved extracted source code from {file_path} to {save_path}")
                        extracted_source_code = ''.join(source_code_lines)
                        scan_code_for_links(extracted_source_code)
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

# ---------------------------
# Classes and Extraction Logic for Nuitka Payloads
# ---------------------------
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
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
        base_name = Path(file_path).with_suffix(".json")
        json_output_path = get_unique_output_path(output_dir, base_name)
        result = subprocess.run([detectiteasy_console_path, "-j", file_path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
        base_name = Path(file_path).with_suffix(".json")
        json_output_path = get_unique_output_path(output_dir, base_name)
        result = subprocess.run([detectiteasy_console_path, "-j", file_path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
        base_name = Path(file_path).with_suffix(".json")
        json_output_path = get_unique_output_path(output_dir, base_name)
        result = subprocess.run([detectiteasy_console_path, "-j", file_path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
                last_section = max(elf.iter_sections(), key=lambda s: s.header.sh_offset + s.header.sh_size)
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
                    stream.read(1)
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

def extract_nuitka_file(file_path, nuitka_type):
    """
    Detect Nuitka type, extract Nuitka executable content, and scan for additional Nuitka executables.
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
            logging.info(f"Scanning extracted directory for additional Nuitka executables...")
            found_executables = scan_directory_for_executables(nuitka_output_dir)
            for exe_path, exe_type in found_executables:
                if exe_type == "Nuitka":
                    logging.info(f"Found normal Nuitka executable in extracted files: {exe_path}")
                    extract_nuitka_file(exe_path, exe_type)
        elif nuitka_type == "Nuitka":
            logging.info(f"Nuitka executable detected in {file_path}")
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]
            extracted_file = extract_rcdata_resource(file_path)
            if extracted_file:
                logging.info(f"Successfully extracted files from Nuitka executable: {file_path}")
                scan_rsrc_file(extracted_file)
            else:
                logging.error(f"Failed to extract normal Nuitka executable: {file_path}")
        else:
            logging.info(f"No Nuitka content found in {file_path}")
    except PayloadError as ex:
        logging.error(f"Payload error while extracting Nuitka file: {ex}")
    except Exception as ex:
        logging.error(f"Unexpected error while extracting Nuitka file: {ex}")

# ---------------------------
# New Functions for Training/Folder Mode
# ---------------------------
def scan_rsrc_file_return(file_path):
    """
    Modified version of scan_rsrc_file that returns the extracted source code as a string.
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
                        extracted_source_code = "\n".join(cleaned_source_code)
                        scan_code_for_links(extracted_source_code)
                        return extracted_source_code
                    else:
                        logging.info(f"No line containing 'upython.exe' found in {file_path}.")
                        return ""
                else:
                    logging.info(f"File {file_path} is empty.")
                    return ""
            except Exception as ex:
                logging.error(f"Error reading file {file_path}: {ex}")
                return ""
        else:
            logging.warning(f"Path {file_path} is not a valid file.")
            return ""
    except Exception as ex:
        logging.error(f"Error during file scanning: {ex}")
        return ""

def extract_normal_source(file_path):
    """
    Read the file content as normal source code (for non-Nuitka files).
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as ex:
        logging.error(f"Error reading normal source from {file_path}: {ex}")
        return ""

def ml_filter(source_codes):
    """
    Placeholder ML filtering that deduplicates lines across all source code strings.
    """
    unique_lines = set()
    filtered = []
    for code in source_codes:
        for line in code.splitlines():
            stripped = line.strip()
            if stripped and stripped not in unique_lines:
                unique_lines.add(stripped)
                filtered.append(stripped)
    return "\n".join(filtered)

def train_mode(directory):
    """
    Traverse the given directory recursively, extract source code from each file (using Nuitka extraction
    for Nuitka executables or normal text reading for others), and merge all unique signatures into signatures.txt.
    """
    all_signatures = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            nuitka_type = is_nuitka_file(file_path)
            if nuitka_type:
                logging.info(f"Detected Nuitka file: {file_path}")
                # Use the modified scan_rsrc_file_return to get extracted code
                source_code = scan_rsrc_file_return(file_path)
                if source_code:
                    all_signatures.append(source_code)
            else:
                # Try to read normal source code
                content = extract_normal_source(file_path)
                if content.strip():
                    all_signatures.append(content)
    if not all_signatures:
        logging.info("No source code extracted from the provided directory.")
        return
    signatures = ml_filter(all_signatures)
    output_file = os.path.join(directory, "signatures.txt")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(signatures)
        print(f"Signatures extracted and saved to {output_file}")
    except Exception as e:
        logging.error(f"Error writing to {output_file}: {e}")

# ---------------------------
# Main Entry Point
# ---------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract source code from Nuitka executables or normal files. "
                    "Provide a file path for single file extraction or a directory for training mode to merge signatures."
    )
    parser.add_argument("path", help="Path to a file or directory")
    args = parser.parse_args()
    target_path = args.path

    if os.path.isdir(target_path):
        print(f"Scanning directory: {target_path}")
        train_mode(target_path)
    elif os.path.isfile(target_path):
        if os.path.exists(target_path):
            nuitka_type = is_nuitka_file(target_path)
            if nuitka_type:
                extract_nuitka_file(target_path, nuitka_type)
            else:
                print("The file is not a Nuitka executable. Attempting normal source extraction.")
                content = extract_normal_source(target_path)
                if content.strip():
                    output_file = os.path.join(os.path.dirname(target_path), "signatures.txt")
                    try:
                        with open(output_file, "w", encoding="utf-8") as f:
                            f.write(content)
                        print(f"Extracted source saved to {output_file}")
                    except Exception as e:
                        logging.error(f"Error writing to {output_file}: {e}")
                else:
                    print("No source code could be extracted.")
        else:
            logging.error(f"The file {target_path} does not exist.")
    else:
        logging.error(f"The path {target_path} does not exist.")
