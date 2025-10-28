import os
import logging
from datetime import datetime
import pefile
import zstandard
from typing import Optional, Tuple, List, Dict, Any
import shutil
import io
import struct

# Set script directory
script_dir = os.getcwd()

# Define log directories and files
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

application_log_file = os.path.join(log_directory, "antivirus.log")

# Configure logging
logging.basicConfig(
    filename=application_log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

logging.info("Application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

patched_dir = os.path.join(script_dir, "patched_files")
extracted_dir = os.path.join(script_dir, "extracted_nuitka")

# Ensure output directories exist
os.makedirs(patched_dir, exist_ok=True)
os.makedirs(extracted_dir, exist_ok=True)

# ----------------------------
# STRING REPLACEMENT CONFIG
OLD_STRING_BASE = "https://keyauth.win/"
NEW_STRING_BASE = "http://keyauth.win2/"

REPLACEMENTS = [
    (OLD_STRING_BASE.encode('ascii'), NEW_STRING_BASE.encode('ascii')),  # ASCII/UTF-8
    (OLD_STRING_BASE.encode('utf-16-le'), NEW_STRING_BASE.encode('utf-16-le'))  # WIDE STRING
]

# Verify strings are same length
for old, new in REPLACEMENTS:
    assert len(old) == len(new), "Old and new strings must be the same length!"
# ----------------------------

def replace_bytes_in_data(data: bytes, old_bytes: bytes, new_bytes: bytes) -> tuple:
    """Replace all occurrences of old_bytes with new_bytes. Returns (modified_data, count)"""
    if len(old_bytes) != len(new_bytes):
        raise ValueError("old_bytes and new_bytes must have the same length")
    
    count = 0
    result = bytearray(data)
    search_pos = 0
    
    while True:
        pos = result.find(old_bytes, search_pos)
        if pos == -1:
            break
        result[pos:pos + len(new_bytes)] = new_bytes
        count += 1
        search_pos = pos + len(new_bytes)
        logging.info(f"Replaced occurrence of {old_bytes} at offset {pos}")
    
    return bytes(result), count

# --- Utility and Detection Functions ---

def is_nuitka_file(file_path):
    """Check if the file is a Nuitka executable (Focus on ID 27)"""
    try:
        pe = pefile.PE(file_path, fast_load=False)
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'): return None
        
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(entry, 'directory'):
                for entry1 in entry.directory.entries:
                    if entry1.id == 27:
                        if hasattr(entry1, 'directory'):
                            data_entry = entry1.directory.entries[0]
                            if hasattr(data_entry, 'data'):
                                offset = pe.get_offset_from_rva(data_entry.data.struct.OffsetToData)
                                with open(file_path, 'rb') as f:
                                    f.seek(offset)
                                    if f.read(2) == b'KA':
                                        logging.info(f"File {file_path} is a Nuitka OneFile (ID 27).")
                                        return "Nuitka OneFile"
        return None
    except Exception as ex:
        logging.error(f"Error detecting Nuitka file: {ex}")
        return None

# -------------------------------------------------------------------------
# CORE LOGIC REVISION: ZSTD DECOMPRESSION FORGIVENESS
# -------------------------------------------------------------------------

class PayloadError(Exception): pass

class NuitkaHeuristicPatcher:
    ZSTD_MAGIC = b'\x28\xB5\x2F\xFD'
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.pe_offset: Optional[int] = None
        self.pe_size: Optional[int] = None
        self.payload_data: Optional[bytes] = None
        self.compressed_block: Optional[bytes] = None
        self.zstd_offset_in_payload: Optional[int] = None
    
    def _find_pe_resource(self, pe: pefile.PE) -> Tuple[Optional[int], Optional[int]]:
        """Find the Nuitka OneFile resource in PE file (ID 27)"""
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
                                    self.pe_offset = offset
                                    self.pe_size = size
                                    return offset, size
        except Exception as ex: pass
        return None, None
    
    def _extract_payload(self) -> bool:
        """Extracts the raw Resource ID 27 data block."""
        try:
            pe = pefile.PE(self.filepath, fast_load=False)
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'): raise PayloadError("No resource directory found")
            offset, size = self._find_pe_resource(pe)
            if offset is None or size is None: raise PayloadError("No Nuitka OneFile payload found (Resource ID 27)")
            
            with open(self.filepath, 'rb') as f:
                f.seek(offset)
                self.payload_data = f.read(size)
            
            logging.info(f"Successfully extracted raw Nuitka payload (ID 27), size: {size} bytes.")
            return True
        except Exception as ex: 
            logging.error(f"Payload extraction failed: {str(ex)}")
            return False

    def _find_zstd_block(self) -> bool:
        """Heuristically finds the primary Zstandard data block."""
        if not self.payload_data: return False
        
        # We start searching after the Nuitka header ('KA' + type byte)
        search_start = 3 
        
        # Find the first occurrence of the Zstandard magic bytes
        zstd_offset = self.payload_data.find(self.ZSTD_MAGIC, search_start)
        
        if zstd_offset == -1:
            logging.error("CRITICAL: Failed to find Zstandard magic signature ('\\x28\\xB5\\x2F\\xFD') in the payload.")
            return False
        
        self.zstd_offset_in_payload = zstd_offset
        logging.info(f"Found Zstandard magic at raw payload offset: {zstd_offset}")
        
        # The compressed block starts here and runs to the end of the resource data.
        self.compressed_block = self.payload_data[zstd_offset:]
        logging.info(f"Compressed block size: {len(self.compressed_block)} bytes.")
        return True

    def patch_and_save_heuristic(self, output_path: str) -> int:
        """Decompresses the ZSTD block, patches, re-compresses, and saves."""
        if not self._extract_payload(): return 0
        if not self._find_zstd_block(): return 0
        
        total_replacements = 0
        decompressed_data = None
        
        try:
            # 1. DECOMPRESS (using ZstdDecompressor().decompressobj() for stream processing forgiveness)
            # This is the critical change to bypass the "could not determine content size in frame header" error.
            decompressor = zstandard.ZstdDecompressor()
            dobj = decompressor.decompressobj()
            decompressed_data = dobj.decompress(self.compressed_block)
            
            # Finalize decompression to flush any remaining data
            decompressed_data += dobj.flush()
            
            logging.info(f"Decompressed successfully using stream mode. Unpacked size: {len(decompressed_data) / 1024 / 1024:.2f} MB.")
            
            # --- DIAGNOSTIC STEP: Save for inspection ---
            exe_name = os.path.basename(self.filepath)
            diag_path = os.path.join(extracted_dir, f"{os.path.splitext(exe_name)[0]}_full_payload.bin")
            with open(diag_path, 'wb') as f:
                 f.write(decompressed_data)
            logging.info(f"DIAGNOSTIC: Full decompressed payload saved to {diag_path} for size verification.")
            # -------------------------------------------
            
            # 2. PATCH STRINGS
            patched_decompressed = decompressed_data
            for old_bytes, new_bytes in REPLACEMENTS:
                patched_decompressed, count = replace_bytes_in_data(patched_decompressed, old_bytes, new_bytes)
                total_replacements += count
            
            if total_replacements == 0:
                logging.error("✗ FAILURE: String not found even in the full decompressed payload.")
                return 0
                
            logging.info(f"*** SUCCESS: Patched {total_replacements} occurrences in the full payload! ***")

            # 3. RE-COMPRESS
            recompressed_block = zstandard.ZstdCompressor().compress(patched_decompressed)
            logging.info(f"Recompressed successfully. New size: {len(recompressed_block)} bytes.")

            # 4. REBUILD PAYLOAD DATA
            # The payload is (Header + Zstd Compressed Block)
            new_payload_data = bytearray(self.payload_data[:self.zstd_offset_in_payload])
            new_payload_data.extend(recompressed_block)
            
            # Pad with null bytes if the new block is smaller than the original resource size
            new_size = len(new_payload_data)
            if new_size < self.pe_size:
                 new_payload_data.extend(b'\x00' * (self.pe_size - new_size))
            elif new_size > self.pe_size:
                 logging.warning("New payload is LARGER than original resource size. Truncating to original size to avoid PE corruption.")
                 new_payload_data = new_payload_data[:self.pe_size] 
            
            # 5. WRITE BACK TO PE FILE
            if not os.path.exists(output_path): shutil.copy2(self.filepath, output_path)
            
            with open(output_path, 'r+b') as f:
                f.seek(self.pe_offset)
                f.write(new_payload_data)
            
            return total_replacements
            
        except Exception as ex:
            logging.error(f"Unexpected error during Heuristic patching: {ex}")
            return 0


# -------------------------------------------------------------------------
# FALLBACK: Explicit RCData 10_3_0 Check (KEPT for completeness)
# -------------------------------------------------------------------------

def patch_rcdata_resource_10_3_0(pe_path: str, output_path: str) -> int:
    """Strictly checks and patches RCData resource (ID 10, Name 3, Lang 0)."""
    global REPLACEMENTS
    total_replacements = 0
    
    try:
        if not os.path.exists(output_path): shutil.copy2(pe_path, output_path)
        pe = pefile.PE(output_path) 
    except Exception as e:
        logging.error(f"Error loading PE file for RCData check: {e}")
        return 0

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        logging.info("No resources found for RCData 10_3_0 check.")
        return 0

    # Target: Type 10 (RCData), ID 3, Lang 0
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_id = resource_type.id if hasattr(resource_type, 'id') else None
        if type_id != 10 or not hasattr(resource_type, 'directory'): continue

        for resource_id in resource_type.directory.entries:
            res_id = resource_id.id if hasattr(resource_id, 'id') else None
            if res_id != 3 or not hasattr(resource_id, 'directory'): continue

            for resource_lang in resource_id.directory.entries:
                if resource_lang.id != 0: continue
                
                data_rva = resource_lang.data.struct.OffsetToData
                offset = pe.get_offset_from_rva(data_rva)
                size = resource_lang.data.struct.Size
                
                logging.info(f"Found RCData resource 10_3_0 at offset {offset}, size {size}")
                
                with open(output_path, 'r+b') as f:
                    f.seek(offset)
                    data = f.read(size)
                
                modified_data = data
                for old_bytes, new_bytes in REPLACEMENTS:
                    new_modified_data, count = replace_bytes_in_data(modified_data, old_bytes, new_bytes)
                    modified_data = new_modified_data
                    total_replacements += count
                
                if total_replacements > 0:
                    logging.info(f"Patched {total_replacements} occurrences in RCData resource (10_3_0).")
                    
                    with open(output_path, 'r+b') as f:
                        f.seek(offset)
                        f.write(modified_data)
                    return total_replacements
            
    logging.info("RCData resource 10_3_0 not found or string not found in it.")
    return 0

# -------------------------------------------------------------------------

def process_nuitka_file(file_path: str, nuitka_type: str):
    """Process and patch Nuitka PE file with Zstd heuristic logic."""
    try:
        base_name = os.path.basename(file_path)
        name_without_ext = os.path.splitext(base_name)[0]
        output_filename = f"{name_without_ext}_patched.exe"
        output_path = os.path.join(patched_dir, output_filename)
        
        counter = 1
        while os.path.exists(output_path):
            output_filename = f"{name_without_ext}_patched_{counter}.exe"
            output_path = os.path.join(patched_dir, output_filename)
            counter += 1
        
        total_replacements = 0

        if nuitka_type == "Nuitka OneFile":
            print("🚀 Running Heuristic (Zstd Stream) Extraction...")
            logging.info(f"Starting HEURISTIC ZSTD patch for: {file_path}")
            
            # 1. PRIMARY: Heuristic Patch (Bypassing Archive Metadata)
            patcher = NuitkaHeuristicPatcher(file_path)
            total_replacements = patcher.patch_and_save_heuristic(output_path)
            
            if total_replacements > 0:
                print(f"✅ Patched ({total_replacements} total occurrences, Zstd Heuristic Success): {output_filename}")
                return
            
            # 2. FALLBACK: Explicit RCData 10_3_0 check
            logging.warning("ZSTD heuristic failed or found no strings. Proceeding to RCData 10_3_0 check...")
            
            # Ensure the output file exists for patching the remaining resources
            if not os.path.exists(output_path):
                shutil.copy2(file_path, output_path)

            rcdata_replacements = patch_rcdata_resource_10_3_0(file_path, output_path)
            
            if rcdata_replacements > 0:
                print(f"✅ Patched ({rcdata_replacements} occurrences in FALLBACK RCData 10_3_0): {output_filename}")
            else:
                logging.error(f"❌ Failed to patch: {file_path}. String not found in any location.")
                print(f"❌ Failed: {base_name}")
        
        else:
            logging.error(f"File {file_path} is not recognized as the target Nuitka OneFile format (ID 27). Skipping.")
            print(f"❌ Failed: {base_name} (Not Nuitka OneFile)")

    except Exception as ex:
        logging.error(f"Error processing {file_path}: {ex}")
        print(f"❌ Error: {base_name}")


# Main script
if __name__ == "__main__":
    print("=" * 60)
    print("Nuitka PE String Patcher (V14 - Zstd Stream Decompression Fix)")
    print(f"Replacing: {OLD_STRING_BASE} -> {NEW_STRING_BASE}")
    print("=" * 60)
    
    file_path = input("\nEnter the path to the Nuitka PE file or directory: ").strip()

    if os.path.exists(file_path):
        if os.path.isdir(file_path):
            print(f"\nScanning directory: {file_path}\n")
            found_count = 0
            for root, _, files in os.walk(file_path):
                for file in files:
                    if not file.lower().endswith('.exe'):
                        continue
                    full_path = os.path.join(root, file)
                    nuitka_type = is_nuitka_file(full_path)
                    if nuitka_type:
                        found_count += 1
                        print(f"\nFound: {file} ({nuitka_type})")
                        process_nuitka_file(full_path, nuitka_type)
            
            if found_count == 0:
                print("No recognized Nuitka OneFile executables found in directory.")
        
        elif os.path.isfile(file_path):
            print(f"\nAnalyzing: {os.path.basename(file_path)}\n")
            nuitka_type = is_nuitka_file(file_path)
            
            if nuitka_type == "Nuitka OneFile":
                process_nuitka_file(file_path, nuitka_type)
            else:
                logging.error(f"File {file_path} is not recognized as the target Nuitka OneFile format (ID 27). Aborting.")
                print("The file is not the specific Nuitka OneFile format required. Aborting.")

    else:
        logging.error(f"The path {file_path} does not exist.")
        print(f"Error: Path does not exist: {file_path}")
    
    print("\n" + "=" * 60)
    print(f"✅ Processing complete! **Check the '{extracted_dir}' folder for the full payload!**")
    print(f"✅ Patched files saved to: {patched_dir}")
    print(f"✅ Logs saved to: {application_log_file}")
    print("=" * 60)