#!/usr/bin/env python3

"""
From KWallet export data to xml file.
Start this program to read from xml file folder "Chrome Form Data"
For each item extract url, usr and passwor and save them in csv file.
Can recognize several user/password data in same entry.
@sstefanov, 2025
"""
import xml.etree.ElementTree as ET
import base64
import csv
import struct

# Paths
XML_FILE = '/tmp/kwallet.xml'              # Your KWallet XML export
OUTPUT_CSV = '/tmp/chrome_passwords.csv'   # Output CSV for Chrome

# Helper to read length-prefixed field
def read_length_prefixed(blob, offset, encoding='utf-16le'):
    if offset + 4 > len(blob):
        return None, offset
    length = struct.unpack('<I', blob[offset:offset+4])[0]
    offset += 4
    while offset < len(blob) and length==0:
        offset += 4
        if offset + 4 > len(blob):
            return None, offset
        length = struct.unpack('<I', blob[offset:offset+4])[0]
    length = length * len('0'.encode(encoding))  # Adjust length for encoding
    if offset + length > len(blob):
        return None, offset
    data_bytes = blob[offset:offset+length]
    try:
        text = data_bytes.decode(encoding, errors='ignore')
    except Exception:
        text = ''
    offset += length
    while offset < len(blob) and blob[offset] == 0:
        offset += 1  # Skip null terminators
    return text, offset

# Parse XML
tree = ET.parse(XML_FILE)
root = tree.getroot()

# Find folder containing "Chrome Form Data"
folder = None
for f in root.findall('folder'):
    name = f.attrib.get('name', '')
    if "Chrome Form Data" in name:
        folder = f
        break

if folder is None:
    print("Could not find folder containing 'Chrome Form Data'")
    exit(1)

all_entries = []

for stream in folder.findall('stream'):
    data_b64 = stream.text
    if not data_b64:
        continue
    try:
        blob = base64.b64decode(data_b64)
    except Exception as e:
        print(f"Skipping invalid base64 stream: {e}")
        continue

    offset = 0x14  # Skip 24-byte header

    while offset < len(blob):
        # URL (ASCII)
        url1, offset = read_length_prefixed(blob, offset, encoding='utf-8')
        if not url1:
            break
        url2, offset = read_length_prefixed(blob, offset, encoding='utf-8')
        if not url2:
            break

        # Username (UTF-16LE)
        fieldname1, offset = read_length_prefixed(blob, offset, encoding='utf-16le')
        if fieldname1 is None:
            fieldname1 = ''
        username, offset = read_length_prefixed(blob, offset, encoding='utf-16le')
        if username is None:
            username = ''

        # Password (UTF-16LE)
        fieldname2, offset = read_length_prefixed(blob, offset, encoding='utf-16le')
        if fieldname2 is None:
            break
        password, offset = read_length_prefixed(blob, offset, encoding='utf-16le')
        if password is None:
            break
        passlist=["pass", "password"]
        if any(p in fieldname2 for p in passlist):
            all_entries.append((url1, url2, fieldname1, username, fieldname2, password))
        offset += 50  # Skip to next entry
        while offset + 4 <= len(blob) and not blob[offset:offset+4] == b'\x2e\x00\x00\x00':
            offset += 1
        offset += 3
        while offset + 1 <= len(blob) and blob[offset] == 0:
            offset += 1

# Write CSV for Chrome import
with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['name', 'url', 'username', 'password'])
    for idx, (url1, url2, fieldname1, username, fieldname2, password) in enumerate(all_entries, start=1):
        writer.writerow([f'Entry{idx}', url1, username, password])

print(f"Exported {len(all_entries)} entries to {OUTPUT_CSV}")
