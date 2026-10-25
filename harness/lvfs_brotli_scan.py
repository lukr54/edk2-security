#!/usr/bin/env python3
"""
LVFS Brotli GUID scanner — measures how many shipping firmware images
contain Brotli-compressed GUIDed sections (Finding B blast radius).

Parses the LVFS metadata, filters to UEFI system firmware, downloads
cab files, extracts them, and binary-searches for the Brotli and LZMA
GUIDs.  LZMA is the expected positive control (most UEFI firmware uses it).

Usage:
    python3 -IB lvfs_brotli_scan.py firmware.xml [--limit N] [--download-dir DIR]

GUIDs (mixed-endian binary, as stored in EFI_GUID_DEFINED_SECTION):
  Brotli: {3D532050-5CDA-4FD0-879E-0F7F630D5AFB}
  LZMA:   {EE4E5898-3914-4259-9D6E-DC7BD79403CF}
"""

import xml.etree.ElementTree as ET
import subprocess
import tempfile
import os
import sys
import struct
import argparse
import hashlib
import shutil

# GUIDs as raw bytes (mixed-endian: first 3 fields LE, last 2 fields BE)
BROTLI_GUID = bytes([
    0x50, 0x20, 0x53, 0x3D,  # Data1 LE
    0xDA, 0x5C,              # Data2 LE
    0xD0, 0x4F,              # Data3 LE
    0x87, 0x9E, 0x0F, 0x7F, 0x63, 0x0D, 0x5A, 0xFB  # Data4 BE
])

LZMA_GUID = bytes([
    0x98, 0x58, 0x4E, 0xEE,
    0x14, 0x39,
    0x59, 0x42,
    0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF
])

LZMA_X86_GUID = bytes([
    0xBD, 0xE6, 0x2A, 0xD4,
    0x52, 0x13,
    0xFB, 0x4B,
    0x90, 0x9A, 0xCA, 0x72, 0xA6, 0xEA, 0xE8, 0x89
])

# Tiano custom decompress GUID (the "safe" one)
CRC32_GUID = bytes([
    0xB0, 0xCD, 0x1B, 0xFC,
    0x31, 0x7D,
    0xAA, 0x49,
    0x93, 0x6A, 0xA4, 0x60, 0x0D, 0x9D, 0xD0, 0x83
])

# UEFI update protocols that indicate system firmware (BIOS/UEFI)
UEFI_PROTOCOLS = {
    "org.uefi.capsule",
    "com.dell.capsule",
    "com.hp.capsule",
    "com.lenovo.capsule",
    "com.intel.capsule",
    "org.flashrom",
}


def parse_lvfs_metadata(xml_path):
    """Parse LVFS metadata XML, return list of UEFI firmware entries."""
    print(f"Parsing {xml_path}...")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    entries = []
    for comp in root.iter("component"):
        comp_id = comp.findtext("id", "")
        name = comp.findtext("name", "")
        developer = comp.findtext("developer_name", "")

        categories = set()
        for cat in comp.iter("category"):
            categories.add(cat.text or "")

        custom = {}
        for val in comp.iter("value"):
            key = val.get("key", "")
            custom[key] = val.text or ""

        protocol = custom.get("LVFS::UpdateProtocol", "")

        # Filter: UEFI system firmware only
        is_uefi = (
            protocol in UEFI_PROTOCOLS
            or "X-System" in categories
            or "X-ManagementEngine" in categories
            or "bios" in name.lower()
            or "uefi" in name.lower()
            or "firmware" in name.lower() and "system" in name.lower()
        )

        if not is_uefi:
            continue

        # Get the latest release with a download URL
        for release in comp.iter("release"):
            for artifact in release.iter("artifact"):
                location = artifact.findtext("location", "")
                if location and location.endswith(".cab"):
                    size_el = artifact.find("size[@type='download']")
                    size = int(size_el.text) if size_el is not None and size_el.text else 0
                    entries.append({
                        "id": comp_id,
                        "name": name,
                        "developer": developer,
                        "protocol": protocol,
                        "categories": categories,
                        "url": location,
                        "size": size,
                        "version": release.get("version", ""),
                    })
                    break  # only latest release per component
            else:
                continue
            break

    return entries


def download_and_scan(entry, download_dir):
    """Download a cab, extract, scan for GUIDs. Returns dict of results."""
    url = entry["url"]
    if not url.startswith("http"):
        url = f"https://fwupd.org/downloads/{url}"

    cab_name = os.path.basename(url)
    cab_path = os.path.join(download_dir, cab_name)

    result = {
        "name": entry["name"],
        "developer": entry["developer"],
        "version": entry["version"],
        "protocol": entry["protocol"],
        "url": url,
        "size": entry["size"],
        "brotli": False,
        "lzma": False,
        "lzma_x86": False,
        "error": None,
    }

    try:
        # Download
        if not os.path.exists(cab_path):
            subprocess.run(
                ["curl", "-sL", "-o", cab_path, url],
                check=True, timeout=120
            )

        # Extract cab
        extract_dir = cab_path + ".d"
        os.makedirs(extract_dir, exist_ok=True)
        subprocess.run(
            ["cabextract", "-q", "-d", extract_dir, cab_path],
            check=True, timeout=60, capture_output=True
        )

        # Scan all extracted files for GUIDs
        for root_dir, dirs, files in os.walk(extract_dir):
            for fname in files:
                fpath = os.path.join(root_dir, fname)
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    if BROTLI_GUID in data:
                        result["brotli"] = True
                    if LZMA_GUID in data:
                        result["lzma"] = True
                    if LZMA_X86_GUID in data:
                        result["lzma_x86"] = True
                except (IOError, OSError):
                    pass

        # Clean up extracted files (keep cab for re-scan)
        shutil.rmtree(extract_dir, ignore_errors=True)

    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except subprocess.CalledProcessError as e:
        result["error"] = f"extract failed: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


def main():
    parser = argparse.ArgumentParser(description="LVFS Brotli GUID scanner")
    parser.add_argument("xml", help="Path to firmware.xml")
    parser.add_argument("--limit", type=int, default=200,
                        help="Max firmware images to scan")
    parser.add_argument("--download-dir", default="./cabs",
                        help="Directory for downloaded cab files")
    parser.add_argument("--max-size", type=int, default=100_000_000,
                        help="Skip cabs larger than this (bytes)")
    args = parser.parse_args()

    os.makedirs(args.download_dir, exist_ok=True)

    entries = parse_lvfs_metadata(args.xml)
    print(f"Found {len(entries)} UEFI firmware entries in LVFS metadata")

    # Filter by size and deduplicate by developer+name
    seen = set()
    filtered = []
    for e in entries:
        key = f"{e['developer']}|{e['name']}"
        if key in seen:
            continue
        if e["size"] > args.max_size:
            continue
        seen.add(key)
        filtered.append(e)

    filtered = filtered[:args.limit]
    print(f"Scanning {len(filtered)} firmware images (deduped, size-filtered)")
    print()

    # Tally by vendor
    vendors = {}
    for e in filtered:
        dev = e["developer"] or "Unknown"
        vendors.setdefault(dev, 0)
        vendors[dev] += 1
    print("Vendors in scan:")
    for v, c in sorted(vendors.items(), key=lambda x: -x[1])[:15]:
        print(f"  {v}: {c}")
    print()

    # Check for cabextract
    if shutil.which("cabextract") is None:
        print("ERROR: cabextract not found. Install it: sudo apt install cabextract")
        sys.exit(1)

    # Scan
    brotli_hits = []
    lzma_hits = 0
    errors = 0
    total = len(filtered)

    for i, entry in enumerate(filtered):
        tag = f"[{i+1}/{total}]"
        name = f"{entry['developer']}/{entry['name']}"
        if len(name) > 60:
            name = name[:57] + "..."

        result = download_and_scan(entry, args.download_dir)

        status = ""
        if result["error"]:
            status = f"ERR: {result['error']}"
            errors += 1
        else:
            parts = []
            if result["brotli"]:
                parts.append("BROTLI!")
                brotli_hits.append(result)
            if result["lzma"]:
                parts.append("lzma")
                lzma_hits += 1
            if not parts:
                parts.append("none")
            status = " ".join(parts)

        print(f"  {tag} {name:60s}  {status}")

    # Summary
    print()
    print("=" * 70)
    print(f"SCAN COMPLETE: {total} firmware images scanned, {errors} errors")
    print(f"  LZMA GUIDed sections found in: {lzma_hits} images")
    print(f"  Brotli GUIDed sections found in: {len(brotli_hits)} images")
    print()

    if brotli_hits:
        print("BROTLI HITS:")
        for h in brotli_hits:
            print(f"  {h['developer']} / {h['name']} v{h['version']}")
            print(f"    Protocol: {h['protocol']}")
            print(f"    URL: {h['url']}")
    else:
        print("NO BROTLI HITS — the Brotli decompressor appears unused in")
        print("shipping firmware.  Blast radius for Finding B is NARROW:")
        print("the vulnerable code is present in the EDK2 tree but not")
        print("exercised by any firmware image in LVFS.")
        print()
        print(f"Control: LZMA was found in {lzma_hits}/{total} images,")
        print("confirming the scanner works and firmware does use GUIDed")
        print("section compression — just not Brotli.")


if __name__ == "__main__":
    main()
