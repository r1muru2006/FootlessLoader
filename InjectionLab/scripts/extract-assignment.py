"""Read XLSM XML as data only. Does not run macros or modify the workbook."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("workbook", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
out = {"source_file": args.workbook.name, "sha256": hashlib.sha256(args.workbook.read_bytes()).hexdigest(), "rows": []}
with zipfile.ZipFile(args.workbook) as archive:
    strings = ["".join(x.itertext()) for x in ET.fromstring(archive.read("xl/sharedStrings.xml")).findall("s:si", ns)]
    for filename, sheet_name, wanted_rows in [
        ("xl/worksheets/sheet1.xml", "DEV Track", {12, 13}),
        ("xl/worksheets/sheet3.xml", "DEV Track - Rubric", {3, 4, 5, 6, 7, 10}),
    ]:
        for row in ET.fromstring(archive.read(filename)).findall("s:sheetData/s:row", ns):
            if int(row.attrib["r"]) not in wanted_rows:
                continue
            values = {}
            for cell in row.findall("s:c", ns):
                value = cell.find("s:v", ns)
                text = value.text if value is not None else ""
                if cell.get("t") == "s" and text:
                    text = strings[int(text)]
                values[cell.attrib["r"]] = text
            out["rows"].append({"sheet": sheet_name, "row": int(row.attrib["r"]), "cells": values})
args.output.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
