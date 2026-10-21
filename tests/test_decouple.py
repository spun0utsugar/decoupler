#!/usr/bin/env python3
"""
Deterministic Synthetic Archive Generator & End-to-End Test Suite
=================================================================
Generates realistic multi-section binary archives to validate `decouple`:
  1. `samples/legacy_cad_gis_archive.oadc`:
     - Header + Validated Section Pointer Directory
     - Section 1: 2D Affine Transform + EPSG:3857 Coordinate System Hint
     - Section 2A: `parcel_polygons` layer (closed Polygon rings)
     - Section 2B: `road_centerlines` layer (LineString polylines)
     - Section 2C: `contour_splines` layer (CubicBezier control polygons)
     - Section 3: Fixed-stride 24-byte repeating attribute records (`record_id`, `measurement`, `label`)
     - Section 4: Regular 6x6 elevation grid lattice (`RegularGrid`)
     - Section 5: Uncompressed 16x16 RGB8 geo-referenced raster tile
     - Section 6: Truly opaque/encrypted payload block (entropy > 7.5, not matching any compression codec)
  2. `samples/municipal_parcels.shp`:
     - Standards-compliant Esri Shapefile main binary header (`0x0000270A`) + Polygon records in WGS84 Lon/Lat
  3. `samples/raw_telemetry_dump.bin`:
     - Unknown magic header containing raw length-prefixed IEEE-754 float64 coordinate sequences,
       monotonic u32 pointer tables, and repeating stride records in unindexed space.
  4. `samples/compressed_nested_archive.bin`:
     - Host binary containing:
       * Root-level uncompressed polyline (`stream_lineage == "root"`)
       * Depth-1 `zlib` (0x78 0x9C) compressed coordinate polygon + nested Depth-2 `gzip` (0x1F 0x8B)
         compressed repeating attribute table (`parent_offset:0x.../decompressed_0/parent_offset:0x.../decompressed_0`)
       * High-entropy (> 7.5 bits/byte) headerless `raw Deflate` stream preceded by a 4-byte length integer
       * Corrupted `zlib` header (`0x78 0x9C` + bad checksum) to verify non-blocking graceful fallback
       * Decompression bomb (`> 200:1` zero-run stream) to verify bomb protection aborts safely
"""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import decouple


def build_oadc_sample(path: Path) -> bytes:
    sections: list[tuple[int, bytes, int]] = []

    # Section 1: Affine Transform [1.0, 0.0, 0.0, 1.0, 500000.0, 4000000.0] + EPSG:3857
    sec_crs = struct.pack("<6dI", 1.0, 0.0, 0.0, 1.0, 500000.0, 4000000.0, 3857)
    sections.append((1, sec_crs, 0))

    # Section 2A: Polygon layer ("parcel_polygons", geom_kind=3, 2 polygons)
    poly1 = [
        (120.0, 140.0),
        (260.0, 140.0),
        (280.0, 260.0),
        (140.0, 280.0),
        (120.0, 140.0),
    ]
    poly2 = [
        (320.0, 160.0),
        (480.0, 160.0),
        (480.0, 310.0),
        (320.0, 310.0),
        (320.0, 160.0),
    ]
    buf_poly = bytearray()
    buf_poly += b"parcel_polygons\x00"
    buf_poly += struct.pack("<HHI", 3, 2, 0)
    for fid, ring in ((101, poly1), (102, poly2)):
        buf_poly += struct.pack("<II", fid, len(ring))
        for x, y in ring:
            buf_poly += struct.pack("<dd", x, y)
    sections.append((2, bytes(buf_poly), 0))

    # Section 2B: LineString layer ("road_centerlines", geom_kind=2, 2 polylines)
    line1 = [(80.0, 90.0), (210.0, 115.0), (350.0, 120.0), (520.0, 150.0)]
    line2 = [(295.0, 80.0), (300.0, 200.0), (305.0, 340.0), (310.0, 420.0)]
    buf_line = bytearray()
    buf_line += b"road_centerlines"
    buf_line += struct.pack("<HHI", 2, 2, 0)
    for fid, ln in ((201, line1), (202, line2)):
        buf_line += struct.pack("<II", fid, len(ln))
        for x, y in ln:
            buf_line += struct.pack("<dd", x, y)
    sections.append((2, bytes(buf_line), 0))

    # Section 2C: CubicBezier layer ("contour_splines", geom_kind=4, 1 curve with 4 control points)
    bez = [(100.0, 360.0), (220.0, 440.0), (380.0, 280.0), (500.0, 390.0)]
    buf_bez = bytearray()
    buf_bez += b"contour_splines\x00"
    buf_bez += struct.pack("<HHI", 4, 1, 0)
    buf_bez += struct.pack("<II", 301, len(bez))
    for x, y in bez:
        buf_bez += struct.pack("<dd", x, y)
    sections.append((2, bytes(buf_bez), 0))

    # Section 3: Fixed-stride 24-byte attribute table (5 records)
    attr_rows = [
        (101, 142.75, "PARCEL_NORTH_A"),
        (102, 198.50, "PARCEL_EAST_B"),
        (201, 12.40, "ARTERIAL_RD_1"),
        (202, 9.80, "COLLECTOR_RD_2"),
        (301, 315.00, "RIDGE_CONTOUR"),
    ]
    buf_attr = bytearray()
    for rid, val, label in attr_rows:
        lbl_bytes = label.encode("ascii")[:16].ljust(16, b"\x00")
        buf_attr += struct.pack("<If", rid, val) + lbl_bytes
    sections.append((3, bytes(buf_attr), 0))

    # Section 4: RegularGrid (6x6 elevation lattice)
    cols, rows_cnt = 6, 6
    buf_grid = bytearray()
    buf_grid += struct.pack("<ddddII", 100.0, 100.0, 80.0, 60.0, cols, rows_cnt)
    for r in range(rows_cnt):
        for c in range(cols):
            elev = 250.0 + 12.5 * r + 8.25 * c
            buf_grid += struct.pack("<f", elev)
    sections.append((4, bytes(buf_grid), 0))

    # Section 5: Uncompressed 16x16 RGB8 Raster Tile
    w, h, ch = 16, 16, 3
    buf_ras = bytearray()
    buf_ras += struct.pack("<IIBBBBI", w, h, ch, 8, 0, 0, 0)
    buf_ras += struct.pack("<dddd", 100.0, 100.0, 500.0, 420.0)
    for y in range(h):
        for x in range(w):
            buf_ras += bytes(((x * 16) % 256, (y * 16) % 256, ((x + y) * 8) % 256))
    sections.append((5, bytes(buf_ras), 0))

    # Section 6: Truly opaque/encrypted block (256 deterministic bytes covering all 256 byte values)
    opaque_payload = bytearray(256)
    for i in range(256):
        opaque_payload[i] = (i * 167 + 13) & 0xFF
    sections.append((99, bytes(opaque_payload), 0xDEAD))

    dir_offset = 16
    dir_size = len(sections) * 16
    current_offset = dir_offset + dir_size

    header = b"OADC" + struct.pack("<HHII", 1, len(sections), dir_offset, 0)
    dir_buf = bytearray()
    payload_buf = bytearray()

    for sec_type, data_bytes, flags in sections:
        dir_buf += struct.pack("<IIII", sec_type, current_offset, len(data_bytes), flags)
        payload_buf += data_bytes
        current_offset += len(data_bytes)

    full_bytes = header + bytes(dir_buf) + bytes(payload_buf)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(full_bytes)
    return full_bytes


def build_shapefile_sample(path: Path) -> bytes:
    ring1 = [
        (-73.9851, 40.7484),
        (-73.9751, 40.7484),
        (-73.9751, 40.7584),
        (-73.9851, 40.7584),
        (-73.9851, 40.7484),
    ]
    rec_content = bytearray()
    rec_content += struct.pack("<I", 5)
    rec_content += struct.pack("<4d", -73.9851, 40.7484, -73.9751, 40.7584)
    rec_content += struct.pack("<II", 1, len(ring1))
    rec_content += struct.pack("<I", 0)
    for lon, lat in ring1:
        rec_content += struct.pack("<dd", lon, lat)

    rec_header = struct.pack(">II", 1, len(rec_content) // 2)
    total_words = (100 + len(rec_header) + len(rec_content)) // 2

    shp_header = bytearray(100)
    struct.pack_into(">I", shp_header, 0, 9994)
    struct.pack_into(">I", shp_header, 24, total_words)
    struct.pack_into("<II", shp_header, 28, 1000, 5)
    struct.pack_into("<4d", shp_header, 36, -73.9851, 40.7484, -73.9751, 40.7584)

    full_bytes = bytes(shp_header) + rec_header + bytes(rec_content)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(full_bytes)
    return full_bytes


def build_raw_heuristic_sample(path: Path) -> bytes:
    buf = bytearray()
    buf += b"RAWV\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    buf += struct.pack("<5I", 4, 36, 136, 160, 184)
    pts = [
        (1000.0, 2000.0),
        (1050.5, 2045.25),
        (1110.0, 2080.75),
        (1180.25, 2100.0),
        (1240.0, 2150.5),
        (1300.0, 2200.0),
    ]
    buf += struct.pack("<I", len(pts))
    for x, y in pts:
        buf += struct.pack("<dd", x, y)
    for rid in range(1, 5):
        label = f"NODE_{rid:02d}".encode("ascii").ljust(16, b"\x00")
        buf += struct.pack("<If", rid, rid * 15.5) + label

    full_bytes = bytes(buf)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(full_bytes)
    return full_bytes


def build_compressed_nested_sample(path: Path) -> bytes:
    """
    Builds a synthetic binary testing all Bounded Recursive Stream Carver requirements:
      1. Root-level uncompressed polyline (4 vertices)
      2. Depth-1 zlib stream (0x78 0x9C) containing:
         - A closed pentagon polygon (6 vertices)
         - A nested Depth-2 gzip stream (0x1F 0x8B) containing a 5-row repeating attribute table
      3. High-entropy (> 7.5 bits/byte) raw Deflate stream preceded by a 4-byte LE length integer,
         containing a 5-vertex coordinate polyline + diverse binary table so compressed entropy > 7.5
      4. Corrupted zlib header (`0x78 0x9C` + invalid payload) to ensure non-blocking graceful skip
      5. Decompression bomb (`> 200:1` ratio) to ensure ratio guardrail aborts safely
    """
    buf = bytearray()
    buf += b"CMPX\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    # 1. Root-level uncompressed polyline
    root_line = [(10.0, 20.0), (40.0, 60.0), (85.0, 90.0), (130.0, 110.0)]
    buf += struct.pack("<I", len(root_line))
    for x, y in root_line:
        buf += struct.pack("<dd", x, y)

    # 2. Build Depth-2 GZIP payload (5 repeating 24-byte attribute records)
    depth2_raw = bytearray(b"D2TB\x00\x00\x00\x00")
    for rid in range(10, 15):
        lbl = f" GZIP_REC_{rid}".encode("ascii").ljust(16, b"\x00")
        depth2_raw += struct.pack("<If", rid, rid * 42.125) + lbl
    depth2_gzip = gzip.compress(bytes(depth2_raw), compresslevel=6, mtime=0)

    # Wrap inside Depth-1 ZLIB payload (level 2 -> 0x78 0x5E header) alongside a closed polygon ring
    depth1_raw = bytearray(b"D1PL\x00\x00\x00\x00")
    pentagon = [
        (200.0, 200.0),
        (300.0, 200.0),
        (330.0, 290.0),
        (250.0, 350.0),
        (170.0, 290.0),
        (200.0, 200.0),
    ]
    depth1_raw += struct.pack("<I", len(pentagon))
    for x, y in pentagon:
        depth1_raw += struct.pack("<dd", x, y)
    depth1_raw += depth2_gzip
    depth1_zlib = zlib.compress(bytes(depth1_raw), level=2)  # Starts with 0x78 0x5E
    assert depth1_zlib[:2] == b"\x78\x5e"
    buf += depth1_zlib

    # Pad to 4-byte alignment
    while len(buf) % 4 != 0:
        buf.append(0)

    # 3. Raw Deflate stream preceded by 4-byte BE expected decompressed length integer, with entropy >= 7.2
    raw_deflate_inner = bytearray()
    deflate_line = [
        (410.123456, 510.654321),
        (445.987654, 535.112233),
        (490.556677, 580.998877),
        (535.334455, 615.776655),
        (590.221100, 660.443322),
    ]
    raw_deflate_inner += struct.pack("<I", len(deflate_line))
    for x, y in deflate_line:
        raw_deflate_inner += struct.pack("<dd", x, y)
    # Add pseudo-random lookup table so raw deflate stream has entropy >= 7.2 bits/byte
    rng_seed = hashlib.sha256(b"deflate_high_entropy_seed").digest()
    for k in range(32):
        raw_deflate_inner.extend(hashlib.sha256(rng_seed + struct.pack("<I", k)).digest())

    cobj = zlib.compressobj(level=9, wbits=-15)
    raw_deflate_bytes = cobj.compress(bytes(raw_deflate_inner)) + cobj.flush()
    # Prefix with 4-byte Big-Endian expected decompressed size (tests BE/LE matching against decompressed size)
    buf += struct.pack(">I", len(raw_deflate_inner))
    buf += raw_deflate_bytes

    # 4a. Valid zlib header + valid Deflate blocks, but corrupted Adler-32 checksum -> logs HEADER_OK_CHECKSUM_MISMATCH
    bad_crc_zlib = bytearray(zlib.compress(b"VALID_BLOCKS_BUT_BAD_ADLER32_CHECKSUM" * 2, level=6))
    bad_crc_zlib[-1] ^= 0xFF
    buf += bytes(bad_crc_zlib)

    # 4b. Corrupted zlib header (`0x78 0x9C` + invalid block type) -> logs INVALID_COMPRESSED_STREAM
    buf += b"\x78\x9c\xff\xff\x00\x11\x22\x33\x44\x55"

    # 5. Decompression bomb (> 200:1 expansion ratio: 100 KB of zeros compressed via zlib) -> must be rejected
    bomb_zlib = zlib.compress(b"\x00" * 100_000, level=9)
    buf += bomb_zlib

    full_bytes = bytes(buf)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(full_bytes)
    return full_bytes


class TestOpenArchiveDecoupler(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base_dir = Path(__file__).resolve().parent
        cls.samples_dir = cls.base_dir / "samples"
        cls.out_dir = cls.base_dir / "example_output"
        cls.oadc_path = cls.samples_dir / "legacy_cad_gis_archive.oadc"
        cls.shp_path = cls.samples_dir / "municipal_parcels.shp"
        cls.raw_path = cls.samples_dir / "raw_telemetry_dump.bin"
        cls.comp_path = cls.samples_dir / "compressed_nested_archive.bin"

        build_oadc_sample(cls.oadc_path)
        build_shapefile_sample(cls.shp_path)
        build_raw_heuristic_sample(cls.raw_path)
        build_compressed_nested_sample(cls.comp_path)

    def test_01_read_only_and_determinism(self) -> None:
        before_sha = hashlib.sha256(self.oadc_path.read_bytes()).hexdigest()
        doc1 = decouple.scan_binary(self.oadc_path.name, self.oadc_path.read_bytes())
        doc2 = decouple.scan_binary(self.oadc_path.name, self.oadc_path.read_bytes())
        after_sha = hashlib.sha256(self.oadc_path.read_bytes()).hexdigest()

        self.assertEqual(before_sha, after_sha, "Source file must never be modified")
        self.assertEqual(doc1.to_dict(), doc2.to_dict(), "IR output must be 100% deterministic")

    def test_02_oadc_container_recovery(self) -> None:
        doc = decouple.scan_binary(self.oadc_path.name, self.oadc_path.read_bytes())
        self.assertEqual(doc.coordinate_system.epsg_hint, 3857)
        self.assertEqual(len(doc.layers), 4)
        self.assertEqual(doc.total_features(), 6)
        self.assertEqual(len(doc.attribute_tables), 1)
        self.assertEqual(doc.attribute_tables[0].record_count, 5)
        self.assertEqual(len(doc.raster_tiles), 1)
        self.assertEqual(doc.raster_tiles[0].width, 16)
        opaque_assets = [a for a in doc.embedded_assets if a.is_opaque]
        self.assertGreaterEqual(len(opaque_assets), 1)
        self.assertGreater(opaque_assets[0].entropy, 7.5)

    def test_03_shapefile_recovery(self) -> None:
        doc = decouple.scan_binary(self.shp_path.name, self.shp_path.read_bytes())
        self.assertEqual(doc.metadata.format_family, "ESRI_SHAPEFILE")
        self.assertEqual(doc.coordinate_system.epsg_hint, 4326)
        self.assertEqual(doc.total_features(), 1)
        feat = doc.layers[0].features[0]
        self.assertEqual(feat.geometry.type, "Polygon")
        self.assertGreaterEqual(feat.provenance.confidence.composite, 0.90)

    def test_04_unindexed_heuristic_recovery(self) -> None:
        doc = decouple.scan_binary(self.raw_path.name, self.raw_path.read_bytes())
        self.assertGreaterEqual(doc.total_features(), 1)
        self.assertGreaterEqual(len(doc.attribute_tables), 1)
        self.assertEqual(doc.attribute_tables[0].record_count, 4)
        ptr_tables = [a for a in doc.embedded_assets if a.kind == "OFFSET_TABLE"]
        self.assertGreaterEqual(len(ptr_tables), 1)

    def test_05_bounded_recursive_stream_carver_and_lineage(self) -> None:
        doc = decouple.scan_binary(
            self.comp_path.name, self.comp_path.read_bytes(), verbose=True
        )
        # Verify zlib (depth 1), nested gzip (depth 2), and length-prefixed raw Deflate were unpacked,
        # while the corrupted stream and >200:1 bomb were safely rejected!
        codecs = {ds.codec for ds in doc.decompressed_streams}
        self.assertIn("ZLIB_RFC1950", codecs)
        self.assertIn("GZIP_RFC1952", codecs)
        self.assertIn("RAW_DEFLATE", codecs)

        # Ensure no stream exceeded 200:1 expansion ratio or depth 3
        for ds in doc.decompressed_streams:
            self.assertLessEqual(ds.expansion_ratio, 200.0)
            self.assertLessEqual(ds.depth, 3)

        # Verify geometries were recovered from BOTH root AND decompressed child streams
        lineages = {
            feat.provenance.stream_lineage
            for layer in doc.layers
            for feat in layer.features
        }
        self.assertIn("root", lineages)
        self.assertTrue(
            any(
                lin.startswith("parent_offset:0x") and "/decompressed_0_zlib" in lin
                for lin in lineages
            ),
            f"Expected decompressed_0_zlib stream lineage in {lineages}",
        )
        self.assertTrue(
            any(
                lin.startswith("parent_offset:0x") and "/decompressed_1_raw" in lin
                for lin in lineages
            ),
            f"Expected decompressed_1_raw stream lineage in {lineages}",
        )

        # Verify the nested depth-2 GZIP attribute table has two-level decompression lineage
        self.assertGreaterEqual(len(doc.attribute_tables), 1)
        tbl_lineage = doc.attribute_tables[0].provenance.stream_lineage
        self.assertIn("decompressed_0_zlib", tbl_lineage)
        self.assertIn("decompressed_0_gzip", tbl_lineage)

    def test_06_exporters_and_batch_mode(self) -> None:
        rc = decouple.main([str(self.samples_dir), "--out", str(self.out_dir), "--verbose"])
        self.assertEqual(rc, 0)

        oadc_out = self.out_dir / "legacy_cad_gis_archive"
        self.assertTrue((oadc_out / "legacy_cad_gis_archive.svg").exists())
        self.assertTrue((oadc_out / "legacy_cad_gis_archive.geojson").exists())
        self.assertTrue((oadc_out / "legacy_cad_gis_archive.sqlite").exists())
        self.assertTrue((oadc_out / "legacy_cad_gis_archive_audit.txt").exists())
        self.assertTrue((oadc_out / "legacy_cad_gis_archive_ir.json").exists())
        self.assertTrue((oadc_out / "raster_tile_6.tiff").exists())
        self.assertTrue((self.out_dir / "batch_manifest.json").exists())

        comp_out = self.out_dir / "compressed_nested_archive"
        conn = sqlite3.connect(str(comp_out / "compressed_nested_archive.sqlite"))
        try:
            cur = conn.cursor()
            ds_cnt = cur.execute("SELECT COUNT(*) FROM decompressed_streams").fetchone()[0]
            self.assertGreaterEqual(ds_cnt, 3)
            lineages = [
                r[0]
                for r in cur.execute("SELECT DISTINCT stream_lineage FROM provenance").fetchall()
            ]
            self.assertIn("root", lineages)
            self.assertTrue(any("decompressed_0" in l for l in lineages))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
