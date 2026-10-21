# OpenArchive Decoupler (`decouple`)

[![CI](https://github.com/spun0utsugar/decoupler/actions/workflows/ci.yml/badge.svg)](https://github.com/spun0utsugar/decoupler/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](decouple.py)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](Cargo.toml)

**OpenArchive Decoupler** is a zero-dependency, offline, read-only structural binary analyzer and universal format decoupler. It ingests legacy CAD archives, GIS vector files, proprietary coordinate containers, and structured telemetry dumps—without requiring the original proprietary software or runtime—and losslessly unpacks them into universal, human-auditable formats (`SVG`, `GeoJSON`, `SQLite`, `TIFF`/`PNG`, and `TXT`/`JSON` audit reports).

> **Legitimate Archival & Migration Use Only**
> This utility is designed strictly for digital preservation, data rescue, interoperability, and legitimate archival migration of legacy files. It opens source files in strictly read-only mode (`mmap` read-only), automatically unpacks standard compressed streams (`zlib`, `gzip`, `raw Deflate`) via its bounded recursive stream carver, and **never** attempts to break cryptographic encryption. Truly unparseable high-entropy regions (encryption or unknown proprietary codecs) are transparently flagged as `OPAQUE_COMPRESSED_OR_ENCRYPTED` with their exact byte spans.

---

## Architecture Overview

```text
Input Binary (read-only mmap)
  │
  ├─► 1. Magic / Header / Sliding-Window Shannon Entropy Profiler
  │
  ├─► 2. Bounded Recursive Stream Carver & Decompressor (Max Depth = 3, or 5 in --aggressive)
  │      ├─► Magic Header Detection: zlib (0x78 0x01 / 0x78 0x5E / 0x78 0x9C / 0x78 0xDA) & gzip (0x1F 0x8B)
  │      ├─► Sliding-Window Raw Deflate Carver (entropy >= 7.20 + LE/BE 4-byte length prefix within 20%)
  │      ├─► Decompression Bomb Guardrails (64 MB hard cap, 200:1 max expansion ratio)
  │      └─► Explicit error categorization (`HEADER_OK_CHECKSUM_MISMATCH` vs `INVALID_COMPRESSED_STREAM`)
  │
  ├─► 3. Structural Pattern Recognition Engine (runs on `root` + all carved child streams, 16 MB heuristic cap)
  │      ├─► Concrete Container Parsers (OADC Tagged Vector Container, Esri Shapefile .shp)
  │      ├─► Pointer / Offset Table Validator (monotonic file-bound pointer runs)
  │      ├─► Sliding-Window IEEE-754 Float64/Float32 Coordinate Sequence Detector
  │      ├─► Geometric Sanity & Continuity Verifier (closed rings, step variance, aspect ratio)
  │      ├─► Regular Grid / Elevation Lattice Detector
  │      ├─► Repeating Fixed-Stride Attribute Record Detector
  │      ├─► Embedded PNG & Raw RGB8/Gray8 Raster Tile Detector
  │      └─► High-Entropy Opaque / Encrypted Region Classifier
  │
  ├─► 4. Multi-Factor Confidence Scorer & Lineage Provenance Tracker
  │      (Tracks `stream_lineage`, e.g. `parent_offset:0x54/decompressed_0_zlib`, plus host byte spans)
  │
  ├─► 5. Strongly-Typed Intermediate Representation (IR)
  │      (`DecoupledDocument`: Metadata, Carved Streams, CRS/Affine Hints, Layers, Geometries, Tables, Rasters, Assets)
  │
  └─► 6. Deterministic Lossless Exporters
         ├─► SVG (layered `<g>`, recovered `viewBox`, per-element `data-offset`, `data-stream-lineage` & `data-confidence`)
         ├─► GeoJSON (RFC 7946 `FeatureCollection` with exact coordinates and `stream_lineage`)
         ├─► SQLite (`.sqlite` database with `decompressed_streams`, `geometries`, `attribute_tables`, `provenance`, etc.)
         ├─► Baseline Uncompressed TIFF / PNG (for recovered raster tiles)
         └─► Plain-Text Audit Report (`_audit.txt`) & Full IR Dump (`_ir.json`)
```

---

## Repository Structure

Both a **single-binary Rust implementation** (`Cargo.toml` + `src/`) and a **zero-dependency Python standard-library implementation** (`decouple.py`) are provided side-by-side with 1-to-1 parity:

- [`Cargo.toml`](Cargo.toml) — Static release profile configuration (`lto = true`, `strip = true`, `flate2`, bundled SQLite).
- [`src/carver.rs`](src/carver.rs) — Bounded Recursive Stream Carver & Decompressor (`zlib`, `gzip`, `raw Deflate`, depth 3 limit, 64 MB cap, 200:1 expansion ratio guardrail).
- [`src/ir.rs`](src/ir.rs) — Strongly-typed Intermediate Representation (`DecoupledDocument`, `DecompressedStreamInfo`, `Layer`, `Geometry`, `AttributeTable`, `RasterTile`, `EmbeddedAsset`, `Provenance` with `stream_lineage`, `ConfidenceBreakdown`).
- [`src/scoring.rs`](src/scoring.rs) — Shannon entropy calculation, IEEE-754 coordinate continuity validator, and composite confidence scoring engine.
- [`src/scanner.rs`](src/scanner.rs) — Binary structural scanner, concrete container extractors (`OADC`, Esri `.shp`), and sliding-window heuristic detectors.
- [`src/exporters/svg.rs`](src/exporters/svg.rs) — Lossless SVG exporter with `viewBox` recovery and provenance attributes.
- [`src/exporters/geojson.rs`](src/exporters/geojson.rs) — Lossless RFC 7946 GeoJSON exporter.
- [`src/exporters/sqlite.rs`](src/exporters/sqlite.rs) — Relational SQLite database exporter (`geometries`, `attribute_tables`, `attribute_rows`, `provenance`, `raster_tiles`, `embedded_assets`).
- [`src/exporters/raster.rs`](src/exporters/raster.rs) — Zero-dependency uncompressed Baseline TIFF 6.0 and PNG writer.
- [`src/exporters/audit.rs`](src/exporters/audit.rs) — Human-readable plain-text audit report and IR JSON serializer.
- [`src/gui.rs`](src/gui.rs) — Optional local read-only workbench UI (`--gui`).
- [`src/main.rs`](src/main.rs) — CLI entry point and deterministic directory batch processor.
- [`decouple.py`](decouple.py) — Standalone, zero-dependency Python 3 implementation (`mmap`, `struct`, `sqlite3`, `tkinter`) that runs anywhere without compilation.
- [`tests/test_decouple.py`](tests/test_decouple.py) — Synthetic binary archive generator and end-to-end verification suite.
- [`example_output/`](example_output/) — Pre-generated SVG, GeoJSON, SQLite, TIFF, IR JSON, and TXT audit outputs from the synthetic test binaries.

---

## Build & Run Instructions

### Option A: Zero-Dependency Python CLI (Immediate Execution)
Requires only Python 3.8+ standard library (zero `pip` packages):

```bash
# Unpack a single binary file into SVG, GeoJSON, SQLite, TIFF, and TXT/JSON audit reports
python decouple.py tests/samples/legacy_cad_gis_archive.oadc --out example_output/single --verbose

# Batch-process an entire directory of archives and generate batch_manifest.json
python decouple.py tests/samples --out example_output --format svg,geojson,sqlite,txt,json,tiff --min-confidence 0.60 --verbose

# Dry-run mode (scan and report only, write no files)
python decouple.py tests/samples/municipal_parcels.shp --dry-run

# Launch the optional local read-only GUI workbench
python decouple.py tests/samples/legacy_cad_gis_archive.oadc --gui
```

### Option B: Native Static Rust Binary (`cargo`)
When a Rust toolchain (`cargo` / `rustc`) is installed:

```bash
# Build optimized static release binary
cargo build --release

# Run CLI
./target/release/decouple tests/samples/legacy_cad_gis_archive.oadc --out decoupled_out --format svg,geojson,sqlite,txt,json,tiff --verbose --min-confidence 0.60

# Run Rust unit tests
cargo test
```

---

## Running the Verification Suite

```bash
python tests/test_decouple.py
```

The test suite synthesizes three distinct binary files in `tests/samples/`:
1. `legacy_cad_gis_archive.oadc` — Multi-section CAD/GIS archive with an affine CRS transform (`EPSG:3857`), polygon parcels, road centerlines, cubic Bezier contour splines, a 24-byte-stride attribute table, a 6x6 regular elevation grid, an uncompressed 16x16 RGB8 raster tile, and a 256-byte high-entropy (`8.000 bits/byte`) opaque block.
2. `municipal_parcels.shp` — Esri Shapefile binary (`0x0000270A`) with WGS84 Lon/Lat (`EPSG:4326`) polygon rings.
3. `raw_telemetry_dump.bin` — Unindexed binary with unknown magic header containing a monotonic `u32` offset table, a length-prefixed IEEE-754 `float64` polyline, and repeating 24-byte attribute records.

---

## License

Released under the [MIT License](LICENSE).
