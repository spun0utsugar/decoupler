use clap::Parser;
use memmap2::MmapOptions;
use openarchive_decoupler::carver::CarverConfig;
use openarchive_decoupler::exporters::{
    audit::{export_audit_txt, export_ir_json},
    geojson::export_geojson,
    raster::export_rasters,
    sqlite::export_sqlite,
    svg::export_svg,
};
use openarchive_decoupler::gui::launch_local_gui;
use openarchive_decoupler::ir::DecoupledDocument;
use openarchive_decoupler::scanner::{scan_binary, ScanConfig};
use serde::Serialize;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

/// OpenArchive Decoupler (`decouple`):
/// Offline, read-only structural binary analyzer and lossless universal format extractor.
#[derive(Parser, Debug)]
#[command(name = "decouple", version, about)]
struct Cli {
    /// Input binary file or directory (for batch mode).
    input: Option<PathBuf>,

    /// Output directory for unpacked artifacts.
    #[arg(long, short = 'o', default_value = "decoupled_out")]
    out: PathBuf,

    /// Comma-separated list of export formats: svg,geojson,sqlite,txt,json,tiff
    #[arg(long, short = 'f', default_value = "svg,geojson,sqlite,txt,json,tiff")]
    format: String,

    /// Minimum composite confidence score [0.0 .. 1.0] required to retain a hypothesis.
    #[arg(long, default_value_t = 0.60)]
    min_confidence: f64,

    /// Enable forensic aggressive mode (lowers raw Deflate entropy threshold to 6.8, increases recursion depth to 5, and probes all valid CMF/FLG zlib headers).
    #[arg(long)]
    aggressive: bool,

    /// Minimum Shannon entropy [0.0 .. 8.0] required to trigger length-prefixed raw Deflate carving.
    #[arg(long, default_value_t = 7.20)]
    deflate_entropy: f64,

    /// Maximum recursion depth for nested compressed stream carving.
    #[arg(long, default_value_t = 3)]
    max_depth: usize,

    /// Perform discovery and print summary report without writing output files.
    #[arg(long)]
    dry_run: bool,

    /// Enable verbose diagnostic logging during binary scanning.
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Launch the local read-only inspection GUI workbench.
    #[arg(long)]
    gui: bool,

    /// Localhost port for the optional web workbench when `--gui` is passed.
    #[arg(long, default_value_t = 7878)]
    port: u16,
}

#[derive(Serialize)]
struct BatchManifestEntry {
    source_file: String,
    sha256: String,
    file_size: usize,
    detected_magic: String,
    layers_recovered: usize,
    features_recovered: usize,
    attribute_tables_recovered: usize,
    raster_tiles_recovered: usize,
    opaque_regions_flagged: usize,
    output_directory: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut carver_cfg = CarverConfig {
        deflate_entropy_threshold: cli.deflate_entropy,
        min_high_entropy_run: 64,
        max_recursion_depth: cli.max_depth,
        scan_step: 32,
        aggressive: cli.aggressive,
        verbose: cli.verbose,
    };
    if cli.aggressive {
        carver_cfg = carver_cfg.with_aggressive();
    }
    let cfg = ScanConfig {
        min_confidence: cli.min_confidence,
        entropy_window_size: 256,
        carver: carver_cfg,
        verbose: cli.verbose,
    };

    let formats: Vec<String> = cli
        .format
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let mut last_doc: Option<DecoupledDocument> = None;

    if let Some(ref input_path) = cli.input {
        if input_path.is_dir() {
            // Batch processing mode
            let mut entries: Vec<PathBuf> = fs::read_dir(input_path)?
                .filter_map(|e| e.ok().map(|d| d.path()))
                .filter(|p| p.is_file())
                .collect();
            entries.sort();

            let mut manifest = Vec::new();
            for file_path in entries {
                let stem = file_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("binary");
                let sub_out = cli.out.join(stem);
                let doc = process_single_file(&file_path, &sub_out, &formats, &cfg, cli.dry_run, cli.verbose)?;
                let opaque_cnt = doc.embedded_assets.iter().filter(|a| a.is_opaque).count();
                manifest.push(BatchManifestEntry {
                    source_file: doc.metadata.source_filename.clone(),
                    sha256: doc.metadata.sha256.clone(),
                    file_size: doc.metadata.file_size,
                    detected_magic: doc.metadata.detected_magic.clone(),
                    layers_recovered: doc.layers.len(),
                    features_recovered: doc.total_features(),
                    attribute_tables_recovered: doc.attribute_tables.len(),
                    raster_tiles_recovered: doc.raster_tiles.len(),
                    opaque_regions_flagged: opaque_cnt,
                    output_directory: sub_out.display().to_string(),
                });
                last_doc = Some(doc);
            }

            if !cli.dry_run {
                fs::create_dir_all(&cli.out)?;
                let manifest_path = cli.out.join("batch_manifest.json");
                let f = File::create(&manifest_path)?;
                serde_json::to_writer_pretty(f, &manifest)?;
                if cli.verbose {
                    println!("[batch] Wrote deterministic manifest to {}", manifest_path.display());
                }
            }
        } else {
            let doc = process_single_file(input_path, &cli.out, &formats, &cfg, cli.dry_run, cli.verbose)?;
            last_doc = Some(doc);
        }
    }

    if cli.gui {
        launch_local_gui(last_doc, &cli.out, cli.port)?;
    }

    Ok(())
}

fn process_single_file(
    input_path: &Path,
    out_dir: &Path,
    formats: &[String],
    cfg: &ScanConfig,
    dry_run: bool,
    verbose: bool,
) -> Result<DecoupledDocument, Box<dyn std::error::Error>> {
    // Open strictly read-only and memory-map without modifying the source file
    let file = File::open(input_path)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    let filename = input_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown.bin");

    if verbose {
        println!(
            "[scan] Memory-mapped '{}' ({} bytes, read-only)",
            filename,
            mmap.len()
        );
    }

    let mut doc = scan_binary(filename, &mmap, cfg);

    println!(
        "[decouple] {} | size={} B | magic=\"{}\" | entropy={:.3} | layers={} | features={} | tables={} | rasters={} | assets={}",
        doc.metadata.source_filename,
        doc.metadata.file_size,
        doc.metadata.detected_magic,
        doc.metadata.overall_entropy,
        doc.layers.len(),
        doc.total_features(),
        doc.attribute_tables.len(),
        doc.raster_tiles.len(),
        doc.embedded_assets.len()
    );

    if dry_run {
        return Ok(doc);
    }

    fs::create_dir_all(out_dir)?;
    let stem = input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");

    if formats.iter().any(|f| f == "tiff" || f == "png" || f == "raster") {
        let written = export_rasters(&mut doc, out_dir)?;
        if verbose && !written.is_empty() {
            println!("[export] Wrote {} raster tile(s): {:?}", written.len(), written);
        }
    }

    if formats.iter().any(|f| f == "svg") {
        let p = out_dir.join(format!("{}.svg", stem));
        export_svg(&doc, &p)?;
        if verbose {
            println!("[export] SVG -> {}", p.display());
        }
    }

    if formats.iter().any(|f| f == "geojson") {
        let p = out_dir.join(format!("{}.geojson", stem));
        export_geojson(&doc, &p)?;
        if verbose {
            println!("[export] GeoJSON -> {}", p.display());
        }
    }

    if formats.iter().any(|f| f == "sqlite" || f == "db") {
        let p = out_dir.join(format!("{}.sqlite", stem));
        export_sqlite(&doc, &p)?;
        if verbose {
            println!("[export] SQLite -> {}", p.display());
        }
    }

    if formats.iter().any(|f| f == "txt") {
        let p = out_dir.join(format!("{}_audit.txt", stem));
        export_audit_txt(&doc, &p)?;
        if verbose {
            println!("[export] Audit TXT -> {}", p.display());
        }
    }

    if formats.iter().any(|f| f == "json") {
        let p = out_dir.join(format!("{}_ir.json", stem));
        export_ir_json(&doc, &p)?;
        if verbose {
            println!("[export] IR JSON -> {}", p.display());
        }
    }

    Ok(doc)
}
