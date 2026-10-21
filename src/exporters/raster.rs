use crate::ir::DecoupledDocument;
use byteorder::{LittleEndian, WriteBytesExt};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Exports any recovered raster tiles into baseline uncompressed TIFF (`.tiff`) or raw `.png` files
/// without requiring any external image libraries.
pub fn export_rasters(doc: &mut DecoupledDocument, out_dir: &Path) -> std::io::Result<Vec<String>> {
    let mut written = Vec::new();
    for tile in &mut doc.raster_tiles {
        if tile.data.is_empty() {
            continue;
        }
        if tile.format == "EMBEDDED_PNG" {
            let filename = format!("{}.png", tile.id);
            let target = out_dir.join(&filename);
            let mut f = File::create(&target)?;
            f.write_all(&tile.data)?;
            tile.exported_path = Some(filename.clone());
            written.push(filename);
        } else {
            let filename = format!("{}.tiff", tile.id);
            let target = out_dir.join(&filename);
            write_uncompressed_tiff(
                &target,
                tile.width,
                tile.height,
                tile.channels,
                &tile.data,
            )?;
            tile.exported_path = Some(filename.clone());
            written.push(filename);
        }
    }
    Ok(written)
}

/// Writes a valid baseline uncompressed TIFF 6.0 file (Little-Endian `II*\0`) for Gray8 or RGB8 pixels.
fn write_uncompressed_tiff(
    path: &Path,
    width: u32,
    height: u32,
    channels: u8,
    pixels: &[u8],
) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut out = BufWriter::new(f);

    let num_tags: u16 = 8;
    let ifd_offset: u32 = 8;
    let ifd_size: u32 = 2 + (num_tags as u32) * 12 + 4;
    let bits_per_sample_offset: u32 = ifd_offset + ifd_size;
    let pixel_offset: u32 = bits_per_sample_offset + 8;

    // 8-byte TIFF header: "II", 42, IFD offset = 8
    out.write_all(b"II")?;
    out.write_u16::<LittleEndian>(42)?;
    out.write_u32::<LittleEndian>(ifd_offset)?;

    // IFD entry count
    out.write_u16::<LittleEndian>(num_tags)?;

    // Helper to write a 12-byte TIFF IFD tag
    let mut write_tag = |tag: u16, field_type: u16, count: u32, val_or_off: u32| -> std::io::Result<()> {
        out.write_u16::<LittleEndian>(tag)?;
        out.write_u16::<LittleEndian>(field_type)?;
        out.write_u32::<LittleEndian>(count)?;
        out.write_u32::<LittleEndian>(val_or_off)?;
        Ok(())
    };

    let photometric: u32 = if channels >= 3 { 2 } else { 1 }; // 2 = RGB, 1 = BlackIsZero
    let byte_count = (width * height * (channels as u32)).min(pixels.len() as u32);

    write_tag(256, 4, 1, width)?; // ImageWidth
    write_tag(257, 4, 1, height)?; // ImageLength
    if channels == 3 {
        write_tag(258, 3, 3, bits_per_sample_offset)?; // BitsPerSample -> [8, 8, 8]
    } else {
        write_tag(258, 3, 1, 8)?;
    }
    write_tag(259, 3, 1, 1)?; // Compression = 1 (None)
    write_tag(262, 3, 1, photometric)?; // PhotometricInterpretation
    write_tag(273, 4, 1, pixel_offset)?; // StripOffsets
    write_tag(277, 3, 1, channels as u32)?; // SamplesPerPixel
    write_tag(279, 4, 1, byte_count)?; // StripByteCounts

    // Next IFD offset = 0
    out.write_u32::<LittleEndian>(0)?;

    // BitsPerSample extra array (8 bytes padded)
    out.write_u16::<LittleEndian>(8)?;
    out.write_u16::<LittleEndian>(8)?;
    out.write_u16::<LittleEndian>(8)?;
    out.write_u16::<LittleEndian>(0)?;

    // Raw pixel strip
    out.write_all(&pixels[..byte_count as usize])?;
    out.flush()
}
