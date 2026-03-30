use image::imageops::FilterType;

pub type ImageFingerprint = u128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintError {
    EmptyInput,
    DecodeFailed,
}

pub fn perceptual_hash(bytes: &[u8]) -> Result<ImageFingerprint, FingerprintError> {
    if bytes.is_empty() {
        return Err(FingerprintError::EmptyInput);
    }

    let image = image::load_from_memory(bytes).map_err(|_| FingerprintError::DecodeFailed)?;
    let grayscale = image.grayscale();
    let resized = grayscale.resize_exact(17, 8, FilterType::Triangle).to_luma8();

    let mut hash = 0u128;
    for y in 0..8u32 {
        for x in 0..16u32 {
            let left = resized.get_pixel(x, y)[0];
            let right = resized.get_pixel(x + 1, y)[0];
            let bit_index = (y * 16 + x) as u128;
            if left > right {
                hash |= 1u128 << bit_index;
            }
        }
    }

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageBuffer, ImageFormat, Rgba};
    use std::io::Cursor;

    fn sample_png() -> Vec<u8> {
        let image = ImageBuffer::from_fn(24, 24, |x, y| {
            let tone = ((x * 7 + y * 11) % 255) as u8;
            Rgba([tone, tone.saturating_add(8), tone.saturating_add(16), 255])
        });
        let dynamic = DynamicImage::ImageRgba8(image);
        let mut out = Cursor::new(Vec::new());
        dynamic
            .write_to(&mut out, ImageFormat::Png)
            .expect("png encode should succeed");
        out.into_inner()
    }

    #[test]
    fn same_image_produces_same_hash() {
        let bytes = sample_png();
        let first = perceptual_hash(&bytes).expect("hash 1");
        let second = perceptual_hash(&bytes).expect("hash 2");
        assert_eq!(first, second);
    }
}
