use std::io;

pub(super) fn decode<'a>(data: &[u8], samples: &'a mut Vec<f32>) -> io::Result<&'a [f32]> {
    if data.len() % 4 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "captured PCM contains an incomplete float sample",
        ));
    }
    let additional = (data.len() / 4).saturating_sub(samples.len());
    samples.try_reserve_exact(additional).map_err(|error| {
        io::Error::new(io::ErrorKind::Other, format!("PCM sample allocation failed: {error}"))
    })?;
    samples.clear();
    samples.extend(data.chunks_exact(4).map(|bytes| {
        f32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }));
    Ok(samples)
}
