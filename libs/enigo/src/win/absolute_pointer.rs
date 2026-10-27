pub(super) fn normalize_absolute(
    coordinate: i32,
    origin: i32,
    extent: i32,
) -> Result<i32, &'static str> {
    Ok((coordinate - origin) * 65535 / extent)
}

#[cfg(test)]
mod tests {
    use super::normalize_absolute;

    #[test]
    fn negative_origin_is_a_valid_desktop_position() {
        assert!(normalize_absolute(-1920, -1920, 3840).is_ok());
        assert!(normalize_absolute(-1080, -1080, 2160).is_ok());
    }

    #[test]
    fn every_pixel_round_trips_through_normalized_coordinates() {
        // The integer bins described by Microsoft's UI Automation input implementation.
        for extent in [1, 2, 3, 7, 1080, 1920, 3840, 7680, 32768, 65535, 65536] {
            for origin in [-32768, -1920, 0] {
                for pixel in 0..extent {
                    let normalized = normalize_absolute(origin + pixel, origin, extent).unwrap();
                    assert!((0..=65535).contains(&normalized));
                    assert_eq!(i64::from(normalized) * i64::from(extent) / 65536,
                        i64::from(pixel), "origin={origin} extent={extent} pixel={pixel}");
                }
            }
        }
    }

    #[test]
    fn invalid_extents_are_errors() {
        for extent in [i32::MIN, -1, 0, 65537, i32::MAX] {
            assert!(normalize_absolute(0, 0, extent).is_err(), "extent={extent}");
        }
    }

    #[test]
    fn outside_coordinates_are_errors() {
        for (coordinate, origin, extent) in [
            (-1921, -1920, 3840), (1920, -1920, 3840),
            (i32::MIN, 0, 1920), (i32::MAX, 0, 1920),
            (i32::MAX, i32::MIN, 65536), (i32::MIN, i32::MAX, 1),
        ] {
            assert!(normalize_absolute(coordinate, origin, extent).is_err(),
                "coordinate={coordinate} origin={origin} extent={extent}");
        }
    }

    #[test]
    fn extreme_origins_preserve_valid_offsets() {
        for origin in [i32::MIN, i32::MAX - 65535] {
            for pixel in [0, 1, 32768, 65534, 65535] {
                assert_eq!(normalize_absolute(origin + pixel, origin, 65536), Ok(pixel));
            }
        }
    }
}
