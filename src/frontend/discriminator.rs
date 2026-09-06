use super::{DiscriminatorScheme, DiscriminatorValue};

pub fn validate_discriminator(value: &DiscriminatorValue, scheme: &DiscriminatorScheme) -> bool {
    matches!(
        (value, scheme),
        (DiscriminatorValue::OneByte(_), DiscriminatorScheme::OneByte)
            | (
                DiscriminatorValue::FourByteU32(_),
                DiscriminatorScheme::FourByteU32
            )
            | (
                DiscriminatorValue::EightByte(_),
                DiscriminatorScheme::EightByte
            )
    )
}

pub fn format_discriminator(value: &DiscriminatorValue) -> String {
    match value {
        DiscriminatorValue::OneByte(b) => format!("0x{:02x}", b),
        DiscriminatorValue::FourByteU32(v) => format!("0x{:08x}", v),
        DiscriminatorValue::EightByte(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            format!("0x{}", hex)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_one_byte() {
        let val = DiscriminatorValue::OneByte(0x01);
        let scheme = DiscriminatorScheme::OneByte;
        assert!(validate_discriminator(&val, &scheme));
    }

    #[test]
    fn test_validate_mismatch() {
        let val = DiscriminatorValue::OneByte(0x01);
        let scheme = DiscriminatorScheme::FourByteU32;
        assert!(!validate_discriminator(&val, &scheme));
    }

    #[test]
    fn test_format_one_byte() {
        let val = DiscriminatorValue::OneByte(0x0a);
        assert_eq!(format_discriminator(&val), "0x0a");
    }

    #[test]
    fn test_format_four_byte() {
        let val = DiscriminatorValue::FourByteU32(0x12345678);
        assert_eq!(format_discriminator(&val), "0x12345678");
    }
}
