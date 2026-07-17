//! Small H.264 Annex-B bitstream helpers shared by the encoded-source
//! implementations (`native_encoded_source`, `ipc_encoded_source`). Kept
//! dependency-free (no `livehal`) so it can be used regardless of which
//! encoded-source feature is enabled.

/// Scan an Annex-B access unit for an SPS NAL and return its
/// profile-level-id as a 6-hex-digit string, if present.
pub(crate) fn scan_sps_profile(data: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos + 3 < data.len() {
        let start_len = if data[pos] == 0 && data[pos + 1] == 0 && data[pos + 2] == 1 {
            3
        } else if pos + 4 <= data.len()
            && data[pos] == 0
            && data[pos + 1] == 0
            && data[pos + 2] == 0
            && data[pos + 3] == 1
        {
            4
        } else {
            pos += 1;
            continue;
        };
        let nal_start = pos + start_len;
        if nal_start < data.len() {
            let nal_type = data[nal_start] & 0x1F;
            if nal_type == 7 {
                // Copy the SPS NAL payload into a small buffer while removing
                // H.264 emulation prevention bytes (0x00 0x00 0x03). The
                // profile-level-id follows the NAL header byte, so we need the
                // next three de-escaped bytes.
                let mut buf = [0u8; 4];
                let mut src = nal_start;
                let mut dst = 0;
                while src < data.len() && dst < 4 {
                    if src + 2 < data.len()
                        && data[src] == 0
                        && data[src + 1] == 0
                        && data[src + 2] == 3
                    {
                        buf[dst] = 0;
                        dst += 1;
                        if dst < 4 {
                            buf[dst] = 0;
                            dst += 1;
                        }
                        src += 3;
                    } else {
                        buf[dst] = data[src];
                        dst += 1;
                        src += 1;
                    }
                }
                if dst == 4 {
                    return Some(format!("{:02x}{:02x}{:02x}", buf[1], buf[2], buf[3]));
                }
            }
        }
        pos += start_len;
    }
    None
}
