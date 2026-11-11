use crate::error::SanitizeError;

/// Maximum permitted UTF-8 byte length for a single cached metadata string.
pub const MAX_METADATA_STR_BYTES: usize = 4_096;

fn is_unicode_tag(cp: u32) -> bool {
    (0xE0000..=0xE007F).contains(&cp)
}

fn is_bidi_or_zero_width(cp: u32) -> bool {
    (0x202A..=0x202E).contains(&cp)
        || (0x2066..=0x2069).contains(&cp)
        || matches!(cp, 0x061C | 0x200B..=0x200F | 0x2060 | 0xFEFF)
}

fn is_c0_del_or_c1(cp: u32) -> bool {
    cp <= 0x1F || cp == 0x7F || (0x80..=0x9F).contains(&cp)
}

/// Deterministically validates `input`, rejecting C0/C1 controls, ANSI CSI/OSC
/// sequences, Unicode Tag characters (`U+E0000..=U+E007F`), bidirectional
/// overrides/isolates, and zero-width format characters.
pub fn validate_metadata_str(input: &str) -> Result<&str, SanitizeError> {
    if input.is_empty() {
        return Err(SanitizeError::EmptyString);
    }
    if input.len() > MAX_METADATA_STR_BYTES {
        return Err(SanitizeError::TooLong {
            len: input.len(),
            max: MAX_METADATA_STR_BYTES,
        });
    }

    for (byte_offset, ch) in input.char_indices() {
        let cp = u32::from(ch);
        if matches!(cp, 0x1B | 0x9B | 0x9D) {
            return Err(SanitizeError::AnsiEscapeSequence { byte_offset });
        }
        if is_c0_del_or_c1(cp) {
            return Err(SanitizeError::ControlCharacter {
                byte_offset,
                codepoint: cp,
            });
        }
        if is_unicode_tag(cp) {
            return Err(SanitizeError::UnicodeTagCharacter {
                byte_offset,
                codepoint: cp,
            });
        }
        if is_bidi_or_zero_width(cp) {
            return Err(SanitizeError::BidiOrZeroWidthCharacter {
                byte_offset,
                codepoint: cp,
            });
        }
    }

    Ok(input)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StripState {
    Normal,
    AfterEsc,
    InCsi,
    InOsc,
    InOscEsc,
}

/// Strips hostile C0/C1 controls, complete ANSI CSI/OSC sequences, Unicode Tag
/// characters, and bidirectional overrides from `input`.
#[must_use]
pub fn strip_hostile_metadata(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut state = StripState::Normal;

    for ch in input.chars() {
        let cp = u32::from(ch);
        match state {
            StripState::Normal => {
                if cp == 0x1B {
                    state = StripState::AfterEsc;
                } else if cp == 0x9B {
                    state = StripState::InCsi;
                } else if cp == 0x9D {
                    state = StripState::InOsc;
                } else if !is_c0_del_or_c1(cp) && !is_unicode_tag(cp) && !is_bidi_or_zero_width(cp)
                {
                    out.push(ch);
                }
            }
            StripState::AfterEsc => {
                if ch == '[' {
                    state = StripState::InCsi;
                } else if ch == ']' {
                    state = StripState::InOsc;
                } else {
                    state = StripState::Normal;
                }
            }
            StripState::InCsi => {
                if (0x40..=0x7E).contains(&cp) {
                    state = StripState::Normal;
                }
            }
            StripState::InOsc => {
                if cp == 0x07 || cp == 0x9C {
                    state = StripState::Normal;
                } else if cp == 0x1B {
                    state = StripState::InOscEsc;
                }
            }
            StripState::InOscEsc => {
                if ch == '\\' {
                    state = StripState::Normal;
                } else {
                    state = StripState::InOsc;
                }
            }
        }
    }

    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_clean_printable_metadata_and_rejects_controls() {
        assert_eq!(
            validate_metadata_str("application/json; charset=utf-8").unwrap(),
            "application/json; charset=utf-8"
        );
        assert!(matches!(
            validate_metadata_str("bad\x00null").unwrap_err(),
            SanitizeError::ControlCharacter { codepoint: 0, .. }
        ));
        assert!(matches!(
            validate_metadata_str("ansi\x1b[31mred").unwrap_err(),
            SanitizeError::AnsiEscapeSequence { .. }
        ));
    }

    #[test]
    fn strips_osc_and_unicode_tags_cleanly() {
        let dirty = "safe-\x1b]0;PWNED-TITLE\x07middle-\u{E0041}\u{E0042}\u{202E}end";
        assert_eq!(strip_hostile_metadata(dirty), "safe-middle-end");
    }
}
