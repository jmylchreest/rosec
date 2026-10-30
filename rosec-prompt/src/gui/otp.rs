//! Editing model for six-digit authenticator codes; no automatic submission.
use zeroize::Zeroizing;

pub(super) const DIGITS: usize = 6;

#[derive(Debug)]
pub(super) struct CodeEntry {
    pub digits: [Zeroizing<String>; DIGITS],
    revealed: Option<usize>,
    pub revision: u64,
}

impl Default for CodeEntry {
    fn default() -> Self {
        Self {
            digits: std::array::from_fn(|_| Zeroizing::new(String::new())),
            revealed: None,
            revision: 0,
        }
    }
}

impl CodeEntry {
    pub fn revealed(&self, index: usize) -> bool {
        self.revealed == Some(index)
    }

    pub fn hide(&mut self, revision: u64) {
        // A timer from an older keystroke must not hide a newer digit early.
        if revision == self.revision {
            self.revealed = None;
        }
    }

    pub fn complete(&self) -> bool {
        self.digits.iter().all(|digit| digit.len() == 1)
    }

    pub fn value(&self) -> Zeroizing<String> {
        Zeroizing::new(self.digits.iter().map(|digit| digit.as_str()).collect())
    }

    /// Return the next focus position; reject non-digits and oversized pastes.
    pub fn edit(&mut self, index: usize, input: String, paste: bool) -> Option<usize> {
        let input = Zeroizing::new(input);
        self.revision = self.revision.wrapping_add(1);
        self.revealed = None;
        if index >= DIGITS {
            return None;
        }
        if input.is_empty() {
            self.digits[index] = Zeroizing::new(String::new());
            return None;
        }
        let normalized = Zeroizing::new(
            input
                .chars()
                .filter(|c| !paste || (!c.is_whitespace() && *c != '-'))
                .collect::<String>(),
        );
        if normalized.is_empty() || !normalized.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let start = if paste && normalized.len() == DIGITS {
            0
        } else {
            index
        };
        if (!paste && normalized.len() != 1) || start + normalized.len() > DIGITS {
            return None;
        }
        for (offset, digit) in normalized.chars().enumerate() {
            self.digits[start + offset] = Zeroizing::new(digit.to_string());
        }
        if !paste {
            self.revealed = Some(index);
        }
        Some((start + normalized.len()).min(DIGITS - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_latest_typed_digit_is_revealed_and_stale_timers_are_ignored() {
        let mut code = CodeEntry::default();
        code.edit(0, "1".into(), false);
        let old = code.revision;
        assert!(code.revealed(0));
        code.edit(1, "2".into(), false);
        assert!(!code.revealed(0));
        assert!(code.revealed(1));
        code.hide(old);
        assert!(code.revealed(1));
        code.hide(code.revision);
        assert!(!code.revealed(1));
        code.edit(0, "123456".into(), true);
        assert!((0..DIGITS).all(|i| !code.revealed(i)));
    }

    #[test]
    fn types_with_leading_zero_and_advances_without_submitting() {
        let mut code = CodeEntry::default();
        for (index, digit) in "012345".chars().enumerate() {
            assert_eq!(
                code.edit(index, digit.to_string(), false),
                Some((index + 1).min(5))
            );
        }
        assert!(code.complete());
        assert_eq!(code.value().as_str(), "012345");
        code.edit(2, String::new(), false);
        assert!(!code.complete());
        code.edit(2, "9".into(), false);
        assert_eq!(code.value().as_str(), "019345");
    }
    #[test]
    fn paste_replaces_whole_code_and_rejects_invalid_or_long_values() {
        let mut code = CodeEntry::default();
        assert_eq!(code.edit(4, "012 345".into(), true), Some(5));
        assert_eq!(code.value().as_str(), "012345");
        for invalid in ["1234567", "123x56", "１２３４５６"] {
            assert_eq!(code.edit(0, invalid.into(), true), None);
            assert_eq!(code.value().as_str(), "012345");
        }
    }
}
