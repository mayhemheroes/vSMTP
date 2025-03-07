/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
*/

/// Some mail systems modify email in transit, potentially invalidating a
/// signature.
///
/// To satisfy all requirements, two canonicalization algorithms are
/// defined for each of the header and the body
#[derive(Debug, PartialEq, Eq, Copy, Clone, strum::EnumString, strum::Display)]
#[strum(serialize_all = "lowercase")]
#[allow(clippy::module_name_repetitions)]
pub enum CanonicalizationAlgorithm {
    /// a "simple" algorithm that tolerates almost no modification
    Simple,
    /// a "relaxed" algorithm that tolerates common modifications
    /// such as whitespace replacement and header field line rewrapping.
    Relaxed,
}

impl CanonicalizationAlgorithm {
    fn dedup_whitespaces(s: &str) -> String {
        let mut new_str = s.to_owned();
        let mut prev = None;
        new_str.retain(|ch| {
            let result = ch != ' ' || prev != Some(' ');
            prev = Some(ch);
            result
        });
        new_str
    }

    ///
    #[must_use]
    pub fn canonicalize_body(self, body: &str) -> String {
        match self {
            CanonicalizationAlgorithm::Relaxed => {
                let mut s = Self::dedup_whitespaces(&body.replace('\t', " "));

                while let Some(idx) = s.find(" \r\n") {
                    s.remove(idx);
                }

                while s.ends_with("\r\n\r\n") {
                    s.remove(s.len() - 1);
                    s.remove(s.len() - 1);
                }

                if !s.is_empty() && !s.ends_with("\r\n") {
                    s.push('\r');
                    s.push('\n');
                }

                s
            }
            CanonicalizationAlgorithm::Simple => {
                if body.is_empty() {
                    return "\r\n".to_string();
                }

                let mut i = body;
                while i.ends_with("\r\n\r\n") {
                    i = &i[..i.len() - 2];
                }

                i.to_string()
            }
        }
    }

    ///
    #[must_use]
    pub fn canonicalize_headers(self, headers: &[String]) -> String {
        match self {
            CanonicalizationAlgorithm::Relaxed => headers
                .iter()
                .map(|s| self.canonicalize_header(s))
                .fold(String::new(), |mut acc, s| {
                    acc.push_str(&s);
                    acc.push_str("\r\n");
                    acc
                }),
            CanonicalizationAlgorithm::Simple => headers
                .iter()
                .map(|s| self.canonicalize_header(s))
                .fold(String::new(), |mut acc, s| {
                    acc.push_str(&s);
                    acc
                }),
        }
    }

    ///
    /// # Panics
    #[must_use]
    pub fn canonicalize_header(self, header: &str) -> String {
        match self {
            CanonicalizationAlgorithm::Relaxed => {
                let mut words = header.splitn(2, ':');
                match (words.next(), words.next()) {
                    (Some(key), Some(value)) => {
                        format!(
                            "{}:{}",
                            key.to_lowercase().trim_end(),
                            Self::dedup_whitespaces(&value.replace('\t', " ").replace("\r\n", " "))
                                .trim()
                        )
                    }
                    _ => todo!("handle this case: (not containing `:`) `{header}`"),
                }
            }
            CanonicalizationAlgorithm::Simple => header.to_string(),
        }
    }
}

/// The algorithm used to canonicalize the message.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Canonicalization {
    /// The algorithm used to canonicalize the header.
    pub header: CanonicalizationAlgorithm,
    /// The algorithm used to canonicalize the body.
    pub body: CanonicalizationAlgorithm,
}

impl Default for Canonicalization {
    fn default() -> Self {
        Self {
            header: CanonicalizationAlgorithm::Simple,
            body: CanonicalizationAlgorithm::Simple,
        }
    }
}

impl std::fmt::Display for Canonicalization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.header, self.body)
    }
}

impl std::str::FromStr for Canonicalization {
    type Err = <CanonicalizationAlgorithm as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (header, body) = s
            .split_once('/')
            .map_or_else(|| (s, None), |(k, v)| (k, Some(v)));

        Ok(Self {
            header: CanonicalizationAlgorithm::from_str(header)?,
            body: body.map_or(
                Ok(CanonicalizationAlgorithm::Simple),
                CanonicalizationAlgorithm::from_str,
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use vsmtp_mail_parser::RawBody;

    use crate::dkim::{CanonicalizationAlgorithm, SigningAlgorithm};

    macro_rules! canonicalization_empty_body {
        ($name:ident, $canon:expr, $algo:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(
                    base64::encode($algo.hash($canon.canonicalize_body(""))),
                    $expected
                );
            }
        };
    }

    #[cfg(feature = "historic")]
    canonicalization_empty_body!(
        simple_empty_body_rsa_sha1,
        CanonicalizationAlgorithm::Simple,
        SigningAlgorithm::RsaSha1,
        "uoq1oCgLlTqpdDX/iUbLy7J1Wic="
    );

    canonicalization_empty_body!(
        simple_empty_body_rsa_sha256,
        CanonicalizationAlgorithm::Simple,
        SigningAlgorithm::RsaSha256,
        "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
    );

    #[cfg(feature = "historic")]
    canonicalization_empty_body!(
        relaxed_empty_body_rsa_sha1,
        CanonicalizationAlgorithm::Relaxed,
        SigningAlgorithm::RsaSha1,
        "2jmj7l5rSw0yVb/vlWAYkK/YBwk="
    );

    canonicalization_empty_body!(
        relaxed_empty_body_rsa_sha256,
        CanonicalizationAlgorithm::Relaxed,
        SigningAlgorithm::RsaSha256,
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    );

    #[test]
    fn canonicalize_ex1() {
        let msg = RawBody::new(
            vec![
                "A: X\r\n".to_string(),
                "B : Y\t\r\n".to_string(),
                "\tZ  \r\n".to_string(),
            ],
            concat!(" C \r\n", "D \t E\r\n", "\r\n", "\r\n").to_string(),
        );

        assert_eq!(
            msg.headers(false)
                .into_iter()
                .map(|(key, value)| CanonicalizationAlgorithm::Relaxed
                    .canonicalize_header(&format!("{key}:{value}")))
                .fold(String::new(), |mut acc, s| {
                    acc.push_str(&s);
                    acc.push_str("\r\n");
                    acc
                }),
            concat!("a:X\r\n", "b:Y Z\r\n")
        );

        assert_eq!(
            CanonicalizationAlgorithm::Relaxed.canonicalize_headers(
                &msg.headers(false)
                    .iter()
                    .map(|(key, value)| format!("{key}:{value}"))
                    .collect::<Vec<_>>()
            ),
            concat!("a:X\r\n", "b:Y Z\r\n")
        );

        assert_eq!(
            CanonicalizationAlgorithm::Relaxed.canonicalize_body(msg.body().as_ref().unwrap()),
            concat!(" C\r\n", "D E\r\n")
        );
    }

    #[test]
    fn canonicalize_ex2() {
        let msg = RawBody::new(
            vec![
                "A: X\r\n".to_string(),
                "B : Y\t\r\n".to_string(),
                "\tZ  \r\n".to_string(),
            ],
            concat!(" C \r\n", "D \t E\r\n", "\r\n", "\r\n").to_string(),
        );

        assert_eq!(
            msg.headers(false)
                .into_iter()
                .map(|(key, value)| CanonicalizationAlgorithm::Simple
                    .canonicalize_header(&format!("{key}:{value}")))
                .fold(String::new(), |mut acc, s| {
                    acc.push_str(&s);
                    acc
                }),
            concat!("A: X\r\n", "B : Y\t\r\n", "\tZ  \r\n")
        );

        assert_eq!(
            CanonicalizationAlgorithm::Simple.canonicalize_headers(
                &msg.headers(false)
                    .iter()
                    .map(|(key, value)| format!("{key}:{value}"))
                    .collect::<Vec<_>>()
            ),
            concat!("A: X\r\n", "B : Y\t\r\n", "\tZ  \r\n")
        );

        assert_eq!(
            CanonicalizationAlgorithm::Simple.canonicalize_body(msg.body().as_ref().unwrap()),
            concat!(" C \r\n", "D \t E\r\n").to_string()
        );
    }

    #[test]
    fn canonicalize_trailing_newline() {
        let msg = RawBody::new(
            vec![
                "A: X\r\n".to_string(),
                "B : Y\t\r\n".to_string(),
                "\tZ  \r\n".to_string(),
            ],
            concat!(" C \r\n", "D \t E\r\n", "\r\n", "\r\nok").to_string(),
        );

        assert_eq!(
            CanonicalizationAlgorithm::Relaxed.canonicalize_body(msg.body().as_ref().unwrap()),
            concat!(" C\r\n", "D E\r\n\r\n\r\nok\r\n")
        );
    }
}
