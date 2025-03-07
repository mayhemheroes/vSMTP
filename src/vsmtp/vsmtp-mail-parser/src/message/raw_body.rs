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

/// Representation of a mail
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RawBody {
    headers: Vec<String>,
    body: Option<String>,
}

impl RawBody {
    ///
    #[must_use]
    pub fn new(headers: Vec<String>, body: String) -> Self {
        Self {
            headers,
            body: Some(body),
        }
    }

    ///
    #[must_use]
    pub fn new_empty(headers: Vec<String>) -> Self {
        Self {
            headers,
            body: None,
        }
    }

    /// Return an iterator over the headers field
    pub fn headers_lines(&self) -> impl Iterator<Item = &str> {
        self.headers.iter().map(String::as_str)
    }

    /// Return an iterator over the body, line by line
    #[must_use]
    pub fn body_lines(&self) -> Option<impl Iterator<Item = &str>> {
        self.body.as_ref().map(|s| s.lines())
    }

    ///
    #[must_use]
    pub const fn body(&self) -> &Option<String> {
        &self.body
    }

    ///
    // TODO: make it lazy if possible
    #[must_use]
    pub fn headers(&self, with_multiline: bool) -> Vec<(String, String)> {
        let mut out = vec![];
        for (idx, header) in self.headers.iter().enumerate() {
            if header.starts_with(' ') || header.starts_with('\t') {
                continue;
            }
            let mut split = header.splitn(2, ':');
            match (split.next(), split.next()) {
                (Some(key), Some(value)) => {
                    let mut s = value.to_string();
                    for i in self.headers[idx + 1..]
                        .iter()
                        .take_while(|s| s.starts_with(' ') || s.starts_with('\t'))
                    {
                        if with_multiline {
                            s.push_str("\r\n");
                        }
                        s.push_str(i);
                    }
                    out.push((key.to_string(), s));
                }
                _ => continue,
            }
        }
        out
    }

    /// Get all headers without parsing.
    #[must_use]
    pub const fn raw_headers(&self) -> &Vec<String> {
        &self.headers
    }

    /// Search for a header (using lowercase) and return its value.
    #[must_use]
    pub fn get_header(&self, name: &str, with_key: bool, with_multiline: bool) -> Option<String> {
        for (idx, header) in self.headers.iter().enumerate() {
            if header.starts_with(' ') || header.starts_with('\t') {
                continue;
            }
            let mut split = header.splitn(2, ':');
            match (split.next(), split.next()) {
                (Some(key), Some(value)) if key.to_lowercase() == name.to_lowercase() => {
                    let mut value = value.to_string();
                    for i in self.headers[idx + 1..]
                        .iter()
                        .take_while(|s| s.starts_with(' ') || s.starts_with('\t'))
                    {
                        if with_multiline {
                            value.push_str("\r\n");
                        }
                        value.push_str(i);
                    }
                    return Some(if with_key {
                        format!("{key}:{value}")
                    } else {
                        value.trim_start().to_string()
                    });
                }
                (Some(_), Some(_)) => continue,
                _ => break,
            }
        }

        None
    }

    /// Count the number of time a header is present. (using lowercase)
    #[must_use]
    pub fn count_header(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|h| {
                h.to_lowercase()
                    .starts_with(&format!("{name}:").to_lowercase())
            })
            .count()
    }

    /// Set the value of a header or add it if it does not already exist.
    pub fn set_header(&mut self, name: &str, value: &str) {
        for header in &mut self.headers {
            let mut split = header.splitn(2, ": ");
            match (split.next(), split.next()) {
                (Some(key), Some(_)) if key.to_lowercase() == name.to_lowercase() => {
                    // TODO: handle folding ?
                    *header = format!("{key}: {value}");
                    return;
                }
                _ => {}
            }
        }
        self.add_header(name, value);
    }

    /// Rename a header.
    pub fn rename_header(&mut self, old: &str, new: &str) {
        for header in &mut self.headers {
            let mut split = header.splitn(2, ": ");
            match (split.next(), split.next()) {
                (Some(key), Some(value)) if key.to_lowercase() == old.to_lowercase() => {
                    *header = format!("{new}: {value}");
                    return;
                }
                _ => {}
            }
        }
    }

    /// Append a header to the list.
    pub fn add_header(&mut self, name: &str, value: &str) {
        // TODO: handle folding ?
        self.headers.push(format!("{name}: {value}"));
    }

    /// Prepend a header to the list.
    pub fn prepend_header(&mut self, headers: impl IntoIterator<Item = String>) {
        // TODO: handle folding ?
        self.headers.splice(..0, headers);
    }

    /// Remove a header from the list.
    pub fn remove_header(&mut self, name: &str) -> bool {
        if let Some(index) = self.headers.iter().position(|header| {
            header
                .to_lowercase()
                .starts_with(&format!("{}:", name.to_lowercase()))
        }) {
            self.headers.remove(index);
            true
        } else {
            false
        }
    }
}

impl std::fmt::Display for RawBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in &self.headers {
            f.write_str(i)?;
            f.write_str("\r\n")?;
        }
        f.write_str("\r\n")?;
        if let Some(body) = &self.body {
            f.write_str(body)?;
        }
        Ok(())
    }
}
