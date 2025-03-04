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

//! ### Message
//!
//! Those methods are used to query data from the email and/or mutate it.

/// Checks if the message contains a specific header.
///
/// ### Args
///
/// * `header` - the name of the header to search.
///
/// ### Effective smtp stage
///
/// All of them, although it is most useful in the `preq` stage because this
/// is when the email body is received.
///
/// ### Example
/// ```js
/// #{
///     postq: [
///         action "check for VSMTP header" || {
///             if has_header("X-VSMTP") {
///                 log("info", "incoming message could be from another vsmtp server");
///             }
///         }
///     ],
/// }
/// ```
///
/// ### Module:Message
fn has_header(header) { sys::has_header(msg(), header) }

/// Get a specific header from the incoming message.
///
/// ### Args
///
/// * `header` - the name of the header to get.
///
/// ### Return
///
/// * `string` - the header value, or an empty string if the header was not found.
///
/// ### Effective smtp stage
///
/// All of them, although it is most useful in the `preq` stage because this
/// is when the email body is received.
///
/// ### Example
/// ```js
/// #{
///     postq: [
///         action "display VSMTP header" || {
///             print(get_header("X-VSMTP"));
///         }
///     ],
/// }
/// ```
///
/// ### Module:Message
fn get_header(header) { sys::get_header(msg(), header) }

/// Get a list of all headers.
///
/// # Return
///
/// * `array` - all of the headers found in the message.
///
/// # Effective smtp stage
///
/// All of them, although it is most useful in the `preq` stage because this
/// is when the email body is received.
///
/// # Example
/// ```js
/// #{
///     postq: [
///         action "log display headers" || {
///             log("trace", `${get_all_headers()}`);
///         }
///     ],
/// }
/// ```
///
/// # Module:Message
fn get_all_headers() { sys::get_all_headers(msg()) }

/// Get a list of all values of a specific header from the incoming message.
///
/// # Args
///
/// * `header` - the name of the header to search.
///
/// # Return
///
/// * `array` - all header values, or an empty array if the header was not found.
///
/// # Effective smtp stage
///
/// All of them, although it is most useful in the `preq` stage because this
/// is when the email body is received.
///
/// # Example
/// ```js
/// #{
///     postq: [
///         action "display return path" || {
///             print(get_all_headers("Return-Path"));
///         }
///     ],
/// }
/// ```
///
/// # Module:Message
fn get_all_headers(header) { sys::get_all_headers(msg(), header) }

/// Count the number of headers with the given name.
///
/// # Args
///
/// * `header` - the name of the header to count.
///
/// # Return
///
/// * `number` - the number headers with the same name.
///
/// # Effective smtp stage
///
/// All of them, although it is most useful in the `preq` stage because this
/// is when the email body is received.
///
/// # Example
/// ```js
/// #{
///     postq: [
///         action "display VSMTP header" || {
///             print(get_header("X-VSMTP"));
///         }
///     ],
/// }
/// ```
///
/// # Module:Message
fn count_header(header) { sys::count_header(msg(), header) }

/// Add a new header at the end of the header list in the message.
///
/// ### Args
///
/// * `header` - the name of the header to append.
/// * `value` - the value of the header to append.
///
/// ### Effective smtp stage
///
/// All of them. Even though the email is not received at the current stage,
/// vsmtp stores new headers and will add them on top of the ones received once
/// the `preq` stage is reached.
///
/// ### Example
/// ```js
/// #{
///     postq: [
///         action "append a header" || {
///             append_header("X-JOHN", "received by john's server.");
///         }
///     ],
/// }
/// ```
///
/// ### Module:Message
fn append_header(header, value) { sys::append_header(msg(), header, value) }

/// Add a new header on top all other headers in the message.
///
/// ### Args
///
/// * `header` - the name of the header to prepend.
/// * `value` - the value of the header to prepend.
///
/// ### Effective smtp stage
///
/// All of them. Even though the email is not received at the current stage,
/// vsmtp stores new headers and will add them on top of the ones received once
/// the `preq` stage is reached.
///
/// ### Example
/// ```js
/// #{
///     postq: [
///         action "prepend a header" || {
///             prepend_header("X-JOHN", "received by john's server.");
///         }
///     ],
/// }
/// ```
///
/// ### Module:Message
fn prepend_header(header, value) { sys::prepend_header(msg(), header, value) }

/// Replace an existing header value by a new value, or append a new header
/// to the message.
///
/// ### Args
///
/// * `header` - the name of the header to set or add.
/// * `value` - the value of the header to set or add.
///
/// ### Effective smtp stage
///
/// All of them. Even though the email is not received at the current stage,
/// vsmtp stores new headers and will add them on top to the ones received once
/// the `preq` stage is reached.
///
/// Be aware that if you want to set a header value from the original message,
/// you must use `set_header` in the `preq` stage and onwards.
///
/// ### Example
/// ```js
/// #{
///     postq: [
///         action "update subject" || {
///             let subject = get_header("Subject");
///             set_header("Subject", `${subject} (analyzed by vsmtp)`);
///         }
///     ],
/// }
/// ```
///
/// ### Module:Message
fn set_header(header, value) { sys::set_header(msg(), header, value) }

/// Replace an existing header name by a new value.
///
/// # Args
///
/// * `old` - the name of the header to rename.
/// * `new` - the new new of the header.
///
/// # Effective smtp stage
///
/// All of them, although it is most useful in the `preq` stage because this
/// is when the email body is received.
///
/// # Example
/// ```js
/// #{
///     postq: [
///         action "rename header" || {
///             rename_header("X-To-Rename", "X-Renamed");
///         }
///     ],
/// }
/// ```
///
/// # Module:Message
fn rename_header(o, n) { sys::rename_header(msg(), o, n) }

/// Remove an existing header from the message.
///
/// # Args
///
/// * `header` - the name of the header to remove.
///
/// # Return
///
/// * a boolean value, true if a header has been removed, false otherwise.
///
/// # Effective smtp stage
///
/// All of them, although it is most useful in the `preq` stage because this
/// is when the email body is received.
///
/// # Example
/// ```js
/// #{
///     postq: [
///         action "remove one X-VSMTP header" || {
///             remove_header("X-VSMTP");
///         },
///
///         // There can be multiple headers with the same name.
///         // Since `remove_header` return `true` when it removes an
///         // header, you can use a `while` loop to remove all headers
///         // that bear the same name.
///         action "remove all X-VSMTP headers" || {
///             while remove_header("X-VSMTP") is true {}
///         },
///     ],
/// }
/// ```
///
/// # Module:Message
fn remove_header(header) { sys::remove_header(msg(), header) }

/// Add a recipient to the `To` header of the message.
///
/// ### Args
///
/// * `addr` - the recipient address to add to the `To` header.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "update recipients" || add_rcpt_message("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// ### Module:Message
fn add_rcpt_message(addr) { sys::add_rcpt_message(msg(), addr) }

/// Remove a recipient from the `To` header of the message.
///
/// ### Args
///
/// * `addr` - the recipient to remove to the `To` header.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "update recipients" || remove_rcpt_message("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// ### Module:Message
fn remove_rcpt_message(addr) { sys::remove_rcpt_message(msg(), addr) }

/// Replace a recipient by an other in the `To` header of the message.
///
/// ### Args
///
/// * `old_addr` - the recipient to replace.
/// * `new_addr` - the new address to use when replacing `old_addr`.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "rewrite recipient" || rewrite_rcpt_message("john.doe@example.com", "john-mta@example.com"),
///     ]
/// }
/// ```
///
/// ### Module:Message
fn rewrite_rcpt_message(old_addr, new_addr) {
    sys::rewrite_rcpt_message(msg(), old_addr, new_addr)
}

/// Change the sender's address in the `From` header of the message.
///
/// ### Args
///
/// * `new_addr` - the new sender address to set.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "replace sender" || rewrite_mail_from_message("john.server@example.com"),
///     ]
/// }
/// ```
///
/// ### Module:Message
fn rewrite_mail_from_message(new_addr) { sys::rewrite_mail_from_message(msg(), new_addr) }

/// Get a copy of the whole email as a string.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
/// ```js
/// #{
///     postq: [
///        action "display email content" || log("trace", `email content: ${mail()}`),
///     ]
/// }
/// ```
///
/// ### Module:Message
fn mail() { msg().mail }
