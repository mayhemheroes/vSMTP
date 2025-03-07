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

//! ### Security
//!
//! This module contains multiple security functions that you can use to protect your server.

/// Do not accept a message from a known internal domain if the client is unknown.
///
/// ### Args
/// * `allowed_hosts` - group of IPv4 | IPv6 | IPv4 range | IPv6 range | fqdn
///
/// ### Return
/// * `deny()`
/// * `next()`
///
/// ### Effective smtp stage
/// `mail` and onwards.
///
/// ### Example
/// ```js
/// mail: [
///    rule "check mail relay" || {
///        object allowed_hosts group = [
///            object mta_ip ip4 = "192.168.1.254",
///            object mta_fqdn fqdn = "mta-internal.foobar.com"
///        ];
///        check_mail_relay(allowed_hosts)
///    }
/// ]
///
/// ### Module:Security
/// ```
fn check_mail_relay(allowed_hosts) {
    if in_domain(ctx().mail_from)
    && !(ctx().is_authenticated || (ctx().client_ip in allowed_hosts)) {
        deny(code554_7_1)
    } else {
        next()
    }
}

/// Do not accept open relaying.
///
/// ### Args
///
/// * `allowed_hosts` - group of IPv4 | IPv6 | IPv4 range | IPv6 range | fqdn
///
/// ### Return
/// * `deny()`
/// * `next()`
///
/// ### Effective smtp stage
/// `rcpt` only.
///
/// ### Example
/// ```js
/// rcpt: [
///    rule "check rcpt relay" || {
///        object allowed_hosts group = [
///            object mta_ip ip4 = "192.168.1.254",
///            object mta_fqdn fqdn = "mta-internal.foobar.com"
///        ];
///        check_rcpt_relay(allowed_hosts)
///    }
/// ]
///
/// ### Module:Security
/// ```
fn check_rcpt_relay(allowed_hosts) {
    if !in_domain(ctx().rcpt)
    && !(ctx().is_authenticated || (ctx().client_ip in allowed_hosts)) {
        remove_rcpt_envelop(ctx().rcpt);
        info(code554_7_1)
    } else {
        next()
    }
}

/// create key-value pairs of spf results
/// to inject into the spf or auth headers.
private fn spf_key_value_list(query) {
`receiver=${hostname()};
 client-ip=${ctx().client_ip};
 envelope_from=${ctx().mail_from};
 identity=mailfrom;
 ${
   if "mechanism" in query { `mechanism=${query.mechanism};` }
   else if "problem" in query { `problem=${query.problem};` }
 }`
}

/// Record results in a spf header (RFC 7208-9)
private fn spf_header(query) {
    `${query.result} ${spf_key_value_list(query)}`
}

/// Record results in the auth header (RFC 7208-9)
private fn auth_header(query) {
`${hostname()}; spf=${query.result}
 reason="${spf_key_value_list(query)}"
 smtp.mailfrom=${ctx().mail_from}`;
}

/// WARNING: This is a low level api.
///
/// Get spf record following the Sender Policy Framework (RFC 7208).
/// see https://datatracker.ietf.org/doc/html/rfc7208
///
/// ### Return
/// * a rhai `Map`
///     * result (String) : the result of an SPF evaluation.
///     * cause  (String) : the "mechanism" that matched or the "problem" error (RFC 7208-9.1).
///
/// ### Effective smtp stage
/// `rcpt` and onwards.
///
/// ### Note
/// `check_spf` only checks for the sender's identity, not the `helo` value.
///
/// ### Example
/// ```js
/// #{
///     mail: [
///         rule "raw check spf" || {
///             let query = check_spf_inner();
///
///             log("debug", `result: ${query.result}`);
///
///             // the 'result' parameter gives you the result of evaluation.
///             // (see https://datatracker.ietf.org/doc/html/rfc7208#section-2.6)
///             switch query.result {
///                 "pass" => next(),
///                 "fail" => {
///                     // the 'cause' parameter gives you the cause of the result if there
///                     // was an error, and the mechanism of the result if it succeeded.
///                     log("error", `check spf error: ${query.cause}`);
///                     deny()
///                 },
///                 _ => next(),
///             };
///         },
///     ],
/// }
/// ```
///
/// ### Module:Security
fn check_spf_inner() { sys::check_spf(ctx(), srv()) }

/// Check spf record following the Sender Policy Framework (RFC 7208).
/// see https://datatracker.ietf.org/doc/html/rfc7208
///
/// ### Args
///
/// * `header` - "spf" | "auth" | "both" | "none"
/// * `policy` - "strict" | "soft"
///
/// ### Return
/// * `deny(code550_7_23 | code451_7_24 | code550_7_24)` - an error occurred during lookup. (returned even when a softfail is received using the "strict" policy)
/// * `next()` - the operation succeeded.
///
/// ### Effective smtp stage
/// `rcpt` and onwards.
///
/// ### Errors
/// * The `header` argument is not valid.
/// * The `policy` argument is not valid.
///
/// ### Note
/// `check_spf` only checks for the sender's identity, not the `helo` value.
///
/// ### Example
/// ```js
/// #{
///     mail: [
///        rule "check spf" || check_spf("spf", "soft")
///     ]
/// }
///
/// #{
///     mail: [
///         // if this check succeed, it wil return `next`.
///         // if it fails, it might return `deny` with a custom code
///         // (X.7.24 or X.7.25 for example)
///         //
///         // if you want to use the return status, just put the check_spf
///         // function on the last line of your rule.
///         rule "check spf 1" || {
///             log("debug", `running sender policy framework on ${mail_from()} identity ...`);
///             check_spf("spf", "soft")
///         },
///
///         // policy is set to "strict" by default.
///         rule "check spf 2" || check_spf("both"),
///     ],
/// }
/// ```
///
/// ### Module:Security
fn check_spf(header, policy) {

    if in_domain(ctx().mail_from) {
        return next();
    }

    const AUTH_HEADER = "Authentication-Results";
    const SPF_HEADER = "Received-SPF";

    let query = sys::check_spf(ctx(), srv());

    // TODO: The Received-SPF header field is a trace field
    // and SHOULD be prepended to the existing header, above the Received: field
    // It MUST appear above all other Received-SPF fields in the message.
    switch header {
        // It is RECOMMENDED that SMTP receivers record the result"
        "spf" => prepend_header(SPF_HEADER, spf_header(query)),
        "auth" => prepend_header(AUTH_HEADER, auth_header(query)),
        "both" => {
            prepend_header(AUTH_HEADER, auth_header(query));
            prepend_header(SPF_HEADER, spf_header(query));
        },
        "none" => {},
        _ => throw `spf 'header' argument must be 'spf', 'auth' or 'both', not '${header}'`,
    }

    if policy == "strict" {
        switch query.result {
            "pass" => next(),
            "fail" => deny(code550_7_23),
            "softfail" => deny(code550_7_23),
            "temperror" => deny(code451_7_24),
            "permerror" => deny(code550_7_24),
            _ => next(),
        }
    } else if policy == "soft" {
        switch query.result {
            "fail" => deny(code550_7_23),
            "temperror" => deny(code451_7_24),
            "permerror" => deny(code550_7_24),
            _ => next(),
        }
    } else {
        throw `spf 'policy' argument must be 'strict' or 'soft', not '${policy}'`;
    }
}

/// Check spf record following the Sender Policy Framework (RFC 7208).
/// A wrapper with the policy set to "strict" by default.
/// see https://datatracker.ietf.org/doc/html/rfc7208
///
/// ### Args
///
/// * `header` - "spf" | "auth" | "both" | "none"
///
/// ### Return
/// * `deny(code550_7_23 | code451_7_24 | code550_7_24)` - an error occurred during lookup. (returned even when a softfail is received using the "strict" policy)
/// * `next()` - the operation succeeded.
///
/// ### Effective smtp stage
/// `rcpt` and onwards.
///
/// ### Errors
/// * The `header` argument is not valid.
/// * The `policy` argument is not valid.
///
/// ### Note
/// `check_spf` only checks for the sender's identity, not the `helo` value.
///
/// ### Example
/// ```js
/// #{
///     mail: [
///        rule "check spf relay" || check_spf(allowed_hosts),
///     ]
/// }
///
/// #{
///     mail: [
///         // if this check succeed, it wil return `next`.
///         // if it fails, it might return `deny` with a custom code
///         // (X.7.24 or X.7.25 for example)
///         //
///         // if you want to use the return status, just put the check_spf
///         // function on the last line of your rule.
///         rule "check spf 1" || {
///             log("debug", `running sender policy framework on ${mail_from()} identity ...`);
///             check_spf("spf", "soft")
///         },
///
///         // policy is set to "strict" by default.
///         rule "check spf 2" || check_spf("both"),
///     ],
/// }
/// ```
/// ### Module:Security
fn check_spf(header) {
    check_spf(header, "strict")
}

private fn dkim_verify_first_signature_or_error(policy) {
    log("warn", `verifying DKIM signature with policy=${policy}`);

    let last_error = #{ status: "none" };

    let header = get_header_untouched(msg(), "DKIM-Signature");
    header.truncate(policy.nbr_headers);

    for i in header {
        try {
            let signature = sys::parse_signature(i);

            if signature.has_expired(policy.expiration_epsilon) {
                log("warn", `DKIM signature expired, continuing`);
                continue;
            }

            // NOTE: for any reason, you can decide to ignore the signature
            // if signature... {
            //     continue;
            // }

            for key in sys::get_public_key(srv(), signature, policy.on_multiple_key_records) {
                try {
                    sys::verify_dkim(msg(), signature, key);
                    log("warn", "DKIM signature successfully verified");

                    if key.has_debug_flag {
                        log("warn", "DKIM signature contains `debug_flag`, continuing");
                        continue;
                    }

                    // header.b & header.a can be set optionally
                    return #{
                        status: "pass",
                        sdid: signature.sdid,
                        auid: signature.auid,
                    };
                } catch (e) {
                    log("warn", `DKIM signature verification failed: ${e.to_debug()}`);
                    last_error =  #{ status: sys::handle_dkim_error(e) };
                }
            }

        } catch (e) {
            log("warn", `DKIM signature invalid: ${e.to_debug()}`);
            last_error =  #{ status: sys::handle_dkim_error(e) };
        }
    }

    log("warn", `no valid DKIM signature, returning: '${last_error}'`);
    last_error
}

fn verify_dkim_inner(policy) {
    if ctx().has_dkim_result {
        ctx().dkim_result
    } else {
        let result = dkim_verify_first_signature_or_error(policy);
        ctx().store_dkim(result);
        result
    }
}

/// Verify the `DKIM-Signature` header(s) in the mail and produce a `Authentication-Results`.
/// If this function has already been called once, it will return the result of the previous call.
/// see https://datatracker.ietf.org/doc/html/rfc6376
///
/// ### Return
///
/// * a DkimResult object
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
///
/// ```js
/// #{
///   preq: [
///     action "check dkim" || { verify_dkim(); },
///   ]
/// }
/// ````
///
/// ### Module:Security
fn verify_dkim() {
    let result = verify_dkim_inner(#{
        nbr_headers: 5,
        // the dns query may result in multiple public key, the registry with invalid format are ignored.
        // among ["first_one", "cycle"]
        on_multiple_key_records: "cycle",
        // is the `expire_time` of the signature over `now +/- epsilon` (as seconds)
        expiration_epsilon: 100,
    });

    let header = `${get_root_domain(ctx().server_name)};
  dkim=${result.status}`;

    prepend_header("Authentication-Results", header);
    result
}

/// Produce a `DKIM-Signature` header.
///
/// ### Args
///
/// * `selector` - the DNS selector to expose the public key & for the verifier
/// * `headers_field` - list of headers to sign
/// * `canonicalization` - the canonicalization algorithm to use (ex: "simple/relaxed")
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
///
/// ```js
/// #{
///   preq: [
///     action "sign dkim" || {
///       sign_dkim("2022-09", ["From", "To", "Date", "Subject", "From"], "simple/relaxed");
///     },
///   ]
/// }
/// ```
///
/// ### Module:Security
fn sign_dkim(selector, headers_field, canonicalization) {
    let signature = sys::generate_signature_dkim(msg(), ctx(), srv(), selector, headers_field, canonicalization);
    prepend_header("DKIM-Signature", signature);
}

/// Alias for `sign_dkim(selector, ["From", "To", "Date", "Subject", "From"], "simple/relaxed")`
///
/// ### Module:Security
fn sign_dkim(selector) {
    sign_dkim(selector, ["From", "To", "Date", "Subject", "From"], "simple/relaxed")
}

/// Apply the DMARC policy to the mail.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
///
/// ```js
/// #{
///   preq: [
///     rule "check dmarc" || { check_dmarc() },
///   ]
/// }
/// ```
///
/// ### Module:Security
fn check_dmarc() {
    let rfc5322_from;
    let record;
    try {
        rfc5322_from = parse_rfc5322_from(msg()).domain;
        record = get_dmarc_record(srv(), rfc5322_from);
    } catch (e) {
        log("warn", `DMARC record not found: ${e.to_debug()}`);
        return next();
    }

    let dkim_result = verify_dkim_inner(#{
        // TODO: only take `d == rfc5322_from`
        nbr_headers: 5,
        on_multiple_key_records: "cycle",
        expiration_epsilon: 1000,
    });
    let spf_result = sys::check_spf(ctx(), srv());

    let header = `${get_root_domain(ctx().server_name)};
  dkim=${dkim_result.status}
  spf=${spf_result.result}
  reason="${spf_key_value_list(spf_result)}"
  smtp.mailfrom=${ctx().mail_from}`;

    let dmarc_pass = dmarc_check(record, rfc5322_from, dkim_result, ctx().mail_from.domain, spf_result.result);

    prepend_header("Authentication-Results", `${header}
  dmarc=${if dmarc_pass { "pass" } else { "fail" }}`);

    if dmarc_pass {
        return next();
    } else {
        let receiver_policy = record.receiver_policy;
        log("warn", `dmarc check failed, handling 'receiver_policy=${receiver_policy}'`);

        switch receiver_policy {
            "none" => {
                return next();
            },
            "quarantine" => {
                return quarantine("dmarc");
            },
            "reject" => {
                return deny(/*code_...*/);
            }
        }
    }
}
