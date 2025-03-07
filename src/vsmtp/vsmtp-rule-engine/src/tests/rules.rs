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
use crate::{rule_engine::RuleEngine, tests::helpers::get_default_state};
use vsmtp_common::{addr, rcpt::Rcpt, state::State, status::Status, CodeID, ReplyOrCodeID};
use vsmtp_mail_parser::{MailMimeParser, MessageBody};

#[test]
fn test_connect_rules() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["rules/connect.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");

    // ctx.client_addr is 0.0.0.0 by default.
    state.context().write().unwrap().connection.client_addr = "127.0.0.1:0".parse().unwrap();
    assert_eq!(re.run_when(&mut state, State::Connect), Status::Next);

    state.context().write().unwrap().connection.client_addr = "0.0.0.0:0".parse().unwrap();
    assert_eq!(
        re.run_when(&mut state, State::Connect),
        Status::Deny(ReplyOrCodeID::Left(CodeID::Denied))
    );
}

#[test]
fn test_helo_rules() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["rules/helo.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");
    state.context().write().unwrap().envelop.helo = "example.com".to_string();

    assert_eq!(re.run_when(&mut state, State::Connect), Status::Next);
    assert_eq!(re.run_when(&mut state, State::Helo), Status::Next);
}

#[test]
fn test_mail_from_rules() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["rules/mail.vsl"]),
    )
    .unwrap();

    let (mut state, _) = get_default_state("./tmp/app");
    {
        let email = state.context();
        let mut email = email.write().unwrap();
        email.envelop.mail_from = addr!("staff@example.com");

        let message = state.message();
        let mut message = message.write().unwrap();

        *message = MessageBody::try_from(concat!(
            "From: staff <staff@example.com>\r\n",
            "Date: Fri, 21 Nov 1997 10:01:10 -0600\r\n",
            "\r\n",
            "This is a reply to your hello.\r\n",
        ))
        .unwrap();

        message.parse::<MailMimeParser>().unwrap();
    }

    assert_eq!(
        re.run_when(&mut state, State::MailFrom),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
    assert_eq!(
        re.run_when(&mut state, State::PostQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
    assert_eq!(
        state.context().read().unwrap().envelop.mail_from.full(),
        "no-reply@example.com"
    );
}

#[test]
fn test_rcpt_rules() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["rules/rcpt.vsl"]),
    )
    .unwrap();

    let (mut state, _) = get_default_state("./tmp/app");
    {
        let email = state.context();
        let mut email = email.write().unwrap();

        email.envelop.rcpt = vec![
            vsmtp_common::rcpt::Rcpt::new(addr!("johndoe@compagny.com")),
            vsmtp_common::rcpt::Rcpt::new(addr!("user@example.com")),
            vsmtp_common::rcpt::Rcpt::new(addr!("customer@company.com")),
        ];

        let message = state.message();
        let mut message = message.write().unwrap();

        *message = MessageBody::try_from(concat!(
            "From: staff <staff@example.com>\r\n",
            "Date: Fri, 21 Nov 1997 10:01:10 -0600\r\n",
            "\r\n",
            "This is a reply to your hello.\r\n",
        ))
        .unwrap();

        message.parse::<MailMimeParser>().unwrap();
    }

    assert_eq!(
        re.run_when(&mut state, State::RcptTo),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
    assert_eq!(re.run_when(&mut state, State::PostQ), Status::Next);
    assert_eq!(
        state
            .context()
            .read()
            .unwrap()
            .envelop
            .rcpt
            .iter()
            .map(|r| r.address.clone())
            .collect::<Vec<_>>(),
        vec![
            Rcpt::new(addr!("johndoe@example.com")),
            Rcpt::new(addr!("user@example.com")),
            Rcpt::new(addr!("no-reply@example.com")),
        ]
    );
}
