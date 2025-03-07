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
use crate::{
    rule_engine::RuleEngine,
    rule_state::RuleState,
    tests::helpers::{get_default_config, get_default_state},
};
use vsmtp_common::{
    addr, mail_context::MessageMetadata, state::State, status::Status, CodeID, ReplyOrCodeID,
};
use vsmtp_mail_parser::{BodyType, Mail, MailHeaders, MailMimeParser, MessageBody};

#[test]
fn test_email_context_empty() {
    let config = get_default_config("./tmp/app");
    let config = std::sync::Arc::new(config);
    let re = RuleEngine::new(config.clone(), Some(rules_path!["main.vsl"])).unwrap();

    let resolvers = std::sync::Arc::new(std::collections::HashMap::new());
    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

    let mut state = RuleState::new(config, resolvers, queue_manager, &re);

    assert_eq!(
        re.run_when(&mut state, State::Connect),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[test]
fn test_email_context_raw() {
    let config = get_default_config("./tmp/app");
    let config = std::sync::Arc::new(config);
    let re = RuleEngine::new(config.clone(), Some(rules_path!["main.vsl"])).unwrap();
    let resolvers = std::sync::Arc::new(std::collections::HashMap::new());
    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();
    let mut state = RuleState::new(config, resolvers, queue_manager, &re);

    *state.message().write().unwrap() = MessageBody::try_from(concat!(
        "from: <foo@bar>\r\n",
        "date: Tue, 30 Nov 2021 20:54:27 +0100\r\n",
        "\r\n"
    ))
    .unwrap();
    assert_eq!(
        re.run_when(&mut state, State::PreQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[test]
fn test_email_context_mail() {
    let config = get_default_config("./tmp/app");
    let config = std::sync::Arc::new(config);
    let re = RuleEngine::new(config.clone(), Some(rules_path!["main.vsl"])).unwrap();
    let resolvers = std::sync::Arc::new(std::collections::HashMap::new());
    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();
    let mut state = RuleState::new(config, resolvers, queue_manager, &re);

    {
        *state.message().write().unwrap() = MessageBody::try_from(concat!(
            "To: other.rcpt@toremove.org, other.rcpt@torewrite.net\r\n",
            "\r\n"
        ))
        .unwrap();
        state
            .message()
            .write()
            .unwrap()
            .parse::<MailMimeParser>()
            .unwrap();

        assert_eq!(
            *state
                .message()
                .write()
                .unwrap()
                .parsed::<MailMimeParser>()
                .unwrap(),
            Mail {
                headers: MailHeaders(vec![(
                    "to".to_string(),
                    "other.rcpt@toremove.org, other.rcpt@torewrite.net".to_string(),
                )]),
                body: BodyType::Undefined,
            }
        );

        state.context().write().unwrap().envelop.rcpt = vec![
            addr!("rcpt@toremove.org").into(),
            addr!("rcpt@torewrite.net").into(),
        ];
        state.context().write().unwrap().metadata = MessageMetadata {
            timestamp: Some(std::time::SystemTime::now()),
            message_id: Some("<message-id>".to_string()),
            skipped: None,
            spf: None,
            dkim: None,
        };
    }

    assert_eq!(
        re.run_when(&mut state, State::PostQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
    assert_eq!(
        state.message().read().unwrap().get_header("to"),
        Some("rewrite1@example.com, rewrite2@example.com, added3@example.com".to_string())
    );
}

#[test]
fn test_email_bcc() {
    let config = get_default_config("./tmp/app");
    let config = std::sync::Arc::new(config);
    let re = RuleEngine::new(config.clone(), Some(rules_path!["bcc", "main.vsl"])).unwrap();
    let resolvers = std::sync::Arc::new(std::collections::HashMap::new());
    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

    let mut state = RuleState::new(config, resolvers, queue_manager, &re);

    assert_eq!(
        re.run_when(&mut state, State::PostQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[test]
fn test_email_add_get_set_header() {
    let config = get_default_config("./tmp/app");
    let config = std::sync::Arc::new(config);

    let re = RuleEngine::new(
        config.clone(),
        Some(rules_path!["mutate_header", "main.vsl"]),
    )
    .unwrap();
    let resolvers = std::sync::Arc::new(std::collections::HashMap::new());
    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

    let mut state = RuleState::new(config, resolvers, queue_manager, &re);
    assert_eq!(
        re.run_when(&mut state, State::Connect),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok))
    );

    let (mut state, _) = get_default_state("./tmp/app");
    *state.message().write().unwrap() = MessageBody::default();
    let status = re.run_when(&mut state, State::PreQ);
    assert_eq!(status, Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)));

    *state.message().write().unwrap() = MessageBody::default();

    state.context().write().unwrap().metadata = MessageMetadata {
        timestamp: None,
        message_id: None,
        skipped: None,
        spf: None,
        dkim: None,
    };
    assert_eq!(
        re.run_when(&mut state, State::PostQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}
