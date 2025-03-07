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
use crate::rule_engine::RuleEngine;
use crate::rule_state::RuleState;
use crate::tests::helpers::{get_default_config, get_default_state};
use vsmtp_common::rcpt::Rcpt;
use vsmtp_common::transfer::ForwardTarget;
use vsmtp_common::{addr, CodeID, ReplyOrCodeID};
use vsmtp_common::{
    mail_context::MessageMetadata, state::State, status::Status, transfer::Transfer,
};
use vsmtp_config::build_resolvers;
use vsmtp_config::field::FieldServerVirtual;
use vsmtp_mail_parser::{MailMimeParser, MessageBody};
use vsmtp_test::config::local_test;

#[test]
fn test_logs() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["actions", "logs.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");
    assert_eq!(
        re.run_when(&mut state, State::Connect),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok))
    );
}

#[test]
fn test_users() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["actions", "utils.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");

    assert_eq!(
        re.run_when(&mut state, State::Delivery),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[test]
fn test_context_write() {
    let config = local_test();
    let re = RuleEngine::new(
        std::sync::Arc::new(config),
        Some(rules_path!["actions", "write.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");

    state.context().write().unwrap().metadata = MessageMetadata {
        message_id: Some("test_message_id".to_string()),
        timestamp: Some(std::time::SystemTime::now()),
        skipped: None,
        spf: None,
        dkim: None,
    };
    *state.message().write().unwrap() = MessageBody::try_from(concat!(
        "From: john doe <john@doe.com>\r\n",
        "To: green@foo.net\r\n",
        "Subject: test email\r\n",
        "\r\n",
        "This is a raw email.\r\n",
    ))
    .unwrap();

    assert_eq!(
        re.run_when(&mut state, State::MailFrom),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
    assert_eq!(
        re.run_when(&mut state, State::PreQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
    assert_eq!(
        re.run_when(&mut state, State::PostQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );

    // raw mail should have been written on disk.
    pretty_assertions::assert_eq!(
        std::fs::read_to_string("./tmp/app/tests/generated/test_message_id.eml")
            .expect("could not read 'test_message_id'"),
        [
            "X-VSMTP-INIT: done.\r\n",
            "From: john doe <john@doe.com>\r\n",
            "To: green@foo.net\r\n",
            "Subject: test email\r\n",
            "\r\n",
            "This is a raw email.\r\n"
        ]
        .concat()
    );

    std::fs::remove_file("./tmp/app/tests/generated/test_message_id.eml")
        .expect("could not remove generated test file");
}

#[test]
fn test_context_dump() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["actions", "dump.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");

    state.context().write().unwrap().metadata = MessageMetadata {
        message_id: Some("test_message_id".to_string()),
        timestamp: Some(std::time::SystemTime::now()),
        skipped: None,
        spf: None,
        dkim: None,
    };
    *state.message().write().unwrap() = MessageBody::default();
    assert_eq!(
        re.run_when(&mut state, State::PreQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );

    *state.message().write().unwrap() = MessageBody::try_from(concat!(
        "From: john@doe.com\r\n",
        "To: green@bar.net\r\n",
        "X-Custom-Header: my header\r\n",
        "Date: toto\r\n",
        "\r\n",
        "this is an empty body\r\n",
    ))
    .unwrap();
    state
        .message()
        .write()
        .unwrap()
        .parse::<MailMimeParser>()
        .unwrap();

    assert_eq!(
        re.run_when(&mut state, State::PostQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );

    assert_eq!(
        std::fs::read_to_string("./tmp/app/tests/generated/test_message_id.json")
            .expect("could not read 'test_message_id'"),
        serde_json::to_string_pretty(&*state.context().read().unwrap())
            .expect("couldn't convert context into string")
    );

    std::fs::remove_file("./tmp/app/tests/generated/test_message_id.json")
        .expect("could not remove generated test file");
}

#[test]
fn test_quarantine() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["actions", "quarantine.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");

    state.context().write().unwrap().metadata = MessageMetadata {
        message_id: Some("test_message_id".to_string()),
        timestamp: Some(std::time::SystemTime::now()),
        skipped: None,
        spf: None,
        dkim: None,
    };
    *state.message().write().unwrap() = MessageBody::default();
    assert_eq!(
        re.run_when(&mut state, State::PreQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );

    assert!(state
        .context()
        .read()
        .unwrap()
        .envelop
        .rcpt
        .iter()
        .all(|rcpt| rcpt.transfer_method == Transfer::None));

    *state.message().write().unwrap() = MessageBody::try_from(concat!(
        "From: john@doe.com\r\n",
        "To: green@bar.net\r\n",
        "Date: toto\r\n",
        "X-Custom-Header: my header\r\n",
        "\r\n",
        "this is an empty body\r\n",
    ))
    .unwrap();
    state
        .message()
        .write()
        .unwrap()
        .parse::<MailMimeParser>()
        .unwrap();

    assert_eq!(
        re.run_when(&mut state, State::PostQ),
        Status::Quarantine("tests/generated/quarantine2".to_string())
    );
}

#[test]
fn test_transports() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["actions", "transports.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");
    *state.message().write().unwrap() = MessageBody::try_from(concat!(
        "From: john@doe.com\r\n",
        "To: green@bar.net\r\n",
        "Date: toto\r\n",
        "X-Custom-Header: my header\r\n",
        "\r\n",
        "this is an empty body\r\n",
    ))
    .unwrap();
    state
        .message()
        .write()
        .unwrap()
        .parse::<MailMimeParser>()
        .unwrap();

    assert_eq!(re.run_when(&mut state, State::Connect), Status::Next);
    assert_eq!(re.run_when(&mut state, State::Delivery), Status::Next);

    let rcpt = state.context().read().unwrap().envelop.rcpt.clone();

    assert_eq!(rcpt[0].address.full(), "john@example.com");
    assert_eq!(
        rcpt[0].transfer_method,
        Transfer::Forward(ForwardTarget::Domain("localhost".to_string()))
    );

    assert_eq!(rcpt[1].address.full(), "doe@example.com");
    assert_eq!(rcpt[1].transfer_method, Transfer::Mbox);

    assert_eq!(rcpt[2].address.full(), "green@example.com");
    assert_eq!(
        rcpt[2].transfer_method,
        Transfer::Forward(ForwardTarget::Domain("localhost".to_string()))
    );

    assert_eq!(rcpt[3].address.full(), "foo@example.com");
    assert_eq!(rcpt[3].transfer_method, Transfer::Deliver);

    assert_eq!(rcpt[4].address.full(), "bar@example.com");
    assert_eq!(rcpt[4].transfer_method, Transfer::Deliver);

    assert_eq!(rcpt[5].address.full(), "a@example.com");
    assert_eq!(rcpt[5].transfer_method, Transfer::None);

    assert_eq!(rcpt[6].address.full(), "b@example.com");
    assert_eq!(rcpt[6].transfer_method, Transfer::Maildir);

    assert_eq!(rcpt[7].address.full(), "c@example.com");
    assert_eq!(rcpt[7].transfer_method, Transfer::Maildir);

    assert_eq!(rcpt[8].address.full(), "d@example.com");
    assert_eq!(rcpt[8].transfer_method, Transfer::None);
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_transports_all() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["actions", "transports_all.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");
    state
        .message()
        .write()
        .unwrap()
        .parse::<MailMimeParser>()
        .unwrap();

    re.run_when(&mut state, State::Connect);
    re.run_when(&mut state, State::Delivery);

    state
        .context()
        .read()
        .unwrap()
        .envelop
        .rcpt
        .iter()
        .for_each(|rcpt| {
            assert_eq!(rcpt.transfer_method, Transfer::None);
        });
}

#[test]
fn test_hostname() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["actions", "utils.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");

    assert_eq!(
        re.run_when(&mut state, State::PostQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_lookup() {
    let mut config = vsmtp_config::Config::default();
    config.server.queues.dirpath = "./tmp/spool".into();
    config.app.dirpath = "./tmp/app".into();

    let config = std::sync::Arc::new(config);
    let re = RuleEngine::new(config.clone(), Some(rules_path!["actions", "utils.vsl"])).unwrap();
    let resolvers = std::sync::Arc::new(build_resolvers(&config).unwrap());
    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

    let mut state = RuleState::new(config, resolvers, queue_manager, &re);
    state.context().write().unwrap().envelop.rcpt = vec![
        Rcpt::new(addr!("john.doe@example.com")),
        Rcpt::new(addr!("foo.bar@localhost")),
    ];

    assert_eq!(
        re.run_when(&mut state, State::RcptTo),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[test]
fn test_in_domain_and_server_name() {
    let (mut state, config) = get_default_state("./tmp/app");
    let re = RuleEngine::new(config, Some(rules_path!["actions", "utils.vsl"])).unwrap();

    assert_eq!(
        re.run_when(&mut state, State::Connect),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[test]
fn test_in_domain_and_server_name_sni() {
    let mut config = get_default_config("./tmp/app");
    config.server.r#virtual = std::collections::BTreeMap::from_iter([
        ("example.com".to_string(), FieldServerVirtual::default()),
        ("doe.com".to_string(), FieldServerVirtual::default()),
        ("green.com".to_string(), FieldServerVirtual::default()),
    ]);
    let config = std::sync::Arc::new(config);

    let re = RuleEngine::new(config.clone(), Some(rules_path!["actions", "utils.vsl"])).unwrap();
    let resolvers = std::sync::Arc::new(std::collections::HashMap::new());
    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();
    let mut state = RuleState::new(config, resolvers, queue_manager, &re);

    assert_eq!(
        re.run_when(&mut state, State::PreQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}
