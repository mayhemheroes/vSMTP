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

use super::Connection;
use vsmtp_common::{
    auth::Mechanism,
    re::{anyhow, base64, log, tokio},
    CodeID,
};
use vsmtp_config::Resolvers;
use vsmtp_rule_engine::RuleEngine;

#[allow(clippy::module_name_repetitions)]
#[must_use]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("authentication failed: {0}")]
    Failed(rsasl::prelude::SessionError),
    #[error("authentication cancelled")]
    Canceled,
    #[error("authentication timeout")]
    Timeout(std::io::Error),
    #[error("base64 decoding error")]
    InvalidBase64,
    #[error("error while sending a response: `{0}`")]
    SendingResponse(anyhow::Error),
    #[error("error while reading message: `{0}`")]
    ReadingMessage(std::io::Error),
    #[error("SASL error: `{0}`")]
    BackendError(rsasl::prelude::SASLError),
    #[error("mechanism `{0}` must be used in encrypted connection")]
    AuthMechanismMustBeEncrypted(Mechanism),
    #[error("client started the authentication but server did not send any challenge: `{0}`")]
    AuthClientMustNotStart(Mechanism),
}
/*
async fn auth_step<S>(
    conn: &mut Connection<S>,
    session: &mut vsmtp_rsasl::DiscardOnDrop<Session>,
    buffer: &[u8],
) -> Result<bool, AuthExchangeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    if buffer == [b'*'] {
        return Err(AuthExchangeError::Canceled);
    }

    let bytes64decoded = base64::decode(buffer).map_err(|_| AuthExchangeError::InvalidBase64)?;

    match session.step(&bytes64decoded) {
        Ok(vsmtp_rsasl::Step::Done(buffer)) => {
            if !buffer.is_empty() {
                todo!(
                    "Authentication successful, bytes to return to client: {:?}",
                    std::str::from_utf8(&buffer)
                );
            }

            conn.send_code(CodeID::AuthSucceeded)
                .await
                .map_err(AuthExchangeError::SendingResponse)?;
            Ok(true)
        }
        Ok(vsmtp_rsasl::Step::NeedsMore(buffer)) => {
            let reply = format!(
                "334 {}\r\n",
                base64::encode(std::str::from_utf8(&buffer).unwrap())
            );

            conn.send(&reply)
                .await
                .map_err(AuthExchangeError::SendingResponse)?;
            Ok(false)
        }
        Err(e) if e.matches(vsmtp_rsasl::ReturnCode::GSASL_AUTHENTICATION_ERROR) => {
            Err(AuthExchangeError::Failed)
        }
        Err(e) => Err(AuthExchangeError::StepError(e)),
    }
}

*/
/*
pub async fn on_authentication<S>(
    conn: &mut Connection<S>,
    rsasl: std::sync::Arc<rsasl::config::SASLConfig>,
    rule_engine: std::sync::Arc<RuleEngine>,
    resolvers: std::sync::Arc<Resolvers>,
    mechanism: Mechanism,
    initial_response: Option<Vec<u8>>,
) -> Result<(), AuthExchangeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    // TODO: if initial data == "=" ; it mean empty ""

    if mechanism.must_be_under_tls() && !conn.context.is_secured {
        if conn
            .config
            .server
            .smtp
            .auth
            .as_ref()
            .map_or(false, |auth| auth.enable_dangerous_mechanism_in_clair)
        {
            log::warn!(
                "An unsecured AUTH mechanism ({mechanism}) is used on a non-encrypted connection!"
            );
        } else {
            conn.send_code(CodeID::AuthMechanismMustBeEncrypted)
                .await
                .map_err(AuthExchangeError::SendingResponse)?;

            return Err(AuthExchangeError::AuthMechanismMustBeEncrypted(mechanism));
        }
    }

    if !mechanism.client_first() && initial_response.is_some() {
        conn.send_code(CodeID::AuthClientMustNotStart)
            .await
            .map_err(AuthExchangeError::SendingResponse)?;

        return Err(AuthExchangeError::AuthClientMustNotStart(mechanism));
    }

    let mut guard = rsasl.lock().await;
    let mut session = guard.server_start(&format!("{mechanism}")).unwrap();
    session.store(Box::new((rule_engine, resolvers, conn.context.clone())));

    let mut succeeded =
        auth_step(conn, &mut session, &initial_response.unwrap_or_default()).await?;

    while !succeeded {
        succeeded = match conn.read(READ_TIMEOUT).await {
            Ok(Some(buffer)) => {
                log::trace!("{buffer}");
                auth_step(conn, &mut session, buffer.as_bytes()).await
            }
            Ok(None) => Err(AuthExchangeError::ReadingMessage(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF during SASL exchange",
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                Err(AuthExchangeError::Timeout(e))
            }
            Err(e) => Err(AuthExchangeError::ReadingMessage(e)),
        }?;
    }

    // TODO: if success get session property

    Ok(())
}
*/

const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

struct Writer<'a, S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    conn: &'a mut Connection<S>,
}

impl<'a, S> std::io::Write for Writer<'a, S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        println!("buf: {}", std::str::from_utf8(buf).unwrap());

        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move {
                tokio::io::AsyncWriteExt::write_all(&mut self.conn.inner.inner, b"334 ").await?;
                tokio::io::AsyncWriteExt::write_all(
                    &mut self.conn.inner.inner,
                    base64::encode(buf).as_bytes(),
                )
                .await?;
                tokio::io::AsyncWriteExt::write_all(&mut self.conn.inner.inner, b"\r\n").await?;
                std::io::Result::Ok(())
            })
        })
        .map(|_| buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move {
                tokio::io::AsyncWriteExt::flush(&mut self.conn.inner.inner).await
            })
        })
    }
}

pub async fn on_authentication<S>(
    conn: &mut Connection<S>,
    rsasl_config: std::sync::Arc<rsasl::config::SASLConfig>,
    rule_engine: std::sync::Arc<RuleEngine>,
    resolvers: std::sync::Arc<Resolvers>,
    mechanism: Mechanism,
    initial_response: Option<Vec<u8>>,
) -> Result<(), Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    // TODO: if initial data == "=" ; it mean empty ""

    if mechanism.must_be_under_tls() && !conn.context.is_secured {
        if conn
            .config
            .server
            .smtp
            .auth
            .as_ref()
            .map_or(false, |auth| auth.enable_dangerous_mechanism_in_clair)
        {
            log::warn!(
                "An unsecured AUTH mechanism ({mechanism}) is used on a non-encrypted connection!"
            );
        } else {
            conn.send_code(CodeID::AuthMechanismMustBeEncrypted)
                .await
                .map_err(Error::SendingResponse)?;

            return Err(Error::AuthMechanismMustBeEncrypted(mechanism));
        }
    }

    let sasl_server =
        rsasl::prelude::SASLServer::<rsasl::validate::NoValidation>::new(rsasl_config);

    let mut session = sasl_server
        .start_suggested(rsasl::prelude::Mechname::parse(mechanism.to_string().as_bytes()).unwrap())
        .map_err(Error::BackendError)?;

    let mut data = match initial_response {
        Some(_) if !mechanism.client_first() => {
            conn.send_code(CodeID::AuthClientMustNotStart)
                .await
                .map_err(Error::SendingResponse)?;

            return Err(Error::AuthClientMustNotStart(mechanism));
        }
        Some(buffer) => Some(buffer),
        None => None,
    };

    let mut writer = Writer { conn };

    if session.are_we_first() {
        // todo!();
    } else if data.is_none() {
        writer.conn.send("334 \r\n").await.unwrap();

        data = match writer.conn.read(READ_TIMEOUT).await {
            Ok(Some(buffer)) => Some(base64::decode(buffer).unwrap()),
            Ok(None) | Err(_) => todo!(),
        };
    }

    while {
        if let Some(data) = &data {
            dbg!(std::str::from_utf8(data));
        }
        let (state, _) = session
            .step(data.as_deref(), &mut writer)
            .map_err(Error::Failed)?;
        state.is_running()
    } {
        data = match writer.conn.read(READ_TIMEOUT).await {
            Ok(Some(buffer)) => Some(base64::decode(buffer).unwrap()),
            Ok(None) | Err(_) => todo!(),
        };
    }

    let _validation = session.validation().unwrap();

    conn.send_code(CodeID::AuthSucceeded)
        .await
        .map_err(Error::SendingResponse)?;

    Ok(())
}

#[test]
fn b() {
    // AGhlbGxvAHdvcmxk
    println!("{}", base64::encode(b"\0hello\0world"));
}
