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

///
pub struct Callback;

impl rsasl::callback::SessionCallback for Callback {
    fn callback(
        &self,
        session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context,
        request: &mut rsasl::callback::Request,
    ) -> Result<(), rsasl::prelude::SessionError> {
        let _ = (session_data, context, request);
        println!("callback");
        Ok(())
    }

    fn validate(
        &self,
        session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context,
        validate: &mut rsasl::validate::Validate<'_>,
    ) -> Result<(), rsasl::validate::ValidationError> {
        let _ = (session_data, context, validate);
        println!("validate");
        Ok(())
    }
}
