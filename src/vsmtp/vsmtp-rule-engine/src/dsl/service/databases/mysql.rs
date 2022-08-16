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

use crate::{api::EngineResult, dsl::service::Service};
use vsmtp_common::re::{
    anyhow, r2d2,
    r2d2_mysql::{self, mysql::prelude::Queryable},
};

pub fn query(
    pool: &r2d2::Pool<r2d2_mysql::MysqlConnectionManager>,
    query: &str,
) -> anyhow::Result<Vec<String>> {
    Ok(pool.get().unwrap().query::<String, _>(query).unwrap())
}

pub fn parse_mysql_database(db_name: &str, options: &rhai::Map) -> EngineResult<Service> {
    for key in ["url"] {
        if !options.contains_key(key) {
            return Err(format!("database {db_name} is missing the '{key}' option.").into());
        }
    }

    let url = options.get("url").unwrap().to_string();
    let connections = u32::try_from(
        options
            .get("connections")
            .unwrap_or(&rhai::Dynamic::from(1))
            .as_int()
            .unwrap(),
    )
    .unwrap();

    let opts = r2d2_mysql::mysql::Opts::from_url(&url).unwrap();
    let builder = r2d2_mysql::mysql::OptsBuilder::from_opts(opts);
    let manager = r2d2_mysql::MysqlConnectionManager::new(builder);

    Ok(Service::MySQLDatabase {
        url,
        pool: r2d2::Pool::builder()
            .max_size(connections)
            .build(manager)
            .unwrap(),
    })
}
