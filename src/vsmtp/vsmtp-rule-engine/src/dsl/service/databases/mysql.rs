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
use mysql::prelude::Queryable;
use vsmtp_common::re::anyhow;

/// A r2d2 connection manager for mysql.
#[derive(Clone, Debug)]
pub struct MySQLConnectionManager {
    params: mysql::Opts,
}

impl MySQLConnectionManager {
    pub fn new(params: mysql::OptsBuilder) -> MySQLConnectionManager {
        MySQLConnectionManager {
            params: mysql::Opts::from(params),
        }
    }
}

impl r2d2::ManageConnection for MySQLConnectionManager {
    type Connection = mysql::Conn;
    type Error = mysql::Error;

    fn connect(&self) -> Result<mysql::Conn, mysql::Error> {
        mysql::Conn::new(self.params.clone())
    }

    fn is_valid(&self, conn: &mut mysql::Conn) -> Result<(), mysql::Error> {
        conn.query("SELECT version()").map(|_: Vec<String>| ())
    }

    fn has_broken(&self, conn: &mut mysql::Conn) -> bool {
        self.is_valid(conn).is_err()
    }
}

pub fn query(
    pool: &r2d2::Pool<MySQLConnectionManager>,
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

    let opts = mysql::Opts::from_url(&url).unwrap();
    let builder = mysql::OptsBuilder::from_opts(opts);
    let manager = MySQLConnectionManager::new(builder);

    Ok(Service::MySQLDatabase {
        url,
        pool: r2d2::Pool::builder()
            .max_size(connections)
            .build(manager)
            .unwrap(),
    })
}
