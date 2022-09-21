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
use crate::api::{rule_state::deny, EngineResult, SharedObject, StandardVSLPackage};
use crate::dsl::{
    action::parsing::{create_action, parse_action},
    delegation::parsing::{create_delegation, parse_delegation},
    directives::{Directive, Directives},
    object::parsing::{create_object, parse_object},
    rule::parsing::{create_rule, parse_rule},
    service::{
        parsing::{create_service, parse_service},
        Service,
    },
};
use crate::rule_state::RuleState;
use anyhow::Context;
use rhai::{module_resolvers::FileModuleResolver, packages::Package, Engine, Scope, AST};
use vqueue::{GenericQueueManager, QueueID};
use vsmtp_common::{mail_context::MailContext, state::State, status::Status};
use vsmtp_config::{Config, Resolvers};
use vsmtp_mail_parser::MessageBody;

/// a sharable rhai engine.
/// contains an ast representation of the user's parsed .vsl script files,
/// and modules / packages to create a cheap rhai runtime.
pub struct RuleEngine {
    /// ast built from the user's .vsl files.
    pub(super) ast: AST,
    /// rules & actions registered by the user.
    pub(super) directives: Directives,
    /// vsl's standard rust api.
    pub(super) vsl_native_module: rhai::Shared<rhai::Module>,
    /// vsl's standard rhai api.
    pub(super) vsl_rhai_module: rhai::Shared<rhai::Module>,
    /// rhai's standard api.
    pub(super) std_module: rhai::Shared<rhai::Module>,
    /// a translation of the toml configuration as a rhai Map.
    pub(super) toml_module: rhai::Shared<rhai::Module>,
}

type RuleEngineInput<'a> = either::Either<Option<std::path::PathBuf>, &'a str>;

impl RuleEngine {
    /// creates a new instance of the rule engine, reading all files in the
    /// `script_path` parameter.
    /// if `script_path` is `None`, a warning is emitted and a deny-all script
    /// is loaded.
    ///
    /// # Errors
    /// * failed to register `script_path` as a valid module folder.
    /// * failed to compile or load any script located at `script_path`.
    pub fn new(
        config: std::sync::Arc<Config>,
        input: Option<std::path::PathBuf>,
    ) -> anyhow::Result<Self> {
        Self::new_inner(config, &either::Left(input))
    }

    // NOTE: since a single engine instance is created for each postq emails
    //       no instrument attribute are placed here.
    /// create a rule engine instance from a script.
    ///
    /// # Errors
    ///
    /// * failed to compile the script.
    pub fn from_script(config: std::sync::Arc<Config>, input: &str) -> anyhow::Result<Self> {
        Self::new_inner(config, &either::Right(input))
    }

    #[tracing::instrument(name = "building-rules", skip_all)]
    fn new_inner(
        config: std::sync::Arc<Config>,
        input: &RuleEngineInput<'_>,
    ) -> anyhow::Result<Self> {
        let (server_config, app_config) = (
            serde_json::to_string(&config.server)
                .context("failed to convert the server configuration to json")?,
            serde_json::to_string(&config.app)
                .context("failed to convert the app configuration to json")?,
        );

        tracing::debug!("Building vSL compiler ...");

        let mut compiler = Self::new_compiler(config);

        let toml_module = {
            let mut toml_module = rhai::Module::new();
            toml_module
                .set_var("server", compiler.parse_json(server_config, true)?)
                .set_var("app", compiler.parse_json(app_config, true)?);
            rhai::Shared::new(toml_module)
        };

        let std_module = rhai::packages::StandardPackage::new().as_shared_module();
        let vsl_native_module = StandardVSLPackage::new().as_shared_module();

        compiler
            .register_global_module(std_module.clone())
            .register_static_module("sys", vsl_native_module.clone())
            .register_static_module("toml", toml_module.clone());

        compiler.set_module_resolver(match &input {
            // TODO: handle canonicalization.
            either::Either::Left(Some(path)) => FileModuleResolver::new_with_path_and_extension(
                path.parent().ok_or_else(|| {
                    anyhow::anyhow!(
                        "file '{}' does not have a valid parent directory for rules",
                        path.display()
                    )
                })?,
                "vsl",
            ),
            either::Either::Left(None) | either::Either::Right(_) => {
                FileModuleResolver::new_with_extension("vsl")
            }
        });

        tracing::debug!("Compiling vSL api ...");

        let vsl_rhai_module =
            rhai::Shared::new(Self::compile_api(&compiler).context("failed to compile vsl's api")?);

        compiler.register_global_module(vsl_rhai_module.clone());

        let main_vsl = match &input {
            either::Either::Left(Some(path)) => {
                tracing::info!("Analyzing vSL rules at {path:?}");

                std::fs::read_to_string(&path)
                    .context(format!("failed to read file: '{}'", path.display()))?
            }
            either::Either::Left(None) => {
                tracing::warn!(
                    "No 'main.vsl' provided in the config, the server will deny any incoming transaction by default."
                );
                include_str!("../api/default_rules.rhai").to_string()
            }
            either::Either::Right(script) => (*script).to_string(),
        };

        let ast = compiler
            .compile_into_self_contained(&rhai::Scope::new(), &main_vsl)
            .map_err(|err| anyhow::anyhow!("failed to compile vsl scripts: {err}"))?;

        let directives = Self::extract_directives(&compiler, &ast)?;

        tracing::info!("Done.");

        Ok(Self {
            ast,
            directives,
            vsl_native_module,
            vsl_rhai_module,
            std_module,
            toml_module,
        })
    }

    // FIXME: delegation handling to refactor.
    /// runs all rules from a stage using the current transaction state.
    ///
    /// the `server_address` parameter is used to distinguish logs from each other,
    /// printing the address & port associated with this run session, not the current
    /// context. (because the context could have been pulled from the filesystem when
    /// receiving delegation results)
    /// # Panics
    #[tracing::instrument(name = "rule", skip_all, fields(stage = %smtp_state))]
    pub fn run_when(&self, rule_state: &mut RuleState, smtp_state: State) -> Status {
        let directive_set = if let Some(directive_set) = self.directives.get(&smtp_state) {
            directive_set
        } else {
            tracing::debug!("No rules for the current state, skipping.");
            return Status::Next;
        };

        // check if we need to skip directive execution or resume because of a delegation.
        let directive_set = match rule_state.skipped() {
            Some(Status::DelegationResult) if smtp_state.is_email_received() => {
                if let Some(header) = rule_state
                    .message()
                    .read()
                    .expect("Mutex poisoned")
                    .get_header("X-VSMTP-DELEGATION")
                {
                    let header = vsmtp_mail_parser::get_mime_header("X-VSMTP-DELEGATION", &header);

                    let (stage, directive_name, message_id) =
                        if let (Some(stage), Some(directive_name), Some(message_id)) = (
                            header.args.get("stage"),
                            header.args.get("directive"),
                            header.args.get("id"),
                        ) {
                            (stage, directive_name, message_id)
                        } else {
                            return Status::DelegationResult;
                        };

                    if *stage == smtp_state.to_string() {
                        if let Some(d) = directive_set
                            .iter()
                            .position(|directive| directive.name() == directive_name)
                        {
                            // If delegation results are coming in and that this is the correct
                            // directive that has been delegated, we need to pull
                            // the old context because its state has been lost
                            // when the delegation happened.
                            //
                            // There is however no need to discard the old email because it
                            // will be overridden by the results once it's time to write
                            // in the 'mail' queue.

                            // FIXME: this is only useful for preq, the other processes
                            //        already fetch the old context.
                            match rule_state
                                .server
                                .queue_manager
                                .get_ctx(&QueueID::Delegated, message_id)
                            {
                                Ok(mut context) => {
                                    context.metadata.skipped = None;
                                    *rule_state.context().write().unwrap() = context;
                                }
                                Err(error) => {
                                    tracing::error!(%error, "Failed to get old email context from working queue after a delegation");
                                }
                            }

                            tracing::debug!("Resuming rule '{directive_name}' after delegation.",);

                            rule_state.resume();
                            &directive_set[d..]
                        } else {
                            return Status::DelegationResult;
                        }
                    } else {
                        return Status::DelegationResult;
                    }
                } else {
                    return Status::DelegationResult;
                }
            }
            Some(status) => return (*status).clone(),
            None => &directive_set[..],
        };

        #[allow(clippy::single_match_else)]
        match self.execute_directives(rule_state, directive_set, smtp_state) {
            Ok(status) => {
                tracing::debug!(?status);

                if status.is_finished() {
                    tracing::debug!(
                        "The rule engine will skip all rules because of the previous result."
                    );
                    rule_state.skipping(status.clone());
                }

                status
            }
            Err(error) => {
                tracing::error!(%error);
                // TODO: keep the error for the `deferred` info.

                // if an error occurs, the engine denies the connection by default.
                rule_state.skipping(deny());
                deny()
            }
        }
    }

    /// Instantiate a [`RuleState`] and run it for the only `state` provided
    ///
    /// # Return
    ///
    /// A tuple with the mail context, body, result status, and skip status.
    #[must_use]
    pub fn just_run_when(
        &self,
        state: State,
        config: std::sync::Arc<Config>,
        resolvers: std::sync::Arc<Resolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
        mail_context: MailContext,
        mail_message: MessageBody,
    ) -> (MailContext, MessageBody, Status, Option<Status>) {
        let mut rule_state = RuleState::with_context(
            config,
            resolvers,
            queue_manager,
            self,
            mail_context,
            mail_message,
        );

        let result = self.run_when(&mut rule_state, state);

        let (mail_context, mail_message, skipped) = rule_state
            .take()
            .expect("should not have strong reference here");

        (mail_context, mail_message, result, skipped)
    }

    #[allow(clippy::similar_names)]
    fn execute_directives(
        &self,
        state: &mut RuleState,
        directives: &[Directive],
        stage: State,
    ) -> EngineResult<Status> {
        let mut status = Status::Next;

        for directive in directives {
            tracing::debug!("Executing {} '{}'", directive.as_ref(), directive.name());
            status = directive.execute(state, &self.ast, stage)?;

            if status != Status::Next {
                break;
            }
        }

        Ok(status)
    }

    /// create a rhai engine to compile all scripts with vsl's configuration.
    #[must_use]
    pub fn new_compiler(config: std::sync::Arc<Config>) -> rhai::Engine {
        let mut engine = Engine::new();

        // NOTE: on_parse_token is not deprecated, just subject to change in future releases.
        #[allow(deprecated)]
        engine.on_parse_token(|token, _, _| {
            match token {
                // remap 'is' operator to '==', it's easier than creating a new operator.
                // NOTE: warning => "is" is a reserved keyword in rhai's tokens, maybe change to "eq" ?
                rhai::Token::Reserved(s) if &*s == "is" => rhai::Token::EqualsTo,
                rhai::Token::Identifier(s) if &*s == "not" => rhai::Token::NotEqualsTo,
                // Pass through all other tokens unchanged
                _ => token,
            }
        });

        engine
            .disable_symbol("eval")
            .register_custom_syntax_raw("rule", parse_rule, true, create_rule)
            .register_custom_syntax_raw("action", parse_action, true, create_action)
            .register_custom_syntax_raw("delegate", parse_delegation, true, create_delegation)
            .register_custom_syntax_raw("object", parse_object, true, create_object)
            .register_custom_syntax_raw(
                "service",
                parse_service,
                true,
                move |context: &mut rhai::EvalContext<'_, '_, '_, '_, '_, '_, '_, '_, '_>,
                      input: &[rhai::Expression<'_>]| {
                    create_service(context, input, &config)
                },
            )
            .register_iterator::<Vec<vsmtp_common::Address>>()
            .register_iterator::<Vec<SharedObject>>();

        engine.set_fast_operators(false);

        engine
    }

    /// compile vsl's api into a module.
    ///
    /// # Errors
    /// * Failed to compile the API.
    /// * Failed to create a module from the API.
    pub fn compile_api(engine: &rhai::Engine) -> anyhow::Result<rhai::Module> {
        let ast = engine
            .compile_scripts_with_scope(
                &rhai::Scope::new(),
                [
                    // objects.
                    include_str!("../api/codes.rhai"),
                    include_str!("../api/networks.rhai"),
                    // functions.
                    include_str!("../api/auth.rhai"),
                    include_str!("../api/connection.rhai"),
                    include_str!("../api/delivery.rhai"),
                    include_str!("../api/envelop.rhai"),
                    include_str!("../api/getters.rhai"),
                    include_str!("../api/internal.rhai"),
                    include_str!("../api/message.rhai"),
                    include_str!("../api/security.rhai"),
                    include_str!("../api/services.rhai"),
                    include_str!("../api/status.rhai"),
                    include_str!("../api/transaction.rhai"),
                    include_str!("../api/types.rhai"),
                    include_str!("../api/utils.rhai"),
                ],
            )
            .context("failed to compile vsl's api")?;

        rhai::Module::eval_ast_as_new(rhai::Scope::new(), &ast, engine)
            .context("failed to create a module from vsl's api.")
    }

    // FIXME: could be easily refactored.
    //        every `ok_or_else` could be replaced by an unwrap here.
    /// extract rules & actions from the main vsl script.
    fn extract_directives(engine: &rhai::Engine, ast: &rhai::AST) -> anyhow::Result<Directives> {
        let mut scope = Scope::new();
        scope
            .push("date", ())
            .push("time", ())
            .push_constant("CTX", ())
            .push_constant("SRV", ());

        let raw_directives = engine
            .eval_ast_with_scope::<rhai::Map>(&mut scope, ast)
            .context("failed to compile your rules.")?;

        let mut directives = Directives::new();

        for (stage, directive_set) in raw_directives {
            let stage = match State::try_from(stage.as_str()) {
                Ok(stage) => stage,
                Err(_) => anyhow::bail!("the '{stage}' smtp stage does not exist."),
            };

            let directive_set = directive_set
                .try_cast::<rhai::Array>()
                .ok_or_else(|| {
                    anyhow::anyhow!("the stage '{stage}' must be declared using the array syntax")
                })?
                .into_iter()
                .map(|rule| {
                    let map = rule.try_cast::<rhai::Map>().unwrap();
                    let directive_type = map
                        .get("type")
                        .ok_or_else(|| anyhow::anyhow!("a directive in stage '{stage}' does not have a valid type"))?
                        .to_string();

                        let name = map
                        .get("name")
                        .ok_or_else(|| anyhow::anyhow!("a directive in stage '{stage}' does not have a name"))?
                        .to_string();

                    let pointer = map
                        .get("evaluate")
                        .ok_or_else(|| anyhow::anyhow!("the directive '{stage}' in stage '{name}' does not have an evaluation function"))?
                        .clone()
                        .try_cast::<rhai::FnPtr>()
                        .ok_or_else(|| anyhow::anyhow!("the evaluation field for the directive '{stage}' in stage '{name}' must be a function pointer"))?;

                    let directive =
                        match directive_type.as_str() {
                            "rule" => Directive::Rule { name, pointer },
                            "action" => Directive::Action { name, pointer },
                            "delegate" => {

                                if !stage.is_email_received() {
                                    anyhow::bail!("invalid delegation '{name}' in stage '{stage}': delegation directives are available from the 'postq' stage and onwards.");
                                }

                                let service = map
                                    .get("service")
                                    .ok_or_else(|| anyhow::anyhow!("the delegation '{name}' in stage '{stage}' does not have a service to delegate processing to"))?
                                    .clone()
                                    .try_cast::<std::sync::Arc<Service>>()
                                    .ok_or_else(|| anyhow::anyhow!("the field after the 'delegate' keyword in the directive '{name}' in stage '{stage}' must be a smtp service"))?;

                                Directive::Delegation { name, pointer, service }
                            },
                            unknown => anyhow::bail!("unknown directive type '{unknown}' called '{name}'"),
                        };

                    Ok(directive)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            directives.insert(stage, directive_set);
        }

        let names = directives
            .iter()
            .flat_map(|(_, d)| d)
            .map(crate::dsl::directives::Directive::name)
            .collect::<Vec<_>>();

        // TODO: refactor next loop with templated function 'find_duplicate'.
        for (idx, name) in names.iter().enumerate() {
            for other in &names[idx + 1..] {
                if other == name {
                    anyhow::bail!("found duplicate rule '{name}': a rule must have a unique name",);
                }
            }
        }

        Ok(directives)
    }
}
