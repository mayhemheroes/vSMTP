<div align="center">
  <a href="https://www.viridit.com/#gh-light-mode-only">
    <img src="https://github.com/viridIT/vSMTP/blob/main/assets/vsmtp-black-nobckgrd.png"
      alt="vSMTP" />
  </a>
  <a href="https://www.viridit.com/#gh-dark-mode-only">
    <img src="https://github.com/viridIT/vSMTP/blob/main/assets/vsmtp-white-nobckgrd.png"
      alt="vSMTP" />
  </a>
</div>

<div align="center">
  <a href="https://www.viridit.com">
    <img src="https://img.shields.io/badge/visit-viridit.com-green?logo=internet"
      alt="website" />
  </a>
  <a href="https://vsmtp.rs">
    <img src="https://img.shields.io/badge/read-vsmtp.rs-yellowgreen"
      alt="documentation" />
  </a>
  <a href="https://discord.gg/N8JGBRBshf">
    <img src="https://img.shields.io/badge/join-discord-blue?logo=discord&color=blueviolet"
      alt="discord" />
  </a>
</div>

<div align="center">
  <a href="https://www.whatrustisit.com">
    <img src="https://img.shields.io/badge/rustc-1.62.1%2B-informational.svg?logo=rust"
      alt="Rustc Version 1.62.1" />
  </a>
  <a href="https://docs.rs/vsmtp">
    <img src="https://docs.rs/vsmtp/badge.svg"
      alt="docs" />
  </a>
  <a href="https://www.gnu.org/licenses/gpl-3.0">
    <img src="https://img.shields.io/github/license/viridIT/vSMTP?color=blue"
      alt="License GPLv3" />
  </a>
</div>

<div align="center">
  <a href="https://github.com/viridIT/vSMTP/actions/workflows/ci.yaml">
    <img src="https://github.com/viridIT/vSMTP/actions/workflows/ci.yaml/badge.svg"
      alt="CI" />
  </a>
  <a href="https://app.codecov.io/gh/viridIT/vSMTP">
    <img src="https://img.shields.io:/codecov/c/gh/viridIT/vSMTP?logo=codecov"
      alt="coverage" />
  </a>
  <a href="https://deps.rs/repo/github/viridIT/vSMTP">
    <img src="https://deps.rs/repo/github/viridIT/vSMTP/status.svg"
      alt="dependency status" />
  </a>
</div>

<div align="center">
  <a href="https://github.com/viridIT/vSMTP/releases">
    <img src="https://img.shields.io/github/v/release/viridIT/vSMTP?logo=github"
      alt="Latest Release">
  </a>
  <a href="https://crates.io/crates/vsmtp">
    <img src="https://img.shields.io/crates/v/vsmtp.svg"
      alt="Crates.io" />
  </a>
  <a href="https://hub.docker.com/repository/docker/viridit/vsmtp">
    <img src="https://img.shields.io/docker/pulls/viridit/vsmtp?logo=docker"
      alt="Docker Pulls" >
  </a>
</div>

---

# What is vSMTP ?

vSMTP is a next-gen *Mail Transfer Agent* (MTA), faster, safer and greener.

- It is 100% built in [Rust](https://www.rust-lang.org).
- It is lighting fast.
- It is modular and highly customizable.
- It has a complete filtering system.
- It is actively developed and maintained.

## Faster, Safer, Greener

While optimizing IT resources becomes an increasing challenge, computer attacks remain a constant problem.

Every day, over 300 billion emails are sent and received in the world. Billions of attachments are processed, analyzed and delivered, contributing to the increase in greenhouse gas emissions.

To meet these challenges, viridIT is developing a new technology of email gateways, also called vSMTP.

Follow us on [viridit.com](https://viridit.com)

## Filtering

vSMTP enable you to create complex set of rules to filter your emails using [vSMTP's scripting language (vsl)](https://vsmtp.rs/reference/vSL/vsl.html) based on [Rhai](https://github.com/rhaiscript/rhai).
You can:

- inspect / modify the content of incoming emails.
- forward and deliver emails locally or remotely.
- connect to databases.
- run commands.
- quarantine emails.

and much more.

```js
// -- database.vsl
// here we declare our services.
// connect to a database with the csv format.
service greylist db:csv = #{
  connector: "/db/greylist.csv",
  access: "O_RDWR",
  refresh: "always",
  delimiter: ',',
};
```

```js
// -- main.vsl
// here we declare our rules for filtering.

import "database" as db;

#{
  // hook on the 'mail from' stage. (when the server receives the `MAIL FROM:` command)
  mail: [
    rule "greylist" || {

      let sender = mail_from();

      // is the user in our greylist ?
      if db::greylist.get(sender) == [] {
        // it does not, we add the address to the database, then deny the email.
        db::greylist.set([ sender ]);
        // close the connection with a built in "451 - 4.7.1" error code.
        deny(code_greylist)
      } else {
        // it is, we accept the email.
        accept()
      }
    }
  ],
}
```

Check out the [api](https://github.com/viridIT/vSMTP/tree/main/src/vsmtp/vsmtp-rule-engine/src/api) folder to get a view of what you can do with vsl.

## Benchmarks

Comparison between Postfix 3.6.4 & vSMTP 1.0.1 performances, performed on a Ubuntu 22.04 LTS running with an AMD Ryzen 5 5600X 6-Core Processor.

<div align="center">
  <a href="https://www.viridit.com/#gh-light-mode-only">
    <img width="70%" height="70%" src="https://github.com/viridIT/vSMTP/blob/develop/assets/tp-100k-white.png"
      alt="100kb messages throughput example" />
  </a>
  <a href="https://www.viridit.com/#gh-dark-mode-only">
    <img width="70%" height="70%" src="https://github.com/viridIT/vSMTP/blob/develop/assets/tp-100k-black.png"
      alt="100kb messages throughput example" />
  </a>
</div>

Check out the [benchmarks readme](./benchmarks/README.md#benchmarks) to get reproducible examples.

## Documentation

For documentation please consult the [vBook](https://vsmtp.rs), the online reference and user guide for vSMTP.

To stay tuned, ask questions and get in-depth answers feel free to join our [Discord](https://discord.gg/N8JGBRBshf) server.
You can also open GitHub [discussions](https://github.com/viridIT/vSMTP/discussions).

## Roadmap

> vSMTP is currently under development and not yet ready for production use.

The next releases "1.3.x" will focus on SQL databases support & DMARC. You can find more information about the project agenda in [Milestones](https://github.com/viridIT/vSMTP/milestones).

Check out updates history in [Changelogs](https://github.com/viridIT/vSMTP/blob/develop/CHANGELOG.md).

A guideline about contributing to vSMTP can be found in the [contributing](CONTRIBUTING.md) section.

## Commercial

For any question related to commercial, licensing, etc. you can [contact us] on our website.

[contact us]: https://www.viridit.com/contact

## License

The standard version of vSMTP is free and under an Open Source license.

It is provided as usual without any warranty. Please refer to the [license](https://github.com/viridIT/vSMTP/blob/main/LICENSE) for further information.
