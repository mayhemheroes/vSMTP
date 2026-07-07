#!/usr/bin/env bash
#
# mayhem/build.sh — build vSMTP cargo-fuzz targets as sanitized libFuzzer binaries
# (OSS-Fuzz Rust path: cargo-fuzz + ASan via RUSTFLAGS) AND the functional test suite.
# Runs inside the commit image (RUST mayhem/Dockerfile) as mayhem in /mayhem.
#
# AIR-GAPPED (SPEC 6.5): the PATCH tier re-runs THIS script OFFLINE. First (online)
# build populates $CARGO_HOME; the re-run resolves from that cache with
# CARGO_NET_OFFLINE=true set by the runtime — so NO --offline here.
#
# RUNTIME PATCHES: vSMTP is a 2022 snapshot. Its fuzz crate is an isolated workspace
# that resolves NEWER rsasl/rhai than the frozen root lock; those + two upstream files
# do not compile on a modern nightly. We patch them AT BUILD TIME ONLY (never committed)
# so the git tree stays purely additive. Patches are idempotent / offline-safe.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"
cd "$SRC"

TRIPLE="x86_64-unknown-linux-gnu"
FUZZ_DIR="fuzz"

echo "=== build-time compatibility patches (in-container only) ==="

python3 - "$SRC/src/vsmtp/vsmtp-rule-engine" <<PYEOF
import sys, re, glob, os
root = sys.argv[1]
for p in glob.glob(f"{root}/**/*.rs", recursive=True):
    s = open(p).read(); orig = s
    s = s.replace("PluginFunction", "PluginFunc")
    def add_imports(m):
        block = m.group(1)
        if "use rhai::plugin::PluginFunc" in s:
            return block
        return block + "\n    use rhai::FuncRegistration;\n    use rhai::plugin::PluginFunc;"
    s = re.sub(r"(#\[rhai::plugin::export_module\]\nmod \w+ \{)", add_imports, s)
    s = s.replace("EvalContext<'_, '_, '_, '_, '_, '_, '_, '_, '_>",
                  "EvalContext<'_, '_, '_, '_, '_, '_>")
    if s != orig:
        open(p, "w").write(s); print("patched", os.path.relpath(p, root))
print("rule-engine rhai patch ok")
PYEOF

python3 - "$SRC/src/vsmtp/vsmtp-server/src/receiver/rsasl_exchange.rs" <<PYEOF
import sys
p = sys.argv[1]
try:
    s = open(p).read()
except FileNotFoundError:
    print("rsasl_exchange.rs absent, skip"); raise SystemExit(0)
s = s.replace(".with_default_mechanisms()\n            .with_defaults()", ".with_defaults()")
s = s.replace("let (state, _) = session", "let state = session")
open(p, "w").write(s); print("rsasl_exchange patch ok")
PYEOF

cargo fetch --manifest-path "$FUZZ_DIR/Cargo.toml" 2>&1 | tail -3 || true

python3 <<PYEOF
import os, re, glob
hits = glob.glob(os.environ["CARGO_HOME"] + "/registry/src/*/rsasl-2.0.1")
if not hits:
    print("rsasl-2.0.1 not found, skip"); raise SystemExit(0)
d = hits[0]; os.system(f"chmod -R u+w {d}")
p = f"{d}/src/context.rs"; s = open(p).read()
s = s.replace("pub fn build_context<'a>(provider: &'a dyn Provider) -> &'a Context<'a>",
              "pub fn build_context<'a>(provider: &'a (dyn Provider + 'a)) -> &'a Context<'a>")
s = s.replace("unsafe { &*(provider as *const dyn Provider as *const Context) }",
              "unsafe { std::mem::transmute(provider) }")
open(p, "w").write(s)
p = f"{d}/src/callback.rs"; s = open(p).read()
s = re.sub(r"fn new_action<'t, 'p, P: Property<'p>>", "fn new_action<'t, P: Property<'a>>", s)
s = re.sub(r"val: &'t mut Tagged<'p, Action<P>>", "val: &'t mut Tagged<'a, Action<P>>", s)
open(p, "w").write(s)
p = f"{d}/src/validate.rs"; s = open(p).read()
s = s.replace("unsafe { &mut *(opt as &mut dyn Erased as *mut dyn Erased as *mut Self) }",
              "unsafe { std::mem::transmute(opt as &mut dyn Erased) }")
open(p, "w").write(s)
print("rsasl-2.0.1 registry patch ok")
PYEOF

# vSMTP's config layer selects the run identity at COMPILE time via option_env!("CI"):
# with CI set it uses the always-present "root" user/group (and skips chown); unset it
# calls users::get_user_by_name("vsmtp").expect(...) which PANICS in the image (no vsmtp
# user) on every input, so the `receiver` and `rules` harnesses never iterate. Build the
# fuzz binaries with CI set so they drive real config/rule-engine/receiver code instead.
# The `receiver`/`rules` harnesses build their config with a RELATIVE spool dir
# ("./tmp/fuzz") whose queue dirs QueueManager::init() creates at runtime. Mayhem mounts
# the image dir READ-ONLY during the real run, so a relative (=> /mayhem/tmp/fuzz) write
# would panic every input and yield 0 edges. Reroot the spool under always-writable /tmp
# at BUILD time only (git tree stays additive; committed harness keeps its relative path).
python3 - "$SRC/$FUZZ_DIR/fuzz_targets" <<'PYRR'
import sys, glob, os
root = sys.argv[1]
for p in glob.glob(os.path.join(root, '*.rs')):
    s = open(p).read(); o = s
    s = s.replace('"./tmp/fuzz"', '"/tmp/vsmtp-fuzz"')
    # quarantine + queue dirs are created under the APP dir (default /var/spool/vsmtp/app,
    # not writable); point it at /tmp too so QueueManager::init() succeeds under read-only /mayhem.
    s = s.replace('.with_default_app()', '.with_app_at_location("/tmp/vsmtp-app")')
    if s != o:
        open(p, 'w').write(s); print('rerooted spool+app ->/tmp in', os.path.basename(p))
print('spool reroot ok')
PYRR

# --- rules-config-once (build-time only; git tree stays additive) -------------------
# The `rules` harness rebuilds the ENTIRE vSMTP Config inside fuzz_target! on EVERY input
# and .validate().unwrap()s it. With a relative spool/app path that panicked per input under
# Mayhem's read-only image mount (edges=0 + a crash defect); the reroot above stops the
# panic, but the config is still rebuilt every iteration, starving the instrumented
# RuleEngine::from_script parser. Rewrite ONLY rules.rs to build the Config exactly ONCE
# (per-pid OnceLock, rerooted under always-writable /tmp, with a minimal on-disk main.vsl so
# the builder never needs a missing relative file) and drop the per-input unwrap so a script
# that fails to compile is normal fuzz behaviour, not a crash. Idempotent + offline-safe.
cat > "$SRC/$FUZZ_DIR/fuzz_targets/rules.rs" <<'RULESRS'
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use vsmtp_config::Config;
use vsmtp_rule_engine::RuleEngine;

fn build_config() -> Arc<Config> {
    let base = std::path::PathBuf::from(format!("/tmp/vsmtp-rules-{}", std::process::id()));
    let spool = base.join("spool");
    let app = base.join("app");
    std::fs::create_dir_all(&spool).ok();
    std::fs::create_dir_all(&app).ok();
    let vsl = base.join("main.vsl");
    let _ = std::fs::write(&vsl, "#{}\n");

    let config = Config::builder()
        .with_version_str("<1.0.0")
        .unwrap()
        .with_hostname()
        .with_default_system()
        .with_ipv4_localhost()
        .with_default_logs_settings()
        .with_spool_dir_and_default_queues(spool.clone())
        .without_tls_support()
        .with_default_smtp_options()
        .with_default_smtp_error_handler()
        .with_default_smtp_codes()
        .without_auth()
        .with_app_at_location(app.clone())
        .with_vsl(vsl.clone())
        .with_default_app_logs()
        .with_system_dns()
        .without_virtual_entries()
        .validate()
        .expect("vSMTP fuzz config build failed");

    Arc::new(config)
}

fn config() -> Arc<Config> {
    static CONFIG: std::sync::OnceLock<Arc<Config>> = std::sync::OnceLock::new();
    CONFIG.get_or_init(build_config).clone()
}

fuzz_target!(|data: &[u8]| {
    if let Ok(script) = std::str::from_utf8(data) {
        let _ = RuleEngine::from_script(config(), script);
    }
});
RULESRS
echo "rewrote rules.rs -> build-config-once (build-time only)"


export CI=true

# OSS-Fuzz Rust libFuzzer+ASan flags. Honor the $SANITIZER_FLAGS contract (SPEC): rustc
# ignores the clang-oriented $SANITIZER_FLAGS, so map the ASan intent to the rustc flag.
# ASan is the default halting sanitizer; an explicit empty SANITIZER_FLAGS still keeps it.
SANITIZER_FLAGS="${SANITIZER_FLAGS:-}"
RUST_SANITIZER="-Zsanitizer=address"
case "$SANITIZER_FLAGS" in
  *address*|"") : ;;  # ASan requested (default) or no override
esac

# Debug-info contract (SPEC 6.2 item 10): Mayhem triage cannot read DWARF >= 4, and LLVM
# default -Cdebuginfo emits DWARF-5, so pin DWARF < 4. Overridable via $RUST_DEBUG_FLAGS
# (the rust arm of the DEBUG_FLAGS contract verify-repo checks). Prebuilt std+asan rlibs
# are additionally strip_debug'd in the Dockerfile so no linked-in DWARF-5 survives.
export RUST_DEBUG_FLAGS="${RUST_DEBUG_FLAGS:--Cdebuginfo=1 -Zdwarf-version=3}"
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing ${RUST_SANITIZER} ${RUST_DEBUG_FLAGS} -Cforce-frame-pointers"

# cc-built C/C++ shims (libfuzzer-sys runtime + krb5/gssapi/rsasl) -> DWARF-3 too.
export CFLAGS="${CFLAGS:-} -gdwarf-3"
export CXXFLAGS="${CXXFLAGS:-} -gdwarf-3"

FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets" >&2; exit 1; }

# Purge cached fuzz-target artifacts: a prior build's objects can retain DWARF-5 and would
# be reused as-is by an incremental rebuild (offline PATCH re-run recompiles from cache).
rm -rf "$FUZZ_DIR/target"

echo "=== cargo fuzz build (image nightly, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"
echo "targets: ${FUZZ_TARGETS[*]}"

for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
done

echo "=== building functional test suite (vsmtp-mail-parser) ==="
# Oracle = vsmtp-mail-parser (the MIME/mail parser the mime_parser + receiver fuzz
# targets drive). We deliberately scope to this crate: it has clean deps, whereas
# vsmtp-config pulls the rule engine -> rhai -> ahash 0.8.0, a 2022-pinned crate that
# uses the since-removed nightly `stdsimd` feature and cannot compile on the image
# nightly. Built with NORMAL flags into a separate dir so ASan does not leak in.
#
# vsmtp-mail-parser uses #[tracing::instrument], which needs tracing's `attributes`
# feature. In the full workspace that feature is unified in from another member; built
# alone it is dropped. Enable it in-container (not committed; idempotent).
python3 - "$SRC/src/vsmtp/vsmtp-mail-parser/Cargo.toml" <<'PYTOML'
import sys
p = sys.argv[1]; s = open(p).read()
old = 'tracing = { version = "0.1.36", default-features = false, features = ["std"] }'
new = 'tracing = { version = "0.1.36", default-features = false, features = ["std", "attributes"] }'
if old in s:
    open(p, "w").write(s.replace(old, new)); print("mail-parser tracing attributes enabled")
else:
    print("tracing dep line unchanged (already patched?)")
PYTOML
# The crate sets #![deny(missing_docs)]; its test-only `pub mod tests;` trips that
# lint in the test build (not the fuzz build). Downgrade the deny for the oracle
# compile only — we run the tests, not lint the docs.
env CARGO_TARGET_DIR="$SRC/target-tests" RUSTFLAGS="--cap-lints=allow" \
    cargo test --no-run \
      -p vsmtp-mail-parser 2>&1 | tail -25
echo "build.sh complete"
