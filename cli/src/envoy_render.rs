//! Assemble the miner's Envoy config from `image/envoy/`.
//!
//! `base.yaml` holds everything shared: the listeners, the attestation route,
//! the catch-all, the loopback clusters and the data-plane Lua filter. Each
//! file in `upstreams/` holds one upstream's routes, clusters and key-slot
//! settings. See `image/envoy/upstreams/README.md` for the file format.
//!
//! Rendering runs inside the TEE at container start (`start.sh` calls the
//! hidden `gmcli render-envoy`), in three steps:
//!
//! 1. Replace every `__GM_<NAME>__` token in each file's text with the
//!    `GM_<NAME>` environment variable, in one left-to-right pass. The pass
//!    never rescans an inserted value, so a node secret shaped like a token
//!    stays an inert literal. An unset variable is an error, not an empty
//!    string: a missing value must stop the render, not ship a blank host.
//! 2. Parse the files as YAML and splice each upstream's routes and clusters into
//!    `base.yaml` at the `gm:upstream-routes` / `gm:upstream-clusters`
//!    markers, adding the gm-internal header strip list to every upstream
//!    route.
//! 3. Build the Lua `slot_config` table from the upstreams' `slots` blocks and
//!    the `GM_<PROVIDER>_SLOT_IDS` variables `gmcli slot-env` exported.
//!
//! The result is written as JSON (see [`render`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{bail, Context as _, Result};
use serde::Deserialize;
use serde_yaml_ng::Value;

const ROUTES_MARKER: &str = "gm:upstream-routes";
const CLUSTERS_MARKER: &str = "gm:upstream-clusters";
const SLOT_CONFIG_TOKEN: &str = "SLOT_CONFIG";

/// Headers every upstream route removes before forwarding. The Lua filter
/// already strips `x-gm-*` except the route discriminator; the route-level
/// list is the second layer, and the only one that removes `x-gm-provider`.
const GM_INTERNAL_HEADERS: [&str; 6] = [
    "x-gm-request-id",
    "x-gm-gateway-sig",
    "x-gm-product",
    "x-gm-node-key",
    "x-gm-provider",
    "x-gm-upstream-slot",
];

/// Key-slot settings for one upstream, rendered into the Lua `slot_config`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Slots {
    direct_env: String,
    #[serde(default)]
    cloud: bool,
    #[serde(default)]
    disabled: bool,
    auth_header: Option<String>,
    #[serde(default)]
    auth_prefix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamFile {
    slots: Option<Slots>,
    #[serde(default)]
    routes: Vec<Value>,
    #[serde(default)]
    clusters: Vec<Value>,
}

struct Upstream {
    provider: String,
    file: UpstreamFile,
}

/// Render the full Envoy config from `template_dir`.
///
/// `selections` picks one variant for each provider that ships variant files
/// (`anthropic.foundry.yaml` is selected by `("anthropic", "foundry")`).
/// `env` resolves `GM_*` variables; production passes `std::env::var`.
///
/// # Errors
/// Returns an error when a file is missing or malformed, a token has no
/// variable, a selection matches no file, or a marker is absent.
pub fn render(
    template_dir: &Path,
    selections: &BTreeMap<String, String>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<String> {
    let upstreams = load_upstreams(&template_dir.join("upstreams"), selections, env)?;
    let slot_config = slot_config_lua(&upstreams, env);
    let base_env = |name: &str| {
        if name == format!("GM_{SLOT_CONFIG_TOKEN}") {
            Some(slot_config.clone())
        } else {
            env(name)
        }
    };
    let base_path = template_dir.join("base.yaml");
    let mut base = parse_rendered(&base_path, &base_env)?;

    let mut routes = Vec::new();
    let mut clusters = Vec::new();
    for upstream in upstreams {
        for mut route in upstream.file.routes {
            add_internal_header_strip(&mut route, &upstream.provider)?;
            routes.push(route);
        }
        clusters.extend(upstream.file.clusters);
    }
    splice(&mut base, ROUTES_MARKER, routes)?;
    splice(&mut base, CLUSTERS_MARKER, clusters)?;
    // JSON, not YAML: every string is quoted, so no scalar can be retyped on
    // the way into Envoy (unquoted YAML turns `2023-06-01` into a date and
    // `on` into a bool). Envoy's YAML loader reads JSON as-is.
    serde_json::to_string_pretty(&base).context("serialize rendered Envoy config")
}

fn load_upstreams(
    dir: &Path,
    selections: &BTreeMap<String, String>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<Upstream>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "yaml") {
            names.push(path);
        }
    }
    names.sort();

    let mut variant_providers = BTreeSet::new();
    let mut selected = BTreeSet::new();
    let mut providers = BTreeSet::new();
    let mut upstreams = Vec::new();
    for path in names {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .with_context(|| format!("non-UTF-8 upstream file name {}", path.display()))?;
        let provider = match stem.split_once('.') {
            None => stem,
            Some((provider, variant)) => {
                variant_providers.insert(provider.to_owned());
                if selections.get(provider).map(String::as_str) != Some(variant) {
                    continue;
                }
                selected.insert(provider.to_owned());
                provider
            }
        };
        if !providers.insert(provider.to_owned()) {
            bail!("{provider} has more than one upstream file selected");
        }
        let text = std::fs::read_to_string(&path)?;
        let file: UpstreamFile = serde_yaml_ng::from_str(&substitute(&text, env, &path)?)
            .with_context(|| format!("parse {}", path.display()))?;
        if let Some(slots) = &file.slots {
            if !slots.cloud && !slots.disabled && slots.auth_header.is_none() {
                bail!(
                    "{}: a direct upstream's slots need an auth_header",
                    path.display()
                );
            }
        }
        upstreams.push(Upstream {
            provider: provider.to_owned(),
            file,
        });
    }
    check_selections(selections, &variant_providers, &selected)?;
    Ok(upstreams)
}

fn check_selections(
    selections: &BTreeMap<String, String>,
    variant_providers: &BTreeSet<String>,
    selected: &BTreeSet<String>,
) -> Result<()> {
    for (provider, variant) in selections {
        if !selected.contains(provider) {
            bail!("no upstream file {provider}.{variant}.yaml for --select {provider}={variant}");
        }
    }
    for provider in variant_providers {
        if !selections.contains_key(provider) {
            bail!("{provider} ships variant files; pass --select {provider}=<variant>");
        }
    }
    Ok(())
}

fn parse_rendered(path: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Value> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_yaml_ng::from_str(&substitute(&text, env, path)?)
        .with_context(|| format!("parse {}", path.display()))
}

/// Replace each `__GM_<NAME>__` with `GM_<NAME>` in one pass. Inserted values
/// are never rescanned.
fn substitute(text: &str, env: &dyn Fn(&str) -> Option<String>, path: &Path) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("__GM_") {
        let after = &rest[start + 2..];
        let Some(len) = after.find("__") else {
            break;
        };
        let name = &after[..len];
        if !name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            out.push_str(&rest[..start + 2]);
            rest = after;
            continue;
        }
        let Some(value) = env(name) else {
            bail!("{} uses __{name}__ but {name} is not set", path.display());
        };
        out.push_str(&rest[..start]);
        out.push_str(&value);
        rest = &after[len + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn add_internal_header_strip(route: &mut Value, provider: &str) -> Result<()> {
    let Value::Mapping(map) = route else {
        bail!("a route in upstreams/{provider}*.yaml is not a mapping");
    };
    let key = Value::from("request_headers_to_remove");
    let mut headers = match map.remove(&key) {
        None => Vec::new(),
        Some(Value::Sequence(existing)) => existing,
        Some(_) => bail!("{provider}: request_headers_to_remove must be a list"),
    };
    for header in GM_INTERNAL_HEADERS {
        let header = Value::from(header);
        if !headers.contains(&header) {
            headers.push(header);
        }
    }
    map.insert(key, Value::Sequence(headers));
    Ok(())
}

/// Replace the one list item equal to `marker` with `items`.
fn splice(root: &mut Value, marker: &str, items: Vec<Value>) -> Result<()> {
    let marker_value = Value::from(marker);
    let mut found = 0;
    visit_sequences(root, &mut |seq| {
        found += seq.iter().filter(|item| **item == marker_value).count();
    });
    if found != 1 {
        bail!("base.yaml must contain `- {marker}` exactly once (found {found})");
    }
    let mut items = Some(items);
    visit_sequences(root, &mut |seq| {
        if let Some(pos) = seq.iter().position(|item| *item == marker_value) {
            seq.splice(pos..=pos, items.take().unwrap_or_default());
        }
    });
    Ok(())
}

fn visit_sequences(value: &mut Value, visit: &mut dyn FnMut(&mut Vec<Value>)) {
    match value {
        Value::Sequence(seq) => {
            visit(seq);
            for item in seq {
                visit_sequences(item, visit);
            }
        }
        Value::Mapping(map) => {
            for (_, item) in map.iter_mut() {
                visit_sequences(item, visit);
            }
        }
        Value::Tagged(tagged) => visit_sequences(&mut tagged.value, visit),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// The Lua `slot_config` table, on one line so it drops into the filter's
/// block scalar without re-indentation.
fn slot_config_lua(upstreams: &[Upstream], env: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::from("{");
    for upstream in upstreams {
        let Some(slots) = &upstream.file.slots else {
            continue;
        };
        let prefix = format!("GM_{}", upstream.provider.to_ascii_uppercase());
        let ids = env(&format!("{prefix}_SLOT_IDS")).unwrap_or_default();
        let ids: Vec<&str> = ids.split(';').filter(|id| !id.is_empty()).collect();
        let default_env = if ids.is_empty() {
            "nil".to_owned()
        } else {
            lua_string(&format!("{prefix}_KEY_SLOT_1"))
        };
        let mut slot_map = String::from("{");
        for (idx, id) in ids.iter().enumerate() {
            let sep = if idx == 0 { "" } else { ", " };
            let env_name = format!("{prefix}_KEY_SLOT_{}", idx + 1);
            let _ = write!(
                slot_map,
                "{sep}[{}] = {}",
                lua_string(id),
                lua_string(&env_name)
            );
        }
        slot_map.push('}');
        let auth_header = slots
            .auth_header
            .as_deref()
            .map_or("nil".to_owned(), lua_string);
        let _ = write!(
            out,
            "[{}] = {{cloud = {}, disabled = {}, direct_env = {}, default_env = {default_env}, \
             slots = {slot_map}, auth_header = {auth_header}, auth_prefix = {}}}, ",
            lua_string(&upstream.provider),
            slots.cloud,
            slots.disabled,
            lua_string(&slots.direct_env),
            lua_string(&slots.auth_prefix),
        );
    }
    out.push('}');
    out
}

fn lua_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_ascii_control() => {
                let _ = write!(out, "\\{:03}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    const BASE: &str = r#"lua: |
  local expected = "__GM_NODE_SECRET__"
  local slot_config = __GM_SLOT_CONFIG__
routes:
  - name: first
  - gm:upstream-routes
  - name: catch-all
clusters:
  - gm:upstream-clusters
"#;

    const DIRECT: &str = r#"slots:
  direct_env: ACME_API_KEY
  auth_header: authorization
  auth_prefix: "Bearer "
routes:
  - name: acme
    request_headers_to_add:
      - value: "2023-06-01"
    request_headers_to_remove:
      - x-api-key
      - x-gm-provider
clusters:
  - name: acme
    host: __GM_ACME_HOST__
"#;

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new(base: &str, upstreams: &[(&str, &str)]) -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            std::fs::create_dir(dir.path().join("upstreams")).expect("upstreams dir");
            std::fs::write(dir.path().join("base.yaml"), base).expect("base");
            for (name, body) in upstreams {
                std::fs::write(dir.path().join("upstreams").join(name), body).expect("upstream");
            }
            Self { dir }
        }

        fn render(&self, selections: &[(&str, &str)], vars: &[(&str, &str)]) -> Result<String> {
            let selections = selections
                .iter()
                .map(|(provider, variant)| ((*provider).to_owned(), (*variant).to_owned()))
                .collect();
            let vars: BTreeMap<String, String> = vars
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect();
            render(self.dir.path(), &selections, &|name| {
                vars.get(name).cloned()
            })
        }
    }

    const VARS: &[(&str, &str)] = &[
        ("GM_NODE_SECRET", "secret-0001"),
        ("GM_ACME_HOST", "api.acme.test"),
    ];

    fn parsed(rendered: &str) -> serde_json::Value {
        serde_json::from_str(rendered).expect("rendered output is JSON")
    }

    /// The rendered `slot_config`, with the Lua state that owns it.
    fn lua_config(rendered: &str) -> (mlua::Lua, mlua::Table) {
        let lua = mlua::Lua::new();
        let source = parsed(rendered)["lua"].as_str().expect("lua").to_owned();
        let config = lua
            .load(format!("{source}\nreturn slot_config"))
            .eval()
            .expect("rendered Lua runs");
        (lua, config)
    }

    #[test]
    fn splices_upstream_routes_between_base_routes_and_adds_internal_strip() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let out = parsed(&fixture.render(&[], VARS).expect("render"));

        let names: Vec<&str> = out["routes"]
            .as_array()
            .expect("routes")
            .iter()
            .map(|route| route["name"].as_str().expect("name"))
            .collect();
        assert_eq!(names, ["first", "acme", "catch-all"]);
        let removed = &out["routes"][1]["request_headers_to_remove"];
        let expected: Vec<&str> = ["x-api-key", "x-gm-provider"]
            .into_iter()
            .chain(
                GM_INTERNAL_HEADERS
                    .into_iter()
                    .filter(|h| *h != "x-gm-provider"),
            )
            .collect();
        assert_eq!(*removed, serde_json::json!(expected));
        assert_eq!(out["clusters"][0]["host"], "api.acme.test");
    }

    #[test]
    fn base_routes_do_not_get_the_internal_strip() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let out = parsed(&fixture.render(&[], VARS).expect("render"));
        assert!(out["routes"][0].get("request_headers_to_remove").is_none());
    }

    #[test]
    fn date_shaped_strings_stay_strings() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let rendered = fixture.render(&[], VARS).expect("render");
        assert!(rendered.contains(r#""value": "2023-06-01""#), "{rendered}");
    }

    #[test]
    fn unset_token_names_the_file_and_variable() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let err = fixture
            .render(&[], &[("GM_NODE_SECRET", "s")])
            .expect_err("GM_ACME_HOST is unset");
        let message = format!("{err:#}");
        assert!(message.contains("acme.yaml"), "{message}");
        assert!(message.contains("GM_ACME_HOST is not set"), "{message}");
    }

    #[test]
    fn empty_value_is_allowed() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let out = fixture
            .render(&[], &[("GM_NODE_SECRET", ""), ("GM_ACME_HOST", "h")])
            .expect("render");
        assert!(parsed(&out)["lua"]
            .as_str()
            .expect("lua")
            .contains(r#"local expected = """#));
    }

    #[test]
    fn inserted_values_are_never_rescanned() {
        // Calibration: a rescanning substitute() expands the secret into the
        // Lua table and this fails.
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let out = fixture
            .render(
                &[],
                &[
                    ("GM_NODE_SECRET", "__GM_SLOT_CONFIG__"),
                    ("GM_ACME_HOST", "h"),
                ],
            )
            .expect("render");
        assert!(parsed(&out)["lua"]
            .as_str()
            .expect("lua")
            .contains(r#"local expected = "__GM_SLOT_CONFIG__""#));
    }

    #[test]
    fn lowercase_double_underscore_text_is_left_alone() {
        let fixture = Fixture::new(
            "lua: \"__GM_x__ __GM_\"\nroutes: [gm:upstream-routes]\nclusters: [gm:upstream-clusters]\n",
            &[],
        );
        let out = parsed(&fixture.render(&[], &[]).expect("render"));
        assert_eq!(out["lua"], "__GM_x__ __GM_");
    }

    #[test]
    fn slot_config_maps_each_exported_slot_to_its_env_var() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let mut vars = VARS.to_vec();
        vars.push(("GM_ACME_SLOT_IDS", "AAAA;BBBB"));
        let (_lua, config) = lua_config(&fixture.render(&[], &vars).expect("render"));
        let acme: mlua::Table = config.get("acme").expect("acme entry");
        let slots: mlua::Table = acme.get("slots").expect("slots");
        assert_eq!(
            slots.get::<String>("AAAA").expect("A"),
            "GM_ACME_KEY_SLOT_1"
        );
        assert_eq!(
            slots.get::<String>("BBBB").expect("B"),
            "GM_ACME_KEY_SLOT_2"
        );
        assert_eq!(
            acme.get::<String>("default_env").expect("default"),
            "GM_ACME_KEY_SLOT_1"
        );
        assert_eq!(
            acme.get::<String>("direct_env").expect("direct"),
            "ACME_API_KEY"
        );
        assert_eq!(
            acme.get::<String>("auth_header").expect("header"),
            "authorization"
        );
        assert_eq!(
            acme.get::<String>("auth_prefix").expect("prefix"),
            "Bearer "
        );
        assert!(!acme.get::<bool>("cloud").expect("cloud"));
    }

    #[test]
    fn slot_config_without_exported_slots_falls_back_to_direct_env() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let (_lua, config) = lua_config(&fixture.render(&[], VARS).expect("render"));
        let acme: mlua::Table = config.get("acme").expect("acme entry");
        assert!(acme
            .get::<Option<String>>("default_env")
            .expect("default")
            .is_none());
        assert_eq!(
            acme.get::<mlua::Table>("slots").expect("slots").raw_len(),
            0
        );
    }

    #[test]
    fn slot_ids_are_escaped_as_lua_strings() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let mut vars = VARS.to_vec();
        vars.push(("GM_ACME_SLOT_IDS", "a\"b\\c\nd"));
        let (_lua, config) = lua_config(&fixture.render(&[], &vars).expect("render"));
        let acme: mlua::Table = config.get("acme").expect("acme entry");
        let slots: mlua::Table = acme.get("slots").expect("slots");
        assert_eq!(
            slots.get::<String>("a\"b\\c\nd").expect("escaped id"),
            "GM_ACME_KEY_SLOT_1"
        );
    }

    #[test]
    fn upstream_without_slots_has_no_slot_config_entry() {
        let fixture = Fixture::new(BASE, &[("bench.yaml", "routes: [{name: bench}]\n")]);
        let (_lua, config) = lua_config(&fixture.render(&[], VARS).expect("render"));
        assert!(config
            .get::<Option<mlua::Table>>("bench")
            .expect("lookup")
            .is_none());
    }

    const CLOUD: &str = "slots: {direct_env: ACME_API_KEY, cloud: true}\nroutes: [{name: cloud}]\n";

    #[test]
    fn selection_picks_one_variant_file() {
        let fixture = Fixture::new(
            BASE,
            &[("acme.direct.yaml", DIRECT), ("acme.cloud.yaml", CLOUD)],
        );
        let out = parsed(&fixture.render(&[("acme", "cloud")], VARS).expect("render"));
        assert_eq!(out["routes"][1]["name"], "cloud");
        assert_eq!(out["routes"].as_array().expect("routes").len(), 3);
        let (_lua, config) =
            lua_config(&fixture.render(&[("acme", "cloud")], VARS).expect("render"));
        let acme: mlua::Table = config.get("acme").expect("acme entry");
        assert!(acme.get::<bool>("cloud").expect("cloud"));
    }

    #[test]
    fn variant_provider_without_selection_is_an_error() {
        let fixture = Fixture::new(
            BASE,
            &[("acme.direct.yaml", DIRECT), ("acme.cloud.yaml", CLOUD)],
        );
        let err = fixture.render(&[], VARS).expect_err("no selection");
        assert!(
            format!("{err}").contains("--select acme=<variant>"),
            "{err}"
        );
    }

    #[test]
    fn selection_without_a_matching_file_is_an_error() {
        let fixture = Fixture::new(BASE, &[("acme.direct.yaml", DIRECT)]);
        let err = fixture
            .render(&[("acme", "azure")], VARS)
            .expect_err("no file");
        assert!(format!("{err}").contains("acme.azure.yaml"), "{err}");
    }

    #[test]
    fn plain_and_variant_file_for_one_provider_is_an_error() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT), ("acme.cloud.yaml", CLOUD)]);
        let err = fixture
            .render(&[("acme", "cloud")], VARS)
            .expect_err("duplicate");
        assert!(
            format!("{err}").contains("more than one upstream file"),
            "{err}"
        );
    }

    #[test]
    fn direct_slots_without_auth_header_are_rejected() {
        let fixture = Fixture::new(
            BASE,
            &[("acme.yaml", "slots: {direct_env: ACME_API_KEY}\n")],
        );
        let err = fixture.render(&[], VARS).expect_err("no auth header");
        assert!(format!("{err}").contains("auth_header"), "{err}");
    }

    #[test]
    fn unknown_upstream_field_is_rejected() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", "route: []\n")]);
        let err = fixture.render(&[], VARS).expect_err("typo");
        assert!(
            format!("{err:#}").contains("unknown field `route`"),
            "{err:#}"
        );
    }

    #[test]
    fn missing_or_repeated_marker_is_an_error() {
        let fixture = Fixture::new("routes: []\nclusters: [gm:upstream-clusters]\n", &[]);
        let err = fixture.render(&[], &[]).expect_err("missing marker");
        assert!(format!("{err}").contains("found 0"), "{err}");

        let fixture = Fixture::new(
            "routes: [gm:upstream-routes, gm:upstream-routes]\nclusters: [gm:upstream-clusters]\n",
            &[],
        );
        let err = fixture.render(&[], &[]).expect_err("repeated marker");
        assert!(format!("{err}").contains("found 2"), "{err}");
    }
}
