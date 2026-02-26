use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureManifest {
    pub name: String,
    pub windows: Vec<ManifestWindow>,
    pub fixtures: Vec<ManifestFixture>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestWindow {
    pub name: String,
    pub start_height: u32,
    pub end_height: u32,
    pub representative_heights: Vec<u32>,
    #[serde(default)]
    pub epoch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFixture {
    pub id: String,
    pub description: String,
    pub window: String,
    #[serde(default)]
    pub tx_hex: Option<String>,
    #[serde(default)]
    pub tx_hex_blob: Option<String>,
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default = "default_spend_type")]
    pub spend_type: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct MaterializedFixture {
    pub id: String,
    pub description: String,
    pub window: String,
    pub epoch: Option<String>,
    pub height: u32,
    pub tx_hex: String,
    pub spend_type: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct FixtureOptions {
    pub rpc_fetch: bool,
    pub cache_dir: PathBuf,
    pub limit_per_epoch: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchItemReport {
    pub txid: String,
    pub status: String,
    #[serde(default)]
    pub cache_path: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchReport {
    pub manifest_name: String,
    pub cache_dir: String,
    pub total_txids: usize,
    pub fetched: usize,
    pub cached: usize,
    pub failed: usize,
    pub items: Vec<FetchItemReport>,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            rpc_fetch: false,
            cache_dir: default_cache_dir(),
            limit_per_epoch: 200,
        }
    }
}

fn default_spend_type() -> String {
    "p2wpkh".to_string()
}

pub fn default_cache_dir() -> PathBuf {
    if let Ok(path) = std::env::var("JB_FIXTURE_CACHE") {
        return PathBuf::from(path);
    }
    PathBuf::from("fixtures").join("cache")
}

pub fn load_manifest(path: &Path) -> Result<FixtureManifest> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

pub fn materialize_fixtures(
    manifest_path: &Path,
    manifest: &FixtureManifest,
    opts: &FixtureOptions,
) -> Result<Vec<MaterializedFixture>> {
    let manifest_dir = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&opts.cache_dir)
        .with_context(|| format!("creating {}", opts.cache_dir.display()))?;

    let rpc = if opts.rpc_fetch {
        Some(SimpleRpc::from_env()?)
    } else {
        None
    };

    let mut windows = BTreeMap::new();
    for w in &manifest.windows {
        if w.start_height > w.end_height {
            return Err(anyhow!(
                "manifest window {} has start_height > end_height",
                w.name
            ));
        }
        windows.insert(w.name.clone(), w.clone());
    }

    let mut grouped: BTreeMap<String, Vec<&ManifestFixture>> = BTreeMap::new();
    for fixture in &manifest.fixtures {
        grouped
            .entry(fixture.window.clone())
            .or_default()
            .push(fixture);
    }

    let mut out = Vec::new();
    for (window_name, fixtures) in grouped {
        let window = windows
            .get(&window_name)
            .ok_or_else(|| anyhow!("fixture window {} not found in windows list", window_name))?;

        let mut produced = 0usize;
        for height in &window.representative_heights {
            if *height < window.start_height || *height > window.end_height {
                return Err(anyhow!(
                    "window {} representative height {} is outside [{}, {}]",
                    window.name,
                    height,
                    window.start_height,
                    window.end_height
                ));
            }
            for fixture in &fixtures {
                if produced >= opts.limit_per_epoch {
                    break;
                }
                let tx_hex = resolve_tx_hex(fixture, &manifest_dir, &opts.cache_dir, rpc.as_ref())?;
                out.push(MaterializedFixture {
                    id: fixture.id.clone(),
                    description: fixture.description.clone(),
                    window: window.name.clone(),
                    epoch: window.epoch.clone(),
                    height: *height,
                    tx_hex,
                    spend_type: fixture.spend_type.clone(),
                    metadata: fixture.metadata.clone(),
                });
                produced += 1;
            }
            if produced >= opts.limit_per_epoch {
                break;
            }
        }
    }

    Ok(out)
}

pub fn fetch_txid_fixtures(manifest: &FixtureManifest, cache_dir: &Path) -> Result<FetchReport> {
    fs::create_dir_all(cache_dir).with_context(|| format!("creating {}", cache_dir.display()))?;
    let mut txids = manifest
        .fixtures
        .iter()
        .filter_map(|f| f.txid.clone())
        .collect::<Vec<_>>();
    txids.sort();
    txids.dedup();

    if txids.is_empty() {
        return Ok(FetchReport {
            manifest_name: manifest.name.clone(),
            cache_dir: cache_dir.display().to_string(),
            total_txids: 0,
            fetched: 0,
            cached: 0,
            failed: 0,
            items: Vec::new(),
        });
    }

    let rpc = SimpleRpc::from_env()?;

    let mut items = Vec::new();
    let mut fetched = 0usize;
    let mut cached = 0usize;
    let mut failed = 0usize;

    for txid in txids {
        let cache_path = cache_file_path(cache_dir, &txid);
        if read_cached_tx_hex(cache_dir, &txid)?.is_some() {
            cached += 1;
            items.push(FetchItemReport {
                txid,
                status: "cached".to_string(),
                cache_path: Some(cache_path.display().to_string()),
                error: None,
            });
            continue;
        }

        match fetch_tx_hex_by_txid(&rpc, &txid) {
            Ok(tx_hex) => {
                write_cached_tx_hex(cache_dir, &txid, &tx_hex)?;
                fetched += 1;
                items.push(FetchItemReport {
                    txid,
                    status: "fetched".to_string(),
                    cache_path: Some(cache_path.display().to_string()),
                    error: None,
                });
            }
            Err(e) => {
                failed += 1;
                items.push(FetchItemReport {
                    txid,
                    status: "failed".to_string(),
                    cache_path: None,
                    error: Some(format!("{e:#}")),
                });
            }
        }
    }

    Ok(FetchReport {
        manifest_name: manifest.name.clone(),
        cache_dir: cache_dir.display().to_string(),
        total_txids: items.len(),
        fetched,
        cached,
        failed,
        items,
    })
}

fn resolve_tx_hex(
    fixture: &ManifestFixture,
    manifest_dir: &Path,
    cache_dir: &Path,
    rpc: Option<&SimpleRpc>,
) -> Result<String> {
    if let Some(tx_hex) = &fixture.tx_hex {
        return Ok(tx_hex.clone());
    }
    if let Some(blob_path) = &fixture.tx_hex_blob {
        return read_blob_tx_hex(&manifest_dir.join(blob_path));
    }
    if let Some(txid) = &fixture.txid {
        if let Some(cached) = read_cached_tx_hex(cache_dir, txid)? {
            return Ok(cached);
        }
        if let Some(rpc) = rpc {
            let fetched = fetch_tx_hex_by_txid(rpc, txid)?;
            write_cached_tx_hex(cache_dir, txid, &fetched)?;
            return Ok(fetched);
        }
        return Err(anyhow!(
            "fixture {} needs txid {} but rpc_fetch=false and cache miss",
            fixture.id,
            txid
        ));
    }
    Err(anyhow!(
        "fixture {} missing tx source: set tx_hex, tx_hex_blob, or txid",
        fixture.id
    ))
}

#[derive(Deserialize)]
struct BlobFile {
    tx_hex: String,
}

fn read_blob_tx_hex(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("reading blob {}", path.display()))?;
    if let Ok(v) = serde_json::from_slice::<BlobFile>(&bytes) {
        return Ok(v.tx_hex);
    }
    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
        if let Some(s) = v.as_str() {
            return Ok(s.to_string());
        }
    }
    Err(anyhow!("unsupported blob format: {}", path.display()))
}

#[derive(Serialize, Deserialize)]
struct CacheFile {
    txid: String,
    tx_hex: String,
}

fn read_cached_tx_hex(cache_dir: &Path, txid: &str) -> Result<Option<String>> {
    let path = cache_file_path(cache_dir, txid);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let cached: CacheFile =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(cached.tx_hex))
}

fn write_cached_tx_hex(cache_dir: &Path, txid: &str, tx_hex: &str) -> Result<()> {
    fs::create_dir_all(cache_dir).with_context(|| format!("creating {}", cache_dir.display()))?;
    let path = cache_file_path(cache_dir, txid);
    let payload = CacheFile {
        txid: txid.to_string(),
        tx_hex: tx_hex.to_string(),
    };
    fs::write(&path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn cache_file_path(cache_dir: &Path, txid: &str) -> PathBuf {
    cache_dir.join(format!("{}.json", txid))
}

fn fetch_tx_hex_by_txid(rpc: &SimpleRpc, txid: &str) -> Result<String> {
    let v = rpc.call("getrawtransaction", json!([txid, false]))?;
    v.as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("getrawtransaction returned non-string for txid {}", txid))
}

#[derive(Clone)]
struct SimpleRpc {
    url: String,
    user: String,
    pass: String,
}

#[derive(Debug, Deserialize)]
struct SimpleRpcResponse {
    result: Option<Value>,
    error: Option<SimpleRpcErr>,
}

#[derive(Debug, Deserialize)]
struct SimpleRpcErr {
    code: i64,
    message: String,
}

impl SimpleRpc {
    fn from_env() -> Result<Self> {
        Ok(Self {
            url: std::env::var("BITCOIND_RPC_URL")
                .context("missing BITCOIND_RPC_URL (example: http://127.0.0.1:8332)")?,
            user: std::env::var("BITCOIND_RPC_USER").context("missing BITCOIND_RPC_USER")?,
            pass: std::env::var("BITCOIND_RPC_PASS").context("missing BITCOIND_RPC_PASS")?,
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let req = json!({
            "jsonrpc":"1.0",
            "id":"jb",
            "method": method,
            "params": params
        });
        let auth = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.user, self.pass))
        );
        let resp: SimpleRpcResponse = ureq::post(&self.url)
            .set("content-type", "text/plain")
            .set("authorization", &auth)
            .send_json(req)
            .with_context(|| format!("rpc call failed: {method}"))?
            .into_json()
            .with_context(|| format!("rpc decode failed: {method}"))?;
        if let Some(err) = resp.error {
            return Err(anyhow!("rpc {method} error {}: {}", err.code, err.message));
        }
        resp.result
            .ok_or_else(|| anyhow!("rpc {method} returned null result"))
    }
}
