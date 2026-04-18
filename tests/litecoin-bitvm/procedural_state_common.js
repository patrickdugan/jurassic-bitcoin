const crypto = require("crypto");
const path = require("path");

const tradelayerRepo = process.env.TRADELAYER_REPO || "C:\\projects\\tradelayer.js";
const litecore = require(path.join(tradelayerRepo, "node_modules", "bitcore-lib-ltc"));
const TxUtils = require(path.join(tradelayerRepo, "src", "txUtils"));
const Types = require(path.join(tradelayerRepo, "src", "types"));
const Logic = require(path.join(tradelayerRepo, "src", "logic"));
const Activation = require(path.join(tradelayerRepo, "src", "activation"));
const Encode = require(path.join(tradelayerRepo, "src", "txEncoder"));
const OracleList = require(path.join(tradelayerRepo, "src", "oracle"));
const PropertyList = require(path.join(tradelayerRepo, "src", "property"));
const db = require(path.join(tradelayerRepo, "src", "db"));
const { ProceduralRegistry } = require(path.join(tradelayerRepo, "src", "procedural"));
const { createOracleSigner } = require(path.join(tradelayerRepo, "tests", "makeshiftOracle"));

function env(name, fallback = "") {
  const v = process.env[name];
  return v === undefined || v === null || v === "" ? fallback : String(v);
}

function nenv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) throw new Error(`Invalid ${name}=${raw}`);
  return n;
}

function benv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === "") return fallback;
  return String(raw).toLowerCase() === "true";
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function parseTL(scriptHex) {
  const markerHex = "746c";
  const pos = String(scriptHex || "").indexOf(markerHex);
  if (pos < 0) return null;
  const ascii = Buffer.from(scriptHex.slice(pos), "hex").toString();
  if (!ascii.startsWith("tl")) return null;
  const type = parseInt(ascii.slice(2, 3), 36);
  if (!Number.isFinite(type)) return null;
  return { marker: "tl", type, encodedPayload: ascii.slice(3) };
}

async function applyTxNow(txid, senderAddress, blockHeight) {
  const tx = await TxUtils.getRawTransaction(txid);
  const opret = tx?.vout?.find((v) => v?.scriptPubKey?.type === "nulldata");
  const parsed = parseTL(opret?.scriptPubKey?.hex || "");
  if (!parsed) throw new Error(`No TL payload found for tx ${txid}`);

  const decoded = await Types.decodePayload(
    txid,
    parsed.type,
    parsed.marker,
    parsed.encodedPayload,
    senderAddress,
    null,
    0,
    0,
    blockHeight
  );
  decoded.block = blockHeight;
  if (decoded.valid !== true) {
    throw new Error(`tx invalid ${txid}: ${decoded.reason || "unknown"}`);
  }
  await Logic.typeSwitch(parsed.type, decoded);
  return { type: parsed.type, decoded };
}

async function selectFundingUtxo(address, minConf = 0) {
  const utxos = await TxUtils.client.listUnspent(minConf, 9999999, [address]);
  const raw = (utxos || [])
    .filter((u) => Number(u?.amount || 0) > 0)
    .sort((a, b) => {
      const amountDelta = Number(b.amount || 0) - Number(a.amount || 0);
      if (amountDelta !== 0) return amountDelta;
      return Number(b.confirmations || 0) - Number(a.confirmations || 0);
    })[0];
  if (!raw) return null;
  return {
    txId: raw.txid,
    outputIndex: raw.vout,
    address: raw.address,
    script: raw.scriptPubKey,
    satoshis: Math.round(Number(raw.amount || 0) * 1e8),
    confirmations: Number(raw.confirmations || 0)
  };
}

async function broadcastPayload(senderAddress, payload) {
  const utxo = await selectFundingUtxo(senderAddress, 0);
  if (!utxo) {
    throw new Error(`No spendable UTXO found for ${senderAddress}`);
  }
  const privateKey = await TxUtils.client.dumpprivkey(senderAddress);
  const tx = new litecore.Transaction()
    .from(utxo)
    .addData(payload)
    .change(senderAddress)
    .fee(2000);
  tx.sign(privateKey);
  return TxUtils.client.sendrawtransaction(tx.uncheckedSerialize());
}

async function activateIfNeeded(adminAddress, txType, applyImmediate) {
  const activation = Activation.getInstance();
  const alreadyActive = await activation.isTxTypeActive(txType);
  if (alreadyActive) return null;
  const txid = await TxUtils.activationTransaction(adminAddress, txType);
  if (applyImmediate) {
    const block = await TxUtils.getBlockCount();
    await applyTxNow(txid, adminAddress, block);
  }
  return txid;
}

async function issueManagedProperty(admin, ticker, applyImmediate, proceduralType = 1) {
  const props = await PropertyList.getPropertyIndex();
  const existing = props.find((p) => p.ticker === ticker);
  if (existing?.id) {
    return { txid: null, propertyId: Number(existing.id), ticker, reused: true };
  }

  const issuePayload = (effectiveTicker) =>
    Encode.encodeTokenIssue({
      initialAmount: 1,
      ticker: effectiveTicker,
      whitelists: [],
      managed: true,
      backupAddress: "",
      nft: false,
      coloredCoinHybrid: false,
      proceduralType
    });

  try {
    const issueTx = await broadcastPayload(admin, issuePayload(ticker));
    if (applyImmediate) {
      const b = await TxUtils.getBlockCount();
      await applyTxNow(issueTx, admin, b);
    }
    const refreshed = await PropertyList.getPropertyIndex();
    const prop = refreshed.find((p) => p.ticker === ticker);
    if (!prop?.id) throw new Error(`Unable to resolve property id for ${ticker}`);
    return { txid: issueTx, propertyId: Number(prop.id), ticker, reused: false };
  } catch (err) {
    const reason = String(err?.message || err || "");
    if (!/already exists|invalid ticker|undefinedTicker/i.test(reason)) {
      throw err;
    }
    const fallbackTicker = `P${Date.now().toString().slice(-5)}`.slice(0, 6);
    const issueTx = await broadcastPayload(admin, issuePayload(fallbackTicker));
    if (applyImmediate) {
      const b = await TxUtils.getBlockCount();
      await applyTxNow(issueTx, admin, b);
    }
    const refreshed = await PropertyList.getPropertyIndex();
    const prop = refreshed.find((p) => p.ticker === fallbackTicker);
    if (!prop?.id) throw new Error(`Unable to resolve property id for ${fallbackTicker}`);
    return { txid: issueTx, propertyId: Number(prop.id), ticker: fallbackTicker, reused: false };
  }
}

async function createOracle(admin, ticker, applyImmediate) {
  const createTx = await broadcastPayload(
    admin,
    Encode.encodeCreateOracle({
      ticker,
      url: "",
      backupAddress: "",
      whitelists: [],
      lag: 1
    })
  );
  if (applyImmediate) {
    const b = await TxUtils.getBlockCount();
    await applyTxNow(createTx, admin, b);
  }
  const allOracles = await OracleList.getAllOracles();
  const newest = allOracles.sort((a, b) => Number(b.id || 0) - Number(a.id || 0))[0];
  const oracleId = Number(newest?.id || 0);
  if (!oracleId) throw new Error(`Unable to resolve oracle id for ${ticker}`);
  return { txid: createTx, oracleId };
}

async function grantManaged(admin, propertyId, amount, address, templateId, contractRef, applyImmediate, dlcHash) {
  const fundingUtxo = await selectFundingUtxo(admin, 0);
  if (!fundingUtxo) {
    throw new Error(`No spendable UTXO found for grant sender ${admin}`);
  }
  const feeSats = 2000;
  const grantSats = Math.max(0, Number(fundingUtxo.satoshis || 0) - feeSats);
  if (grantSats <= 0) {
    throw new Error(`Unable to size procedural grant for ${address}: utxo=${fundingUtxo.satoshis || 0}`);
  }
  const txid = await TxUtils.createGrantManagedTokenTransaction(admin, {
    propertyId,
    amountGranted: grantSats / 1e8,
    addressToGrantTo: address,
    dlcTemplateId: templateId,
    dlcContractId: contractRef,
    settlementState: "FUNDED",
    dlcHash,
    fundingUtxo
  });
  if (applyImmediate) {
    const b = await TxUtils.getBlockCount();
    await applyTxNow(txid, admin, b);
  }
  return {
    txid,
    requestedAmount: amount,
    grantedAmount: grantSats / 1e8,
    grantedSats: grantSats
  };
}

function encodeBalancePayload(doc) {
  return Buffer.from(JSON.stringify(doc), "utf8").toString("base64");
}

function relayBlobDocToBase64(doc) {
  return "b64:" + Buffer.from(JSON.stringify(doc), "utf8").toString("base64");
}

module.exports = {
  TxUtils,
  Activation,
  db,
  ProceduralRegistry,
  createOracleSigner,
  env,
  nenv,
  benv,
  sha256Hex,
  applyTxNow,
  activateIfNeeded,
  issueManagedProperty,
  createOracle,
  grantManaged,
  encodeBalancePayload,
  relayBlobDocToBase64
};
