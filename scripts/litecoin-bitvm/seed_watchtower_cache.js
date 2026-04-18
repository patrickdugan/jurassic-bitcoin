const crypto = require("crypto");
const path = require("path");
const { createRequire } = require("module");

function env(name, fallback = "") {
  const value = process.env[name];
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return String(value);
}

function nenv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === "") {
    return fallback;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Invalid ${name}=${raw}`);
  }
  return parsed;
}

function resolveTradelayerModule(...segments) {
  const repoRoot = env("TRADELAYER_REPO", "C:\\projects\\tradelayer.js");
  return require(path.join(repoRoot, ...segments));
}

const tradelayerRepo = env("TRADELAYER_REPO", "C:\\projects\\tradelayer.js");
const tradelayerRequire = createRequire(path.join(tradelayerRepo, "package.json"));
const secp = tradelayerRequire("tiny-secp256k1");

const TxUtils = resolveTradelayerModule("src", "txUtils.js");
const Types = resolveTradelayerModule("src", "types.js");
const Logic = resolveTradelayerModule("src", "logic.js");
const Activation = resolveTradelayerModule("src", "activation.js");

function parseTl(scriptHex) {
  const markerHex = "746c";
  const pos = String(scriptHex || "").indexOf(markerHex);
  if (pos < 0) return null;
  const ascii = Buffer.from(scriptHex.slice(pos), "hex").toString();
  if (!ascii.startsWith("tl")) return null;
  const type = parseInt(ascii.slice(2, 3), 36);
  if (!Number.isFinite(type)) return null;
  return { marker: "tl", type, encodedPayload: ascii.slice(3) };
}

async function decodeTxWithSender(txid, senderAddress, blockHeight) {
  const tx = await TxUtils.getRawTransaction(txid);
  const opReturn = tx?.vout?.find((v) => v?.scriptPubKey?.type === "nulldata");
  const parsed = parseTl(opReturn?.scriptPubKey?.hex || "");
  if (!parsed) {
    throw new Error(`No TL payload found for tx ${txid}`);
  }
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
  return { parsed, decoded };
}

async function applyTxNow(txid, senderAddress, blockHeight) {
  const { parsed, decoded } = await decodeTxWithSender(txid, senderAddress, blockHeight);
  if (decoded.valid !== true) {
    throw new Error(`tx invalid ${txid}: ${decoded.reason || "unknown"}`);
  }
  await Logic.typeSwitch(parsed.type, decoded);
  return parsed.type;
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

function canonicalRelayMessage(bundle) {
  return JSON.stringify({
    eventId: String(bundle.eventId || ""),
    outcome: String(bundle.outcome || ""),
    outcomeIndex: Number(bundle.outcomeIndex || 0),
    stateHash: String(bundle.stateHash || ""),
    timestamp: Number(bundle.timestamp || 0),
  });
}

function getRelaySigningKey() {
  for (;;) {
    const key = crypto.randomBytes(32);
    if (secp.isPrivate(key)) {
      return key;
    }
  }
}

function relayBlob(settlement, stateHash, relayPrivkey) {
  const doc = {
    eventId: `watchtower-seed-${Date.now()}`,
    outcome: "SETTLED",
    outcomeIndex: 0,
    stateHash,
    timestamp: Date.now(),
    settlement,
    oraclePubkeyHex: Buffer.from(secp.pointFromScalar(relayPrivkey, true)).toString("hex"),
  };
  const msg = canonicalRelayMessage(doc);
  const msgHash = sha256(Buffer.from(msg, "utf8"));
  doc.signatureHex = Buffer.from(secp.sign(msgHash, relayPrivkey)).toString("hex");
  return "b64:" + Buffer.from(JSON.stringify(doc), "utf8").toString("base64");
}

async function main() {
  const admin = env("TL_ORACLE_ADMIN_ADDRESS") || env("TL_ADMIN_ADDRESS");
  const challenger = env("TL_CHALLENGER_ADDRESS");
  if (!admin) {
    throw new Error("Missing TL_ORACLE_ADMIN_ADDRESS (or TL_ADMIN_ADDRESS)");
  }
  if (!challenger) {
    throw new Error("Missing TL_CHALLENGER_ADDRESS");
  }

  await TxUtils.init();
  await Activation.getInstance().init();

  const block = await TxUtils.getBlockCount();
  const relayPrivkey = getRelaySigningKey();
  const cacheId = env("TL_CACHE_ID", crypto.randomBytes(32).toString("hex"));
  const dlcRef = env("TL_DLC_REF", `ct-watch-${Date.now()}`);
  const cacheAddress = env("TL_CACHE_ADDRESS", `BITVM_CACHE::${dlcRef}`);
  const stateHash = env("TL_CACHE_STATE_HASH", `watch-cache-${Date.now()}`);
  const oracleId = nenv("TL_ORACLE_ID", 1);
  const propertyId = nenv("TL_PROPERTY_ID", 1);
  const amount = nenv("TL_BITVM_AMOUNT", 0.01);
  const challengeBlocks = nenv("TL_BITVM_CHALLENGE_BLOCKS", 6);

  const txid = await TxUtils.createStakeFraudProofTransaction(admin, {
    action: 2,
    oracleId,
    stakedPropertyId: propertyId,
    amount: 0,
    accusedAddress: "",
    evidenceHash: "",
    relayType: 1,
    stateHash,
    dlcRef,
    settlementState: "SETTLED",
    relayBlob: relayBlob(
      {
        mode: "bitvm_cache",
        cacheId,
        propertyId,
        amount,
        fromAddress: admin,
        toAddress: challenger,
        cacheAddress,
        challengeBlocks,
      },
      stateHash,
      relayPrivkey
    ),
  });

  await applyTxNow(txid, admin, block);

  process.stdout.write(
    JSON.stringify(
      {
        seedCacheTxid: txid,
        cacheId,
        dlcRef,
        cacheAddress,
        admin,
        challenger,
        block,
        propertyId,
        amount,
        challengeBlocks,
      },
      null,
      2
    ) + "\n"
  );
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
