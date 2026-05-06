#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const DEFAULT_BITCOIN_BIN = 'C:\\tools\\bitcoin-core-31.0\\bitcoin-31.0\\bin';
const DEFAULT_DATADIR = 'D:\\BitcoinTestnet';
const DEFAULT_WALLET = 'utxoref-testnet';
const DEFAULT_ADMIN = 'tb1qpg5jvhd32vut07pvxg92dka7pttudjy570auuu';
const DEFAULT_TRADELAYER_REPO = 'C:\\projects\\tradelayer.js';
const DEFAULT_TRADELAYER_DB = 'C:\\projects\\tradelayer.js\\nedb-data';
const DEFAULT_ARTIFACT = path.join('artifacts', 'bitcoin-testnet4', 'lnbtc-deposit-grant-latest.json');

function parseArgs(argv) {
  const out = {
    bitcoinBin: process.env.BITCOIN_BIN || DEFAULT_BITCOIN_BIN,
    datadir: process.env.BTCTEST_DATADIR || DEFAULT_DATADIR,
    wallet: process.env.BTCTEST_WALLET || process.env.RPC_WALLET || DEFAULT_WALLET,
    adminAddress: process.env.TL_ADMIN_ADDRESS || DEFAULT_ADMIN,
    destinationAddress: process.env.LNBTC_DESTINATION_ADDRESS || '',
    amountSats: Number(process.env.LNBTC_AMOUNT_SATS || 1000),
    propertyId: Number(process.env.LNBTC_PROPERTY_ID || 1),
    feeRate: Number(process.env.BTCTEST_FEE_RATE || 1),
    tradeLayerRepo: process.env.TRADELAYER_REPO || DEFAULT_TRADELAYER_REPO,
    tradeLayerDbRoot: process.env.TL_NEDB_ROOT || DEFAULT_TRADELAYER_DB,
    artifact: process.env.LNBTC_ARTIFACT || DEFAULT_ARTIFACT,
    recoverTxid: process.env.LNBTC_RECOVER_TXID || '',
    dryRun: false,
    applyLocal: true,
    repairTlbtcProperty: true,
  };

  for (const arg of argv) {
    if (arg.startsWith('--bitcoin-bin=')) out.bitcoinBin = arg.slice('--bitcoin-bin='.length);
    else if (arg.startsWith('--datadir=')) out.datadir = arg.slice('--datadir='.length);
    else if (arg.startsWith('--wallet=')) out.wallet = arg.slice('--wallet='.length);
    else if (arg.startsWith('--admin=')) out.adminAddress = arg.slice('--admin='.length);
    else if (arg.startsWith('--destination=')) out.destinationAddress = arg.slice('--destination='.length);
    else if (arg.startsWith('--amount-sats=')) out.amountSats = Number(arg.slice('--amount-sats='.length));
    else if (arg.startsWith('--property-id=')) out.propertyId = Number(arg.slice('--property-id='.length));
    else if (arg.startsWith('--fee-rate=')) out.feeRate = Number(arg.slice('--fee-rate='.length));
    else if (arg.startsWith('--tradelayer-repo=')) out.tradeLayerRepo = arg.slice('--tradelayer-repo='.length);
    else if (arg.startsWith('--tradelayer-db-root=')) out.tradeLayerDbRoot = arg.slice('--tradelayer-db-root='.length);
    else if (arg.startsWith('--artifact=')) out.artifact = arg.slice('--artifact='.length);
    else if (arg.startsWith('--recover-txid=')) out.recoverTxid = arg.slice('--recover-txid='.length);
    else if (arg === '--dry-run') out.dryRun = true;
    else if (arg === '--no-apply-local') out.applyLocal = false;
    else if (arg === '--no-repair-tlbtc-property') out.repairTlbtcProperty = false;
  }

  if (!Number.isInteger(out.amountSats) || out.amountSats <= 0) {
    throw new Error(`Invalid amountSats: ${out.amountSats}`);
  }
  if (!Number.isInteger(out.propertyId) || out.propertyId <= 0) {
    throw new Error(`Invalid propertyId: ${out.propertyId}`);
  }
  if (!Number.isFinite(out.feeRate) || out.feeRate <= 0) {
    throw new Error(`Invalid feeRate: ${out.feeRate}`);
  }
  return out;
}

function cliPath(config) {
  return path.join(config.bitcoinBin, process.platform === 'win32' ? 'bitcoin-cli.exe' : 'bitcoin-cli');
}

function bitcoinCli(config, args) {
  const fullArgs = [`-datadir=${config.datadir}`, '-chain=testnet4', `-rpcwallet=${config.wallet}`, ...args];
  return execFileSync(cliPath(config), fullArgs, { encoding: 'utf8' }).trim();
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function asciiHex(value) {
  return Buffer.from(String(value), 'utf8').toString('hex');
}

function btc(amountSats) {
  return (Number(amountSats) / 1e8).toFixed(8);
}

function parseTlPayload(payload) {
  if (!payload.startsWith('tl')) throw new Error(`Not a TradeLayer payload: ${payload}`);
  const type = parseInt(payload.slice(2, 3), 36);
  if (!Number.isFinite(type)) throw new Error(`Cannot parse tx type from payload: ${payload}`);
  return {
    marker: 'tl',
    type,
    encodedPayload: payload.slice(3),
  };
}

function extractOpReturnPayloadFromDecodedTx(decodedTx) {
  const opret = (decodedTx.vout || []).find((vout) => vout?.scriptPubKey?.type === 'nulldata');
  const asm = opret?.scriptPubKey?.asm || '';
  const match = asm.match(/^OP_RETURN\s+([0-9a-fA-F]+)$/);
  if (!match) throw new Error('Could not find single-push OP_RETURN payload in recovered tx');
  return Buffer.from(match[1], 'hex').toString('utf8');
}

function configureTradeLayerEnv(config) {
  process.env.CHAIN = 'BTCTEST';
  process.env.AUTODETECT = '0';
  process.env.RPC_HOST = process.env.RPC_HOST || '127.0.0.1';
  process.env.RPC_PORT = process.env.RPC_PORT || '48332';
  process.env.RPC_WALLET = config.wallet;
  process.env.BTCTEST_WALLET = config.wallet;
  process.env.BTCTEST_DATADIR = config.datadir;
  process.env.TL_ADMIN_ADDRESS = config.adminAddress;
  process.env.TL_NEDB_ROOT = config.tradeLayerDbRoot;
  process.env.RPC_COOKIE_FILE = process.env.RPC_COOKIE_FILE || path.join(config.datadir, 'testnet4', '.cookie');
}

function buildMockLnReceipt(config, destinationAddress) {
  const seed = [
    'btctest4-lnbtc-deposit-v1',
    destinationAddress,
    config.amountSats,
    new Date().toISOString(),
  ].join('|');
  const preimage = sha256Hex(`preimage:${seed}`);
  return {
    mode: 'mock-settled',
    amountSats: config.amountSats,
    paymentHash: sha256Hex(preimage),
    preimageHash: sha256Hex(preimage),
    invoiceId: `lnbtc-${sha256Hex(seed).slice(0, 16)}`,
    settled: true,
  };
}

function broadcastGrant(config, destinationAddress, payload) {
  const utxos = JSON.parse(bitcoinCli(config, ['listunspent', '0', '9999999', JSON.stringify([config.adminAddress])]))
    .filter((utxo) => utxo.spendable && utxo.safe !== false)
    .sort((a, b) => Number(b.amount || 0) - Number(a.amount || 0));
  if (!utxos.length) {
    throw new Error(`No spendable admin UTXO found for ${config.adminAddress}`);
  }
  const inputs = JSON.stringify([{ txid: utxos[0].txid, vout: utxos[0].vout }]);
  const outputs = JSON.stringify([{ data: asciiHex(payload) }]);
  const raw = bitcoinCli(config, ['createrawtransaction', inputs, outputs]);
  const options = JSON.stringify({
    fee_rate: config.feeRate,
    changeAddress: config.adminAddress,
    add_inputs: false,
    include_unsafe: true,
  });
  const funded = JSON.parse(bitcoinCli(config, ['fundrawtransaction', raw, options]));
  const signed = JSON.parse(bitcoinCli(config, ['signrawtransactionwithwallet', funded.hex]));
  if (!signed.complete) throw new Error('wallet did not fully sign LNBTC grant transaction');
  const txid = bitcoinCli(config, ['sendrawtransaction', signed.hex]);
  return {
    txid,
    funded,
    signedHex: signed.hex,
    explorer: `https://mempool.space/testnet4/tx/${txid}`,
    destinationAddress,
    payload,
    payloadBytes: Buffer.byteLength(payload, 'utf8'),
  };
}

async function applyGrantLocally(config, grant, payload) {
  configureTradeLayerEnv(config);
  const Activation = require(path.join(config.tradeLayerRepo, 'src', 'activation'));
  const Types = require(path.join(config.tradeLayerRepo, 'src', 'types'));
  const Logic = require(path.join(config.tradeLayerRepo, 'src', 'logic'));
  const TallyMap = require(path.join(config.tradeLayerRepo, 'src', 'tally'));
  const PropertyManager = require(path.join(config.tradeLayerRepo, 'src', 'property'));

  await Activation.getInstance().init();
  if (config.repairTlbtcProperty && Number(config.propertyId) === 1) {
    await PropertyManager.load();
    const existing = await PropertyManager.getPropertyData(1);
    if (!existing) {
      const manager = PropertyManager.getInstance();
      await manager.addProperty(1, 'tlBTC', 21000000, 'Managed', null, config.adminAddress, '', {
        repairedFromTxid: '55e9da04a59c9cc4596ff6443e3bb0b24e5a6bb790b91827c902744664828ac5',
        repairReason: 'BTCTEST local DB was missing the prior on-chain tlBTC issuance while later artifacts reference property 1.',
      });
    }
  }
  const parsed = parseTlPayload(payload);
  const blockHeight = Number(bitcoinCli(config, ['getblockcount']));
  const decoded = await Types.decodePayload(
    grant.txid,
    parsed.type,
    parsed.marker,
    parsed.encodedPayload,
    config.adminAddress,
    null,
    0,
    0,
    blockHeight
  );
  decoded.block = blockHeight;
  if (decoded.valid !== true) {
    throw new Error(`TradeLayer local apply rejected grant: ${decoded.reason || 'unknown reason'}`);
  }
  await Logic.typeSwitch(parsed.type, decoded);
  const balances = await TallyMap.getAddressBalances(grant.destinationAddress);
  return {
    blockHeight,
    decoded,
    balances,
  };
}

async function main() {
  const config = parseArgs(process.argv.slice(2));
  configureTradeLayerEnv(config);

  const Encode = require(path.join(config.tradeLayerRepo, 'src', 'txEncoder'));
  let destinationAddress = config.destinationAddress ||
    (config.dryRun ? `tb1q${sha256Hex('dry-run-destination').slice(0, 38)}` : bitcoinCli(config, ['getnewaddress', 'lnbtc-deposit-destination', 'bech32']));
  let lnReceipt = buildMockLnReceipt(config, destinationAddress);
  let amount = Number(config.amountSats / 1e8).toFixed(8);
  let payload = Encode.encodeGrantManagedToken({
    propertyId: config.propertyId,
    amountGranted: amount,
    addressToGrantTo: destinationAddress,
  });
  let recoveredGrant = null;

  if (config.recoverTxid) {
    const decodedTx = JSON.parse(bitcoinCli(config, ['getrawtransaction', config.recoverTxid, 'true']));
    payload = extractOpReturnPayloadFromDecodedTx(decodedTx);
    const parts = payload.split(',');
    destinationAddress = parts[2] || destinationAddress;
    const amountSats = parseInt(parts[1] || '0', 36);
    if (Number.isFinite(amountSats) && amountSats > 0) {
      config.amountSats = amountSats;
      amount = Number(config.amountSats / 1e8).toFixed(8);
    }
    lnReceipt = buildMockLnReceipt(config, destinationAddress);
    recoveredGrant = {
      txid: config.recoverTxid,
      explorer: `https://mempool.space/testnet4/tx/${config.recoverTxid}`,
      destinationAddress,
      payload,
      payloadBytes: Buffer.byteLength(payload, 'utf8'),
      recovered: true,
    };
  }

  const result = {
    kind: 'btctest4_lnbtc_deposit_grant',
    network: 'BTCTEST',
    bitcoinNetwork: 'testnet4',
    createdAt: new Date().toISOString(),
    dryRun: config.dryRun,
    propertyId: config.propertyId,
    ticker: config.propertyId === 1 ? 'tlBTC' : `property_${config.propertyId}`,
    amountSats: config.amountSats,
    tokenAmount: btc(config.amountSats),
    adminAddress: config.adminAddress,
    destinationAddress,
    lnReceipt,
    payload,
    payloadBytes: Buffer.byteLength(payload, 'utf8'),
    motifMapping: {
      transcriptMultiplicity: 'LN receipt, bridge artifact, and TradeLayer tx11 bind the same deposit amount and destination.',
      identifierBifurcation: 'The invoice id is separate from the TradeLayer property id and wallet address.',
      carrierCamouflage: 'The visible chain object is a standard small OP_RETURN TradeLayer grant transaction.',
    },
  };

  if (!config.dryRun) {
    result.grant = recoveredGrant || broadcastGrant(config, destinationAddress, payload);
    if (config.applyLocal) {
      result.localApply = await applyGrantLocally(config, result.grant, payload);
    }
  }

  const artifact = path.isAbsolute(config.artifact) ? config.artifact : path.join(process.cwd(), config.artifact);
  fs.mkdirSync(path.dirname(artifact), { recursive: true });
  fs.writeFileSync(artifact, JSON.stringify(result, null, 2));
  fs.writeFileSync(
    artifact.replace(/\.json$/i, '.md'),
    [
      '# BTC Testnet4 LNBTC Deposit Grant',
      '',
      `- Network: ${result.bitcoinNetwork}`,
      `- Property: ${result.ticker} (${result.propertyId})`,
      `- Token amount: ${result.tokenAmount}`,
      `- Destination: ${result.destinationAddress}`,
      `- LN receipt mode: ${result.lnReceipt.mode}`,
      result.grant ? `- Grant txid: ${result.grant.txid}` : '- Grant txid: dry run',
      result.grant ? `- Explorer: ${result.grant.explorer}` : '',
      `- Local apply: ${result.localApply ? 'yes' : 'no'}`,
      '',
    ].filter(Boolean).join('\n')
  );

  console.log(JSON.stringify({
    ok: true,
    artifact,
    destinationAddress,
    propertyId: result.propertyId,
    tokenAmount: result.tokenAmount,
    txid: result.grant?.txid || null,
    localBalance: result.localApply?.balances || null,
  }, null, 2));
}

main().catch((error) => {
  console.error(error.stack || error.message || error);
  process.exit(1);
});
