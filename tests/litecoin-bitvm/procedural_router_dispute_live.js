const path = require("path");

const tradelayerRepo = process.env.TRADELAYER_REPO || "C:\\projects\\tradelayer.js";
const ContractRegistry = require(path.join(tradelayerRepo, "src", "contractRegistry"));
const TallyMap = require(path.join(tradelayerRepo, "src", "tally"));

const {
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
} = require("./procedural_state_common");

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

async function publishPrice(oracleAdmin, oracleId, price, applyBlock) {
  const fundingUtxo = await selectFundingUtxo(oracleAdmin, 0);
  if (!fundingUtxo) {
    throw new Error(`No spendable UTXO found for price sender ${oracleAdmin}`);
  }
  const txid = await TxUtils.publishDataTransaction(oracleAdmin, {
    oracleid: oracleId,
    price,
    fundingUtxo
  });
  if (applyBlock !== null && applyBlock !== undefined) {
    await applyTxNow(txid, oracleAdmin, applyBlock);
  }
  return txid;
}

async function relaySettlement(oracleAdmin, params, settlement, signer, applyBlock) {
  const signed = signer.signBundle({
    eventId: settlement.eventId,
    outcome: settlement.outcome || "SETTLED",
    outcomeIndex: 0,
    stateHash: settlement.stateHash,
    timestamp: settlement.timestamp || Math.floor(Date.now() / 1000)
  });
  const fundingUtxo = await selectFundingUtxo(oracleAdmin, 0);
  if (!fundingUtxo) {
    throw new Error(`No spendable UTXO found for relay sender ${oracleAdmin}`);
  }
  const txid = await TxUtils.createStakeFraudProofTransaction(oracleAdmin, {
    action: 2,
    oracleId: params.oracleId,
    relayType: 1,
    stateHash: settlement.stateHash,
    dlcRef: params.dlcRef,
    settlementState: settlement.settlementState || "SETTLED",
    fundingUtxo,
    relayBlob: JSON.stringify({
      ...signed,
      settlement: settlement.payload
    })
  });
  if (applyBlock !== null && applyBlock !== undefined) {
    await applyTxNow(txid, oracleAdmin, applyBlock);
  }
  return txid;
}

async function expectApplyFail(txid, senderAddress, blockHeight, reasonRx) {
  try {
    await applyTxNow(txid, senderAddress, blockHeight);
  } catch (err) {
    const msg = String(err?.message || err || "");
    if (reasonRx && !reasonRx.test(msg)) {
      throw new Error(`Expected failure matching ${reasonRx}, got: ${msg}`);
    }
    return msg;
  }
  throw new Error(`Expected apply failure for ${txid}`);
}

function floor8(value) {
  return Math.floor((Number(value) + Number.EPSILON) * 1e8) / 1e8;
}

function computeRouterPlan({ collateralAmount, realizedLossBps, adapterPathCount, winners }) {
  const normalizedWinners = (winners || []).filter((winner) => winner && winner.address && Number(winner.weightBps || 0) > 0);
  if (normalizedWinners.length === 0) {
    throw new Error("At least one weighted winner is required");
  }
  const weightTotal = normalizedWinners.reduce((sum, winner) => sum + Number(winner.weightBps || 0), 0);
  const stepBps = Math.max(1, Math.floor(10000 / Math.max(1, Number(adapterPathCount || 1))));
  const clippedLossBps = Math.max(0, Math.min(10000, Math.floor(Number(realizedLossBps || 0))));
  const bucketLossBps = Math.floor(clippedLossBps / stepBps) * stepBps;
  const excessLossBps = clippedLossBps - bucketLossBps;
  const totalLossAmount = floor8(Number(collateralAmount) * clippedLossBps / 10000);
  const bucketLossAmount = floor8(Number(collateralAmount) * bucketLossBps / 10000);
  const excessLossAmount = floor8(totalLossAmount - bucketLossAmount);
  const refundRemainderAmount = floor8(Number(collateralAmount) - totalLossAmount);

  let distributed = 0;
  const winnerExcess = normalizedWinners
    .map((winner, idx) => {
      let amount;
      if (idx === normalizedWinners.length - 1) {
        amount = floor8(excessLossAmount - distributed);
      } else {
        amount = floor8(excessLossAmount * Number(winner.weightBps || 0) / weightTotal);
        distributed = floor8(distributed + amount);
      }
      return {
        address: winner.address,
        weightBps: Number(winner.weightBps || 0),
        amount
      };
    })
    .filter((winner) => winner.amount > 0);

  return {
    collateralAmount: floor8(collateralAmount),
    realizedLossBps: clippedLossBps,
    adapterPathCount,
    stepBps,
    bucketLossBps,
    excessLossBps,
    totalLossAmount,
    bucketLossAmount,
    excessLossAmount,
    refundRemainderAmount,
    winnerExcess
  };
}

async function tally(address, propertyId) {
  const row = await TallyMap.getTally(address, propertyId);
  return {
    amount: Number(row?.amount || 0),
    available: Number(row?.available || 0),
    reserved: Number(row?.reserved || 0),
    margin: Number(row?.margin || 0),
    vesting: Number(row?.vesting || 0)
  };
}

async function getCacheDoc(cacheId) {
  const proceduralDb = await db.getDatabase("procedural");
  return proceduralDb.findOneAsync({ _id: `bitvm-cache-${cacheId}` });
}

function diffBalances(before, after) {
  return {
    amount: floor8(Number(after.amount || 0) - Number(before.amount || 0)),
    available: floor8(Number(after.available || 0) - Number(before.available || 0)),
    reserved: floor8(Number(after.reserved || 0) - Number(before.reserved || 0)),
    margin: floor8(Number(after.margin || 0) - Number(before.margin || 0)),
    vesting: floor8(Number(after.vesting || 0) - Number(before.vesting || 0))
  };
}

function assertClose(label, actual, expected, epsilon = 0.00000002) {
  if (Math.abs(Number(actual) - Number(expected)) > epsilon) {
    throw new Error(`${label} mismatch: actual=${actual} expected=${expected}`);
  }
}

async function main() {
  const applyImmediate = benv("TL_APPLY_IMMEDIATE", true);
  const admin = env("TL_ADMIN_ADDRESS");
  const oracleAdmin = env("TL_ORACLE_ADMIN_ADDRESS", admin);
  const alice = env("TL_ALICE_ADDRESS");
  const bob = env("TL_BOB_ADDRESS");
  const charlie = env("TL_CHARLIE_ADDRESS");
  const depositBob = nenv("TL_DEPOSIT_BOB", 0.004);
  const entryPrice = nenv("TL_ENTRY_PRICE", 106);
  const exitPrice = nenv("TL_EXIT_PRICE", 112);
  const leverage = nenv("TL_LEVERAGE", 10);
  const expiryBlocks = nenv("TL_EXPIRY_BLOCKS", 24);
  const adapterPathCount = nenv("TL_ADAPTER_PATH_COUNT", 20);
  const realizedLossBps = nenv("TL_REALIZED_LOSS_BPS", 3700);
  const challengeBlocks = nenv("TL_BITVM_CHALLENGE_BLOCKS", 6);
  const shortTicker = env("TL_SHORT_TICKER", `BVD${Date.now().toString().slice(-3)}`);
  const stateOracleTicker = env("TL_STATE_ORACLE_TICKER", "BITVMSTATE");
  const priceOracleTicker = env("TL_PRICE_ORACLE_TICKER", "LTCUSD");
  const templateId = env("TL_TEMPLATE_ID", `tpl-short-router-dispute-${Date.now()}`);
  const contractRef = env("TL_SHORT_CONTRACT_REF", `bitvm-short-dispute-${Date.now()}`);

  if (!admin || !oracleAdmin || !alice || !bob || !charlie) {
    throw new Error("Missing TL_ADMIN_ADDRESS / TL_ORACLE_ADMIN_ADDRESS / TL_ALICE_ADDRESS / TL_BOB_ADDRESS / TL_CHARLIE_ADDRESS");
  }

  await TxUtils.init();
  await Activation.getInstance().init();
  const chain = await TxUtils.client.getBlockchainInfo();
  if (chain.chain !== "test") {
    throw new Error(`Expected testnet, got ${chain.chain}`);
  }

  const activated = [];
  for (const txType of [1, 11, 13, 14, 16, 30]) {
    activated.push({ txType, txid: await activateIfNeeded(admin, txType, applyImmediate) });
  }

  const stateOracle = await createOracle(oracleAdmin, stateOracleTicker, applyImmediate);
  const priceOracle = await createOracle(oracleAdmin, priceOracleTicker, applyImmediate);
  const shortProp = await issueManagedProperty(admin, shortTicker, applyImmediate, 1);

  await ProceduralRegistry.upsertTemplate(templateId, {
    oracleId: stateOracle.oracleId,
    collateralPropertyId: shortProp.propertyId,
    receiptPropertyId: shortProp.propertyId,
    templateHash: `${templateId}-hash`
  });
  await ProceduralRegistry.upsertContract(contractRef, templateId, "FUNDED", {
    epoch: 1,
    mode: "short-router-dispute"
  });

  const grant = await grantManaged(
    admin,
    shortProp.propertyId,
    depositBob,
    bob,
    templateId,
    contractRef,
    applyImmediate,
    `${templateId}-hash`
  );

  const entryPriceTx = await publishPrice(oracleAdmin, priceOracle.oracleId, entryPrice, applyImmediate ? await TxUtils.getBlockCount() : null);
  const seriesFundingUtxo = await selectFundingUtxo(admin, 0);
  if (!seriesFundingUtxo) {
    throw new Error(`No spendable UTXO found for contract series sender ${admin}`);
  }
  const createSeriesTx = await TxUtils.createContractSeriesTransaction(admin, {
    native: false,
    underlyingOracleId: priceOracle.oracleId,
    onChainData: [],
    notionalPropertyId: 0,
    notionalValue: 1,
    collateralPropertyId: shortProp.propertyId,
    leverage,
    expiryPeriod: expiryBlocks,
    series: 1,
    inverse: true,
    fee: false,
    fundingUtxo: seriesFundingUtxo
  });
  if (applyImmediate) {
    const block = await TxUtils.getBlockCount();
    await applyTxNow(createSeriesTx, admin, block);
  }

  const allContracts = await ContractRegistry.getAllContracts();
  const newestContract = allContracts
    .sort((a, b) => Number(b.id || 0) - Number(a.id || 0))
    .find(
      (contract) =>
        Number(contract.collateralPropertyId) === Number(shortProp.propertyId) &&
        Number(contract.underlyingOracleId) === Number(priceOracle.oracleId)
    );
  if (!newestContract?.id) {
    throw new Error("Unable to resolve created short-epoch contract id");
  }

  const exitPriceTx = await publishPrice(oracleAdmin, priceOracle.oracleId, exitPrice, applyImmediate ? await TxUtils.getBlockCount() : null);
  const routerPlan = computeRouterPlan({
    collateralAmount: depositBob,
    realizedLossBps,
    adapterPathCount,
    winners: [
      { address: alice, weightBps: 7000 },
      { address: charlie, weightBps: 3000 }
    ]
  });
  if (routerPlan.winnerExcess.length < 2) {
    throw new Error("Router dispute flow requires at least two excess branches");
  }

  const preludePayloadDoc = {
    stateRoot: sha256Hex(
      JSON.stringify({
        mode: "short_router_dispute_overlay",
        propertyId: shortProp.propertyId,
        holderAddress: bob,
        amount: grant.grantedAmount,
        templateId,
        contractRef,
        routeWeights: [7000, 3000]
      })
    ),
    transitions: [],
    propertyId: shortProp.propertyId,
    holderAddress: bob,
    amount: grant.grantedAmount,
    templateId,
    contractRef,
    mode: "short_router_dispute_overlay"
  };
  const preludeBalancePayloadB64 = encodeBalancePayload(preludePayloadDoc);
  const preludePayloadHash = sha256Hex(Buffer.from(preludeBalancePayloadB64, "base64"));
  const preludeStateHash = preludePayloadHash;

  const preSettlementBalances = {
    alice: await tally(alice, shortProp.propertyId),
    bob: await tally(bob, shortProp.propertyId),
    charlie: await tally(charlie, shortProp.propertyId)
  };

  const preludeSigner = createOracleSigner();
  const settlementSigner = createOracleSigner();
  const preludeBaseBlock = await TxUtils.getBlockCount();

  const transcriptRelays = [];
  const transcriptAliases = [
    { aliasTag: "aa", eventId: `${contractRef}-alias-aa`, timestamp: Math.floor(Date.now() / 1000) },
    { aliasTag: "aaaa", eventId: `${contractRef}-alias-aaaa`, timestamp: Math.floor(Date.now() / 1000) + 11 }
  ];
  for (let idx = 0; idx < transcriptAliases.length; idx++) {
    const alias = transcriptAliases[idx];
    const signed = preludeSigner.signBundle({
      eventId: alias.eventId,
      outcome: "STATE_OPEN",
      outcomeIndex: 0,
      stateHash: preludeStateHash,
      payloadHash: preludePayloadHash,
      timestamp: alias.timestamp
    });
    const relayBlob = relayBlobDocToBase64({
      ...signed,
      aliasTag: alias.aliasTag,
      balancePayloadB64: preludeBalancePayloadB64,
      statementTag: `hybrid_transcript_alias_${alias.aliasTag}`
    });
    const txid = await TxUtils.createStakeFraudProofTransaction(oracleAdmin, {
      action: 2,
      oracleId: stateOracle.oracleId,
      relayType: 2,
      stateHash: preludeStateHash,
      dlcRef: contractRef,
      settlementState: "OPEN",
      relayBlob
    });
    const applyBlock = preludeBaseBlock + idx;
    if (applyImmediate) {
      await applyTxNow(txid, oracleAdmin, applyBlock);
    }
    transcriptRelays.push({
      aliasTag: alias.aliasTag,
      eventId: alias.eventId,
      txid,
      blockHeight: applyBlock,
      signatureHex: signed.signatureHex
    });
  }

  const namespaceRelays = [];
  const namespaceBundle = preludeSigner.signBundle({
    eventId: `${contractRef}-namespace`,
    outcome: "STATE_OPEN",
    outcomeIndex: 0,
    stateHash: preludeStateHash,
    payloadHash: preludePayloadHash,
    timestamp: Math.floor(Date.now() / 1000) + 21
  });
  const namespaces = [
    { blobRef: `${contractRef}-namespace-zero`, namespaceTag: "dummy_zero" },
    { blobRef: `${contractRef}-namespace-32`, namespaceTag: "dummy_32" }
  ];
  for (let idx = 0; idx < namespaces.length; idx++) {
    const ns = namespaces[idx];
    const relayBlob = relayBlobDocToBase64({
      ...namespaceBundle,
      blobRef: ns.blobRef,
      namespaceTag: ns.namespaceTag,
      balancePayloadB64: preludeBalancePayloadB64
    });
    const txid = await TxUtils.createStakeFraudProofTransaction(oracleAdmin, {
      action: 2,
      oracleId: stateOracle.oracleId,
      relayType: 2,
      stateHash: preludeStateHash,
      dlcRef: contractRef,
      settlementState: "OPEN",
      relayBlob
    });
    const applyBlock = preludeBaseBlock + transcriptAliases.length + idx;
    if (applyImmediate) {
      await applyTxNow(txid, oracleAdmin, applyBlock);
    }
    namespaceRelays.push({
      blobRef: ns.blobRef,
      namespaceTag: ns.namespaceTag,
      txid,
      blockHeight: applyBlock,
      signatureHex: namespaceBundle.signatureHex
    });
  }

  const oracleDataDb = await db.getDatabase("oracleData");
  const preludeRelayDocs = await oracleDataDb.findAsync({
    type: "relay",
    oracleId: stateOracle.oracleId,
    dlcRef: contractRef,
    relayType: 2
  });
  const preludeSummary = {
    oracleId: stateOracle.oracleId,
    stateHash: preludeStateHash,
    payloadHash: preludePayloadHash,
    relayDocCount: preludeRelayDocs.length,
    transcriptAcceptedCount: transcriptRelays.length,
    transcriptSignatureCount: new Set(transcriptRelays.map((row) => row.signatureHex)).size,
    identifierAcceptedCount: namespaceRelays.length,
    identifierSignatureCount: new Set(namespaceRelays.map((row) => row.signatureHex)).size,
    transcriptRelays,
    namespaceRelays
  };

  const baseBlock = preludeBaseBlock + transcriptAliases.length + namespaces.length;

  let bucketSweepTx = null;
  if (routerPlan.bucketLossAmount > 0) {
    bucketSweepTx = await relaySettlement(
      oracleAdmin,
      { oracleId: stateOracle.oracleId, dlcRef: contractRef },
      {
        eventId: `${contractRef}-bucket-sweep`,
        stateHash: `${contractRef}-bucket-sweep`,
        settlementState: "SETTLED",
        payload: {
          mode: "pnl_sweep",
          propertyId: shortProp.propertyId,
          amount: routerPlan.bucketLossAmount,
          fromAddress: bob,
          toAddress: alice
        }
      },
      settlementSigner,
      applyImmediate ? baseBlock : null
    );
  }

  const routeSpecs = [
    {
      share: routerPlan.winnerExcess[0],
      verdict: "reject",
      challengerAddress: charlie,
      label: "branch_reject_release"
    },
    {
      share: routerPlan.winnerExcess[1],
      verdict: "uphold",
      challengerAddress: alice,
      label: "branch_uphold_refund"
    }
  ];

  const routes = [];
  for (let idx = 0; idx < routeSpecs.length; idx++) {
    const spec = routeSpecs[idx];
    const cacheId = `${contractRef}-dispute-${idx + 1}`;
    const cacheAddress = `BITVM_CACHE::${cacheId}`;
    const routeBaseBlock = baseBlock + 1 + idx * 3;

    const cacheTx = await relaySettlement(
      oracleAdmin,
      { oracleId: stateOracle.oracleId, dlcRef: contractRef },
      {
        eventId: `${cacheId}-lock`,
        stateHash: `${cacheId}-lock`,
        settlementState: "SETTLED",
        payload: {
          mode: "bitvm_cache",
          cacheId,
          propertyId: shortProp.propertyId,
          amount: spec.share.amount,
          fromAddress: bob,
          toAddress: spec.share.address,
          cacheAddress,
          challengeBlocks
        }
      },
      settlementSigner,
      applyImmediate ? routeBaseBlock : null
    );

    const earlyPayoutTx = await relaySettlement(
      oracleAdmin,
      { oracleId: stateOracle.oracleId, dlcRef: contractRef },
      {
        eventId: `${cacheId}-early-payout`,
        stateHash: `${cacheId}-early-payout`,
        settlementState: "SETTLED",
        payload: {
          mode: "bitvm_payout",
          cacheId,
          propertyId: shortProp.propertyId,
          amount: spec.share.amount,
          toAddress: spec.share.address
        }
      },
      settlementSigner,
      null
    );

    const earlyPayoutFailure = applyImmediate
      ? await expectApplyFail(earlyPayoutTx, oracleAdmin, routeBaseBlock, /challenge window still open|challenged|mismatch/i)
      : "not-applied";

    const challengeTx = await relaySettlement(
      oracleAdmin,
      { oracleId: stateOracle.oracleId, dlcRef: contractRef },
      {
        eventId: `${cacheId}-challenge`,
        stateHash: `${cacheId}-challenge`,
        settlementState: "DISPUTED",
        payload: {
          mode: "bitvm_challenge",
          cacheId,
          challengerAddress: spec.challengerAddress,
          evidenceHash: `${cacheId}-evidence`
        }
      },
      settlementSigner,
      applyImmediate ? routeBaseBlock + 1 : null
    );

    const resolveTx = await relaySettlement(
      oracleAdmin,
      { oracleId: stateOracle.oracleId, dlcRef: contractRef },
      {
        eventId: `${cacheId}-resolve-${spec.verdict}`,
        stateHash: `${cacheId}-resolve-${spec.verdict}`,
        settlementState: "SETTLED",
        payload: {
          mode: "bitvm_resolve",
          cacheId,
          verdict: spec.verdict,
          resolverAddress: oracleAdmin,
          reason: `router_dispute_${spec.verdict}`
        }
      },
      settlementSigner,
      applyImmediate ? routeBaseBlock + 2 : null
    );

    const finalPayoutTx = await relaySettlement(
      oracleAdmin,
      { oracleId: stateOracle.oracleId, dlcRef: contractRef },
      {
        eventId: `${cacheId}-final-payout`,
        stateHash: `${cacheId}-final-payout`,
        settlementState: "SETTLED",
        payload: {
          mode: "bitvm_payout",
          cacheId,
          propertyId: shortProp.propertyId,
          amount: spec.share.amount,
          toAddress: spec.share.address
        }
      },
      settlementSigner,
      null
    );

    let finalOutcome;
    if (applyImmediate) {
      if (spec.verdict === "reject") {
        await applyTxNow(finalPayoutTx, oracleAdmin, routeBaseBlock + 2);
        finalOutcome = { status: "released" };
      } else {
        const reason = await expectApplyFail(
          finalPayoutTx,
          oracleAdmin,
          routeBaseBlock + 2,
          /challenge upheld; payout blocked|challenged; payout blocked/i
        );
        finalOutcome = { status: "blocked", reason };
      }
    } else {
      finalOutcome = { status: "not-applied" };
    }

    const cacheDoc = await getCacheDoc(cacheId);
    routes.push({
      label: spec.label,
      verdict: spec.verdict,
      amount: spec.share.amount,
      winnerAddress: spec.share.address,
      challengerAddress: spec.challengerAddress,
      cacheId,
      cacheAddress,
      cacheTx,
      earlyPayoutTx,
      earlyPayoutFailure,
      challengeTx,
      resolveTx,
      finalPayoutTx,
      finalOutcome,
      cacheStatus: cacheDoc?.status || "unknown",
      challengeDeadlineBlock: Number(cacheDoc?.challengeDeadlineBlock || 0)
    });
  }

  const finalBalances = {
    alice: await tally(alice, shortProp.propertyId),
    bob: await tally(bob, shortProp.propertyId),
    charlie: await tally(charlie, shortProp.propertyId)
  };
  const balanceDeltas = {
    alice: diffBalances(preSettlementBalances.alice, finalBalances.alice),
    bob: diffBalances(preSettlementBalances.bob, finalBalances.bob),
    charlie: diffBalances(preSettlementBalances.charlie, finalBalances.charlie)
  };

  const expectedAliceDelta = floor8(routerPlan.bucketLossAmount + routeSpecs[0].share.amount);
  const expectedBobDelta = floor8(-(routerPlan.bucketLossAmount + routeSpecs[0].share.amount));
  const expectedCharlieDelta = 0;

  assertClose("alice available delta", balanceDeltas.alice.available, expectedAliceDelta);
  assertClose("bob available delta", balanceDeltas.bob.available, expectedBobDelta);
  assertClose("charlie available delta", balanceDeltas.charlie.available, expectedCharlieDelta);

  if (routes[0].finalOutcome.status !== "released") {
    throw new Error(`reject route did not release payout: ${routes[0].finalOutcome.status}`);
  }
  if (routes[1].finalOutcome.status !== "blocked") {
    throw new Error(`uphold route did not block payout: ${routes[1].finalOutcome.status}`);
  }
  if (routes[0].cacheStatus !== "RELEASED") {
    throw new Error(`reject route cache status mismatch: ${routes[0].cacheStatus}`);
  }
  if (routes[1].cacheStatus !== "RESOLVED_UPHELD") {
    throw new Error(`uphold route cache status mismatch: ${routes[1].cacheStatus}`);
  }

  console.log("[procedural-router-dispute-live] SUCCESS");
  console.log(
    JSON.stringify(
      {
        admin,
        oracleAdmin,
        alice,
        bob,
        charlie,
        activated,
        stateOracleId: stateOracle.oracleId,
        priceOracleId: priceOracle.oracleId,
        shortPropertyId: shortProp.propertyId,
        templateId,
        contractRef,
        entryPriceTx,
        exitPriceTx,
        createSeriesTx,
        contractId: newestContract.id,
        contractTicker: newestContract.ticker,
        contractExpiryPeriod: newestContract.expiryPeriod,
        grant,
        preludeSummary,
        routerPlan,
        bucketSweepTx,
        routes,
        preSettlementBalances,
        finalBalances,
        balanceDeltas
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  console.error("[procedural-router-dispute-live] failed:", err && err.stack ? err.stack : err);
  process.exit(1);
});
