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

const APPLICATIONS = {
  oracle_sidecar: {
    appId: "oracle_sidecar_mesh",
    mode: "oracle_sidecar_mesh",
    role: "dlc_oracle_sidecar",
    propertyPrefix: "OSM",
    oraclePrefix: "OSO",
    templatePrefix: "tpl-oracle-sidecar",
    contractPrefix: "ct-oracle-sidecar",
    requiresBob: true,
    aliasTags: ["fast_attest", "full_attest"],
    namespaceRefs: ["oracle-sidecar-v0", "oracle-sidecar-v1"],
    carrierHints: [
      { carrierLabel: "spray202_oracle_cover", placementMode: "redistribution_spray", ordinaryCover: "2013 payout spray" },
      { carrierLabel: "exact100_oracle_cover", placementMode: "exact_value_batch", ordinaryCover: "2013 exact-value batch" }
    ],
    payloadDoc({ propertyId, holderAddress, secondaryAddress, amount, templateId, contractRef }) {
      return {
        stateRoot: sha256Hex(
          JSON.stringify({
            mode: "oracle_sidecar_mesh",
            propertyId,
            primaryOracle: holderAddress,
            secondaryWatcher: secondaryAddress,
            amount,
            templateId,
            contractRef
          })
        ),
        transitions: [],
        propertyId,
        holderAddress,
        secondaryAddress,
        amount,
        templateId,
        contractRef,
        role: "dlc_oracle_sidecar",
        publicationShapes: ["redistribution_spray", "exact_value_batch"]
      };
    }
  },
  watchtower_beacon: {
    appId: "watchtower_beacon_mesh",
    mode: "watchtower_beacon_mesh",
    role: "watchtower_beacon",
    propertyPrefix: "WTM",
    oraclePrefix: "WTO",
    templatePrefix: "tpl-watchtower",
    contractPrefix: "ct-watchtower",
    requiresBob: true,
    aliasTags: ["beacon_compact", "beacon_full"],
    namespaceRefs: ["alert-handle-0", "alert-handle-32"],
    carrierHints: [
      { carrierLabel: "rebalance_cover", placementMode: "ordinary_rebalance", ordinaryCover: "wallet rebalance cadence" },
      { carrierLabel: "sweep_cover", placementMode: "payout_sweep", ordinaryCover: "routine payout sweep" }
    ],
    payloadDoc({ propertyId, holderAddress, secondaryAddress, amount, templateId, contractRef }) {
      return {
        stateRoot: sha256Hex(
          JSON.stringify({
            mode: "watchtower_beacon_mesh",
            propertyId,
            watcherAddress: holderAddress,
            monitoredAddress: secondaryAddress,
            amount,
            templateId,
            contractRef
          })
        ),
        transitions: [],
        propertyId,
        holderAddress,
        secondaryAddress,
        amount,
        templateId,
        contractRef,
        role: "watchtower_beacon",
        alertClass: "fraud_monitor",
        cadenceWindows: ["near_expiry", "post_challenge"]
      };
    }
  },
  statechain_handoff: {
    appId: "statechain_handoff_mesh",
    mode: "statechain_handoff_mesh",
    role: "statechain_handoff",
    propertyPrefix: "SCM",
    oraclePrefix: "SCO",
    templatePrefix: "tpl-statechain",
    contractPrefix: "ct-statechain",
    requiresBob: true,
    aliasTags: ["handoff_ack", "handoff_finalize"],
    namespaceRefs: ["handoff-handle-0", "handoff-handle-32"],
    carrierHints: [
      { carrierLabel: "checkpoint_consolidation", placementMode: "ordinary_consolidation", ordinaryCover: "wallet consolidation" },
      { carrierLabel: "checkpoint_payout", placementMode: "settlement_batch", ordinaryCover: "settlement batch payout" }
    ],
    payloadDoc({ propertyId, holderAddress, secondaryAddress, amount, templateId, contractRef }) {
      return {
        stateRoot: sha256Hex(
          JSON.stringify({
            mode: "statechain_handoff_mesh",
            propertyId,
            currentOwner: holderAddress,
            nextOwner: secondaryAddress,
            amount,
            templateId,
            contractRef
          })
        ),
        transitions: [],
        propertyId,
        holderAddress,
        secondaryAddress,
        amount,
        templateId,
        contractRef,
        role: "statechain_handoff",
        checkpointModes: ["handoff_ack", "handoff_finalize"]
      };
    }
  }
};

async function setupTemplateAndGrant(config, admin, oracleAdmin, alice, bob, applyImmediate) {
  const grantAmount = nenv("TL_APPLICATION_GRANT_AMOUNT", 0.003);
  const propertyTicker = env("TL_APPLICATION_TICKER", `${config.propertyPrefix}${Date.now().toString().slice(-4)}`);
  const oracleTicker = env("TL_APPLICATION_ORACLE_TICKER", `${config.oraclePrefix}${Date.now().toString().slice(-4)}`);
  const templateId = env("TL_TEMPLATE_ID", `${config.templatePrefix}-${Date.now()}`);
  const contractRef = env("TL_CONTRACT_REF", `${config.contractPrefix}-${Date.now()}`);

  const activated = [];
  for (const txType of [1, 11, 13, 30]) {
    activated.push({ txType, txid: await activateIfNeeded(admin, txType, applyImmediate) });
  }

  const oracle = await createOracle(oracleAdmin, oracleTicker, applyImmediate);
  const prop = await issueManagedProperty(admin, propertyTicker, applyImmediate, 1);
  const templateHash = sha256Hex(
    JSON.stringify({
      templateId,
      oracleId: oracle.oracleId,
      propertyId: prop.propertyId,
      contractRef,
      mode: config.mode
    })
  );

  await ProceduralRegistry.upsertTemplate(templateId, {
    oracleId: oracle.oracleId,
    collateralPropertyId: prop.propertyId,
    receiptPropertyId: prop.propertyId,
    templateHash
  });
  await ProceduralRegistry.upsertContract(contractRef, templateId, "FUNDED", {
    mode: config.mode
  });

  const grant = await grantManaged(
    admin,
    prop.propertyId,
    grantAmount,
    alice,
    templateId,
    contractRef,
    applyImmediate,
    templateHash
  );

  const payloadDoc = config.payloadDoc({
    propertyId: prop.propertyId,
    holderAddress: alice,
    secondaryAddress: bob,
    amount: grant.grantedAmount,
    templateId,
    contractRef
  });
  const balancePayloadB64 = encodeBalancePayload(payloadDoc);
  const payloadHash = sha256Hex(Buffer.from(balancePayloadB64, "base64"));
  const stateHash = payloadHash;

  return {
    activated,
    oracle,
    prop,
    templateId,
    contractRef,
    templateHash,
    grant,
    payloadDoc,
    balancePayloadB64,
    payloadHash,
    stateHash
  };
}

async function publishTranscriptRelays(config, oracleAdmin, oracleId, contractRef, stateHash, payloadHash, balancePayloadB64, applyImmediate, baseBlock) {
  const signer = createOracleSigner();
  const relays = [];

  for (let idx = 0; idx < config.aliasTags.length; idx++) {
    const aliasTag = config.aliasTags[idx];
    const carrierHint = config.carrierHints[idx % config.carrierHints.length];
    const signed = signer.signBundle({
      eventId: `${contractRef}-${aliasTag}`,
      outcome: "STATE_OPEN",
      outcomeIndex: 0,
      stateHash,
      payloadHash,
      timestamp: Math.floor(Date.now() / 1000) + idx * 11
    });
    const relayBlob = relayBlobDocToBase64({
      ...signed,
      aliasTag,
      statementTag: `${config.appId}_${aliasTag}`,
      applicationTag: config.appId,
      carrierHint,
      balancePayloadB64
    });
    const txid = await TxUtils.createStakeFraudProofTransaction(oracleAdmin, {
      action: 2,
      oracleId,
      relayType: 2,
      stateHash,
      dlcRef: contractRef,
      settlementState: "OPEN",
      relayBlob
    });
    const applyBlock = baseBlock + idx;
    if (applyImmediate) {
      await applyTxNow(txid, oracleAdmin, applyBlock);
    }
    relays.push({
      aliasTag,
      txid,
      blockHeight: applyBlock,
      carrierLabel: carrierHint.carrierLabel,
      placementMode: carrierHint.placementMode,
      signatureHex: signed.signatureHex
    });
  }

  return relays;
}

async function publishNamespaceRelays(config, oracleAdmin, oracleId, contractRef, stateHash, payloadHash, balancePayloadB64, applyImmediate, baseBlock) {
  const signer = createOracleSigner();
  const shared = signer.signBundle({
    eventId: `${contractRef}-namespace`,
    outcome: "STATE_OPEN",
    outcomeIndex: 0,
    stateHash,
    payloadHash,
    timestamp: Math.floor(Date.now() / 1000) + 31
  });
  const relays = [];

  for (let idx = 0; idx < config.namespaceRefs.length; idx++) {
    const blobRef = `${contractRef}-${config.namespaceRefs[idx]}`;
    const carrierHint = config.carrierHints[idx % config.carrierHints.length];
    const relayBlob = relayBlobDocToBase64({
      ...shared,
      blobRef,
      namespaceTag: config.namespaceRefs[idx],
      applicationTag: config.appId,
      carrierHint,
      balancePayloadB64
    });
    const txid = await TxUtils.createStakeFraudProofTransaction(oracleAdmin, {
      action: 2,
      oracleId,
      relayType: 2,
      stateHash,
      dlcRef: contractRef,
      settlementState: "OPEN",
      relayBlob
    });
    const applyBlock = baseBlock + idx;
    if (applyImmediate) {
      await applyTxNow(txid, oracleAdmin, applyBlock);
    }
    relays.push({
      blobRef,
      namespaceTag: config.namespaceRefs[idx],
      txid,
      blockHeight: applyBlock,
      carrierLabel: carrierHint.carrierLabel,
      placementMode: carrierHint.placementMode,
      signatureHex: shared.signatureHex
    });
  }

  return relays;
}

async function runApplicationMesh(mode) {
  const config = APPLICATIONS[mode];
  if (!config) {
    throw new Error(`Unknown application mode ${mode}`);
  }

  const applyImmediate = benv("TL_APPLY_IMMEDIATE", true);
  const admin = env("TL_ADMIN_ADDRESS");
  const oracleAdmin = env("TL_ORACLE_ADMIN_ADDRESS", admin);
  const alice = env("TL_ALICE_ADDRESS");
  const bob = env("TL_BOB_ADDRESS");

  if (!admin || !oracleAdmin || !alice || (config.requiresBob && !bob)) {
    throw new Error("Missing TL_ADMIN_ADDRESS / TL_ORACLE_ADMIN_ADDRESS / TL_ALICE_ADDRESS / TL_BOB_ADDRESS");
  }

  await TxUtils.init();
  await Activation.getInstance().init();
  const chain = await TxUtils.client.getBlockchainInfo();
  if (chain.chain !== "test") throw new Error(`Expected testnet, got ${chain.chain}`);

  const context = await setupTemplateAndGrant(config, admin, oracleAdmin, alice, bob, applyImmediate);
  const baseBlock = await TxUtils.getBlockCount();
  const transcriptRelays = await publishTranscriptRelays(
    config,
    oracleAdmin,
    context.oracle.oracleId,
    context.contractRef,
    context.stateHash,
    context.payloadHash,
    context.balancePayloadB64,
    applyImmediate,
    baseBlock
  );
  const namespaceRelays = await publishNamespaceRelays(
    config,
    oracleAdmin,
    context.oracle.oracleId,
    context.contractRef,
    context.stateHash,
    context.payloadHash,
    context.balancePayloadB64,
    applyImmediate,
    baseBlock + transcriptRelays.length
  );

  const oracleDataDb = await db.getDatabase("oracleData");
  const relayDocs = await oracleDataDb.findAsync({
    type: "relay",
    oracleId: context.oracle.oracleId,
    dlcRef: context.contractRef,
    relayType: 2
  });
  const sigDocs = await oracleDataDb.findAsync({
    type: "relaySigUse",
    oracleId: context.oracle.oracleId,
    dlcRef: context.contractRef
  });

  return {
    mode,
    appId: config.appId,
    role: config.role,
    admin,
    oracleAdmin,
    alice,
    bob,
    activated: context.activated,
    oracleId: context.oracle.oracleId,
    propertyId: context.prop.propertyId,
    templateId: context.templateId,
    contractRef: context.contractRef,
    templateHash: context.templateHash,
    grant: context.grant,
    stateHash: context.stateHash,
    payloadHash: context.payloadHash,
    acceptedRelayCount: relayDocs.length,
    signatureUseCount: sigDocs.length,
    transcriptRelays,
    namespaceRelays,
    carrierHints: config.carrierHints,
    publicationSurfaces: config.carrierHints.map((hint) => hint.ordinaryCover)
  };
}

module.exports = {
  runApplicationMesh
};
