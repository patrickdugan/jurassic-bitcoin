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

async function main() {
  const applyImmediate = benv("TL_APPLY_IMMEDIATE", true);
  const admin = env("TL_ADMIN_ADDRESS");
  const oracleAdmin = env("TL_ORACLE_ADMIN_ADDRESS", admin);
  const alice = env("TL_ALICE_ADDRESS");
  const grantAmount = nenv("TL_TRANSCRIPT_GRANT_AMOUNT", 0.003);
  const propertyTicker = env("TL_TRANSCRIPT_TICKER", `TMA${Date.now().toString().slice(-4)}`);
  const oracleTicker = env("TL_TRANSCRIPT_ORACLE_TICKER", `TMO${Date.now().toString().slice(-4)}`);
  const templateId = env("TL_TEMPLATE_ID", `tpl-transcript-${Date.now()}`);
  const contractRef = env("TL_CONTRACT_REF", `ct-transcript-${Date.now()}`);

  if (!admin || !oracleAdmin || !alice) {
    throw new Error("Missing TL_ADMIN_ADDRESS / TL_ORACLE_ADMIN_ADDRESS / TL_ALICE_ADDRESS");
  }

  await TxUtils.init();
  await Activation.getInstance().init();
  const chain = await TxUtils.client.getBlockchainInfo();
  if (chain.chain !== "test") throw new Error(`Expected testnet, got ${chain.chain}`);

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
      mode: "transcript_alias"
    })
  );

  await ProceduralRegistry.upsertTemplate(templateId, {
    oracleId: oracle.oracleId,
    collateralPropertyId: prop.propertyId,
    receiptPropertyId: prop.propertyId,
    templateHash
  });
  await ProceduralRegistry.upsertContract(contractRef, templateId, "FUNDED", {
    mode: "transcript_alias"
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

  const payloadDoc = {
    stateRoot: sha256Hex(
      JSON.stringify({
        mode: "transcript_alias",
        propertyId: prop.propertyId,
        holderAddress: alice,
        amount: grant.grantedAmount,
        templateId,
        contractRef
      })
    ),
    transitions: [],
    propertyId: prop.propertyId,
    holderAddress: alice,
    amount: grant.grantedAmount,
    templateId,
    contractRef,
    mode: "transcript_alias"
  };
  const balancePayloadB64 = encodeBalancePayload(payloadDoc);
  const payloadHash = sha256Hex(Buffer.from(balancePayloadB64, "base64"));
  const stateHash = payloadHash;

  const signer = createOracleSigner();
  const aliases = [
    {
      aliasTag: "aa",
      eventId: `${contractRef}-alias-aa`,
      timestamp: Math.floor(Date.now() / 1000)
    },
    {
      aliasTag: "aaaa",
      eventId: `${contractRef}-alias-aaaa`,
      timestamp: Math.floor(Date.now() / 1000) + 11
    }
  ];

  const relayTxs = [];
  const baseBlock = await TxUtils.getBlockCount();
  for (let idx = 0; idx < aliases.length; idx++) {
    const alias = aliases[idx];
    const signed = signer.signBundle({
      eventId: alias.eventId,
      outcome: "STATE_OPEN",
      outcomeIndex: 0,
      stateHash,
      payloadHash,
      timestamp: alias.timestamp
    });
    const relayBlob = relayBlobDocToBase64({
      ...signed,
      aliasTag: alias.aliasTag,
      balancePayloadB64,
      statementTag: `transcript_alias_${alias.aliasTag}`
    });
    const txid = await TxUtils.createStakeFraudProofTransaction(oracleAdmin, {
      action: 2,
      oracleId: oracle.oracleId,
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
    relayTxs.push({
      aliasTag: alias.aliasTag,
      eventId: alias.eventId,
      txid,
      blockHeight: applyBlock,
      signatureHex: signed.signatureHex
    });
  }

  const oracleDataDb = await db.getDatabase("oracleData");
  const relayDocs = await oracleDataDb.findAsync({ type: "relay", oracleId: oracle.oracleId, dlcRef: contractRef });
  const sigDocs = await oracleDataDb.findAsync({ type: "relaySigUse", oracleId: oracle.oracleId, dlcRef: contractRef });

  console.log("[procedural-transcript-alias-live] SUCCESS");
  console.log(
    JSON.stringify(
      {
        admin,
        oracleAdmin,
        alice,
        activated,
        oracleId: oracle.oracleId,
        propertyId: prop.propertyId,
        templateId,
        contractRef,
        templateHash,
        grant,
        stateHash,
        payloadHash,
        acceptedRelayCount: relayDocs.length,
        signatureUseCount: sigDocs.length,
        relayTxs
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  console.error("[procedural-transcript-alias-live] failed:", err && err.stack ? err.stack : err);
  process.exit(1);
});
