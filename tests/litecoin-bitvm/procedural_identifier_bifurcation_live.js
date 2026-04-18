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
  const grantAmount = nenv("TL_IDENTIFIER_GRANT_AMOUNT", 0.003);
  const propertyTicker = env("TL_IDENTIFIER_TICKER", `IDB${Date.now().toString().slice(-4)}`);
  const oracleTicker = env("TL_IDENTIFIER_ORACLE_TICKER", `IDO${Date.now().toString().slice(-4)}`);
  const templateId = env("TL_TEMPLATE_ID", `tpl-identifier-${Date.now()}`);
  const contractRef = env("TL_CONTRACT_REF", `ct-identifier-${Date.now()}`);

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
      mode: "identifier_bifurcation"
    })
  );

  await ProceduralRegistry.upsertTemplate(templateId, {
    oracleId: oracle.oracleId,
    collateralPropertyId: prop.propertyId,
    receiptPropertyId: prop.propertyId,
    templateHash
  });
  await ProceduralRegistry.upsertContract(contractRef, templateId, "FUNDED", {
    mode: "identifier_bifurcation"
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
        mode: "identifier_bifurcation",
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
    mode: "identifier_bifurcation"
  };
  const balancePayloadB64 = encodeBalancePayload(payloadDoc);
  const payloadHash = sha256Hex(Buffer.from(balancePayloadB64, "base64"));
  const stateHash = payloadHash;

  const signer = createOracleSigner();
  const signed = signer.signBundle({
    eventId: `${contractRef}-identifier`,
    outcome: "STATE_OPEN",
    outcomeIndex: 0,
    stateHash,
    payloadHash,
    timestamp: Math.floor(Date.now() / 1000)
  });

  const namespaces = [
    { blobRef: `${contractRef}-namespace-zero`, namespaceTag: "dummy_zero" },
    { blobRef: `${contractRef}-namespace-32`, namespaceTag: "dummy_32" }
  ];

  const relayTxs = [];
  const baseBlock = await TxUtils.getBlockCount();
  for (let idx = 0; idx < namespaces.length; idx++) {
    const ns = namespaces[idx];
    const relayBlob = relayBlobDocToBase64({
      ...signed,
      blobRef: ns.blobRef,
      namespaceTag: ns.namespaceTag,
      balancePayloadB64
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
      blobRef: ns.blobRef,
      namespaceTag: ns.namespaceTag,
      txid,
      blockHeight: applyBlock,
      signatureHex: signed.signatureHex
    });
  }

  const oracleDataDb = await db.getDatabase("oracleData");
  const relayDocs = await oracleDataDb.findAsync({ type: "relay", oracleId: oracle.oracleId, dlcRef: contractRef });
  const sigDocs = await oracleDataDb.findAsync({ type: "relaySigUse", oracleId: oracle.oracleId, dlcRef: contractRef });

  console.log("[procedural-identifier-bifurcation-live] SUCCESS");
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
  console.error("[procedural-identifier-bifurcation-live] failed:", err && err.stack ? err.stack : err);
  process.exit(1);
});
