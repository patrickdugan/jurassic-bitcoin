# BTC Testnet4 LNBTC Deposit Grant Run

Date: 2026-05-04

This run used the local Bitcoin Core testnet4 wallet at `D:\BitcoinTestnet`
with wallet `utxoref-testnet`.

## Result

- Token property: `tlBTC` / property `1`
- Deposit receipt mode: `mock-settled` LN receipt
- Token amount: `0.00001000`
- Destination wallet address: `tb1qwvzaayzrgreqyyvxp77wlr60ngaqnpcyhujz2m`
- Bitcoin testnet4 grant txid:
  `7dec37bebf56575abd5e3fb48e7fbe1c278cb7d1f78356fe0b2c4113b759464d`
- Explorer:
  `https://mempool.space/testnet4/tx/7dec37bebf56575abd5e3fb48e7fbe1c278cb7d1f78356fe0b2c4113b759464d`

The grant transaction is currently a mempool transaction, and the local
TradeLayer DB has been immediately applied so the desktop/listener path can see
the token balance before waiting for testnet4 mining.

## Verification

TradeLayer listener:

```powershell
Invoke-WebRequest 'http://127.0.0.1:3000/tl_getAllBalancesForAddress' `
  -Method Post `
  -ContentType 'application/json' `
  -Body (@{ params='tb1qwvzaayzrgreqyyvxp77wlr60ngaqnpcyhujz2m' } | ConvertTo-Json) `
  -UseBasicParsing
```

Observed response:

```json
[
  {
    "propertyId": "1",
    "ticker": "tlBTC",
    "amount": 0.00001,
    "available": 0.00001,
    "reserved": 0,
    "margin": 0,
    "vesting": 0,
    "channel": 0
  }
]
```

## Reproduction

The harness is:

```powershell
node .\scripts\bitcoin-testnet4\lnbtc_deposit_grant.js --amount-sats=1000
```

If the transaction already exists and only local TradeLayer state needs to be
recovered/applied:

```powershell
node .\scripts\bitcoin-testnet4\lnbtc_deposit_grant.js `
  --recover-txid=7dec37bebf56575abd5e3fb48e7fbe1c278cb7d1f78356fe0b2c4113b759464d
```

Artifacts:

- `artifacts/bitcoin-testnet4/lnbtc-deposit-grant-latest.json`
- `artifacts/bitcoin-testnet4/lnbtc-deposit-grant-latest.md`
- `artifacts/bitcoin-testnet4/walletListener-btctest.log`

## Notes

The local DB was missing the earlier on-chain `tlBTC` property issuance while
later BTCTEST artifacts already referenced property `1`. The harness repairs
that local property metadata from the prior setup transaction before applying
the grant:

`55e9da04a59c9cc4596ff6443e3bb0b24e5a6bb790b91827c902744664828ac5`

This is a local index-state repair, not a new issuance.
