# bitcoind Windows Regtest (Pruned, D:\)

This setup keeps chain data on `D:\` and binds RPC to localhost only.

## Recommended Datadir

- `D:\bitcoin-regtest`

## Config Steps

1. Create datadir:
   - `mkdir D:\bitcoin-regtest`
2. Copy config template:
   - from `configs/bitcoin.regtest.pruned.conf`
   - to `D:\bitcoin-regtest\bitcoin.conf`
3. Set your RPC credentials in `bitcoin.conf`:
   - `rpcuser=...`
   - `rpcpassword=...`

## Safe Defaults

- `regtest=1`
- `server=1`
- `prune=550`
- `txindex=0` (prune-friendly)
- `fallbackfee=0.0002`
- `rpcbind=127.0.0.1`
- `rpcallowip=127.0.0.1`
- RPC port: `18443`

## Start bitcoind

```powershell
bitcoind -datadir="D:\bitcoin-regtest" -conf="D:\bitcoin-regtest\bitcoin.conf"
```

Optional explicit start form:

```powershell
bitcoind -datadir="D:\bitcoin-regtest" -conf="D:\bitcoin-regtest\bitcoin.conf" -regtest -server -prune=550 -txindex=0 -fallbackfee=0.0002 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1
```

## Stop bitcoind

```powershell
bitcoin-cli -datadir="D:\bitcoin-regtest" stop
```

## Harness Environment

Set in your shell before running the harness:

```powershell
$env:BITCOIND_RPC_URL="http://127.0.0.1:18443"
$env:BITCOIND_RPC_USER="<rpcuser>"
$env:BITCOIND_RPC_PASS="<rpcpassword>"
```

Optional for clearer doctor output:

```powershell
$env:JB_BITCOIND_DATADIR="D:\bitcoin-regtest"
```
