param(
    [string]$DataDir = "D:\bitcoin-regtest",
    [int]$PruneMiB = 550,
    [int]$RpcPort = 18443,
    [switch]$Daemon
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$bitcoind = Join-Path $repoRoot "tools\bitcoin-core-30.2\bitcoin-30.2\bin\bitcoind.exe"

if (-not (Test-Path $bitcoind)) {
    throw "bitcoind not found at $bitcoind"
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$args = @(
    "-regtest",
    "-server",
    "-txindex=0",
    "-fallbackfee=0.0002",
    "-prune=$PruneMiB",
    "-datadir=$DataDir",
    "-rpcport=$RpcPort",
    "-rpcbind=127.0.0.1",
    "-rpcallowip=127.0.0.1"
)

if ($Daemon) {
    $args += "-daemon"
}

& $bitcoind @args
