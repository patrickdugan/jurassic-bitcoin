param(
    [int]$TargetHeight = 281472,
    [string]$RpcUrl = "http://127.0.0.1:8332",
    [string]$RpcUser = "jurassic",
    [string]$RpcPass = "jurassic-pass-local",
    [string]$RepoRoot = "C:\projects\BitcoinConsensusObservatory\jurassic-bitcoin",
    [string]$OutCorpus = "corpus/era-mainnet-2013",
    [int]$PollSeconds = 30
)

$ErrorActionPreference = "Stop"
$logDir = Join-Path $RepoRoot "artifacts\watch"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logPath = Join-Path $logDir "watch-stop-extract-2013.log"

function Write-Log([string]$msg) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    $line | Tee-Object -FilePath $logPath -Append
}

function Rpc-Call([string]$method, [object[]]$params) {
    $pair = "$RpcUser`:$RpcPass"
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $body = @{
        jsonrpc = "1.0"
        id = "jb-watch"
        method = $method
        params = $params
    } | ConvertTo-Json -Compress
    $resp = Invoke-RestMethod -Uri $RpcUrl -Method Post -Headers @{ Authorization = "Basic $auth" } -Body $body -ContentType "text/plain"
    return $resp.result
}

Write-Log "watchdog started target_height=$TargetHeight"
while ($true) {
    try {
        $info = Rpc-Call -method "getblockchaininfo" -params @()
        $h = [int]$info.blocks
        $headers = [int]$info.headers
        $ibd = [bool]$info.initialblockdownload
        Write-Log "status blocks=$h headers=$headers ibd=$ibd progress=$($info.verificationprogress)"
        if ($h -ge $TargetHeight) {
            Write-Log "target reached: blocks=$h >= $TargetHeight"
            break
        }
    } catch {
        Write-Log "rpc poll error: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $PollSeconds
}

try {
    Write-Log "stopping bitcoind via rpc stop"
    [void](Rpc-Call -method "stop" -params @())
} catch {
    Write-Log "rpc stop returned: $($_.Exception.Message)"
}

Start-Sleep -Seconds 5

Write-Log "running extract-era 0..$TargetHeight to $OutCorpus"
$env:BITCOIND_RPC_URL = $RpcUrl
$env:BITCOIND_RPC_USER = $RpcUser
$env:BITCOIND_RPC_PASS = $RpcPass

Push-Location $RepoRoot
try {
    cargo run -q -p jurassic-bitcoin-cli -- extract-era --start-height 0 --end-height $TargetHeight --limit-per-height 10 --out-corpus $OutCorpus --force 2>&1 | Tee-Object -FilePath $logPath -Append
    Write-Log "extract-era completed"
} finally {
    Pop-Location
}
