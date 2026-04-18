param(
    [string]$RepoRoot = "C:\projects\BitcoinConsensusObservatory\jurassic-bitcoin",
    [string]$DataDir = "E:\D_Drive_Archive\BlockchainData\bitcoin-mainnet",
    [string]$RpcUrl = "http://127.0.0.1:8332",
    [string]$RpcUser = "jurassic",
    [string]$RpcPass = "jurassic-pass-local",
    [string]$VolumeLetter = "E:",
    [string]$VolumeSerial = "WX82EC0AYA9A",
    [int]$PollSeconds = 20,
    [int]$LogTailLines = 120
)

$ErrorActionPreference = "Stop"

$logDir = Join-Path $RepoRoot "artifacts\watch"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logPath = Join-Path $logDir "monitor-mainnet-e.log"

function Write-Log([string]$msg) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    $line | Tee-Object -FilePath $logPath -Append
}

function Rpc-Call([string]$method, [object[]]$params) {
    $pair = "$RpcUser`:$RpcPass"
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $body = @{
        jsonrpc = "1.0"
        id = "jb-monitor"
        method = $method
        params = $params
    } | ConvertTo-Json -Compress
    $resp = Invoke-RestMethod -Uri $RpcUrl -Method Post -Headers @{ Authorization = "Basic $auth" } -Body $body -ContentType "text/plain"
    return $resp.result
}

function Get-LatestTxindexSyncHeight {
    $debugLog = Join-Path $DataDir "debug.log"
    if (-not (Test-Path $debugLog)) {
        return $null
    }
    $match = Get-Content $debugLog -Tail $LogTailLines |
        Select-String -Pattern "Syncing txindex with block chain from height (\d+)" |
        Select-Object -Last 1
    if ($null -eq $match) {
        return $null
    }
    return [int]$match.Matches[0].Groups[1].Value
}

function Get-NewVolumeEvents([datetime]$since) {
    $events = Get-WinEvent -FilterHashtable @{ LogName = "System"; StartTime = $since } -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProviderName -match "disk|Ntfs|Kernel-PnP|USBSTOR" -or
            $_.Message -match [regex]::Escape($VolumeLetter) -or
            $_.Message -match [regex]::Escape($VolumeSerial)
        } |
        Sort-Object TimeCreated
    return @($events)
}

$lastBlocks = $null
$lastHeaders = $null
$lastTxindexHeight = $null
$lastEventCheck = (Get-Date).AddMinutes(-10)

Write-Log "monitor started datadir=$DataDir rpc=$RpcUrl volume=$VolumeLetter"

if (-not (Test-Path $DataDir)) {
    Write-Log "warning datadir_missing path=$DataDir"
}

$startupEvents = Get-NewVolumeEvents -since $lastEventCheck
foreach ($event in $startupEvents) {
    $msg = ($event.Message -replace "\s+", " ").Trim()
    Write-Log ("event provider={0} id={1} level={2} time={3} msg={4}" -f $event.ProviderName, $event.Id, $event.LevelDisplayName, $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $msg)
}
$lastEventCheck = Get-Date

while ($true) {
    try {
        $info = Rpc-Call -method "getblockchaininfo" -params @()
        $blocks = [int]$info.blocks
        $headers = [int]$info.headers
        $ibd = [bool]$info.initialblockdownload
        $progress = [double]$info.verificationprogress
        $txindexHeight = Get-LatestTxindexSyncHeight

        $blockDelta = if ($null -eq $lastBlocks) { 0 } else { $blocks - $lastBlocks }
        $headerDelta = if ($null -eq $lastHeaders) { 0 } else { $headers - $lastHeaders }
        $txindexDelta = if ($null -eq $txindexHeight -or $null -eq $lastTxindexHeight) { "na" } else { ($txindexHeight - $lastTxindexHeight).ToString() }

        Write-Log ("status blocks={0} headers={1} ibd={2} progress={3:N6} block_delta={4} header_delta={5} txindex_height={6} txindex_delta={7}" -f $blocks, $headers, $ibd, $progress, $blockDelta, $headerDelta, $(if ($null -eq $txindexHeight) { "na" } else { $txindexHeight }), $txindexDelta)

        $lastBlocks = $blocks
        $lastHeaders = $headers
        $lastTxindexHeight = $txindexHeight
    } catch {
        Write-Log "rpc error $($_.Exception.Message)"
    }

    $events = Get-NewVolumeEvents -since $lastEventCheck
    foreach ($event in $events) {
        $msg = ($event.Message -replace "\s+", " ").Trim()
        Write-Log ("event provider={0} id={1} level={2} time={3} msg={4}" -f $event.ProviderName, $event.Id, $event.LevelDisplayName, $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $msg)
    }
    $lastEventCheck = Get-Date

    Start-Sleep -Seconds $PollSeconds
}
