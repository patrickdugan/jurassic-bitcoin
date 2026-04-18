param(
    [string]$TradelayerRepo = "C:\projects\tradelayer.js",
    [string]$ArtifactDate = (Get-Date -Format "yyyy-MM-dd"),
    [string]$RpcWallet = "wallet.dat",
    [string]$AdminAddress = "tltc1qa0kd2d39nmeph3hvcx8ytv65ztcywg5sazhtw8",
    [string]$ChallengerAddress = "tltc1qwtgx0c9f92ww8gtat82zpsgu4gttwx37xzsf2v"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$artifactDir = Join-Path $repoRoot "artifacts\litecoin-bitvm\$ArtifactDate"
$script:SelectedAdminAddress = $AdminAddress
$script:SelectedAdminUtxo = $null
$script:Tx30ActivationState = $null
$script:RunActivation = $false
$script:PreflightMinedBlocks = @()
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null

function Invoke-LitecoinRpc {
    param(
        [string]$Method,
        [object[]]$Params = @(),
        [string]$Wallet
    )

    $body = @{
        jsonrpc = "1.0"
        id = "litecoin-bitvm"
        method = $Method
        params = $Params
    } | ConvertTo-Json -Compress -Depth 20

    $uri = if ($Wallet) {
        "http://127.0.0.1:19332/wallet/$Wallet"
    } else {
        "http://127.0.0.1:19332/"
    }

    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("user:pass"))
    Invoke-RestMethod -Uri $uri -Method Post -Headers @{ Authorization = "Basic $auth" } -Body $body -ContentType "text/plain"
}

function Get-AdminSpendableUtxos {
    param(
        [int]$MinConf
    )

    @((Invoke-LitecoinRpc -Method "listunspent" -Wallet $RpcWallet -Params @($MinConf, 9999999, @($AdminAddress), $true, @{ minimumAmount = 0.00010000 })).result) |
        Where-Object { $_.spendable -eq $true -and $_.safe -ne $false }
}

function Wait-ForAdminSpendableUtxos {
    param(
        [int]$MinConf = 1,
        [int]$Attempts = 30,
        [int]$DelaySeconds = 2
    )

    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        $confirmed = @(Get-AdminSpendableUtxos -MinConf $MinConf)
        if ($confirmed.Count -gt 0) {
            return $confirmed
        }
        Start-Sleep -Seconds $DelaySeconds
    }

    return @(Get-AdminSpendableUtxos -MinConf $MinConf)
}

function Ensure-LitecoinPreflight {
    Write-Host "preflight: checking LTCTEST RPC"
    $chain = (Invoke-LitecoinRpc -Method "getblockchaininfo").result
    if ($chain.chain -ne "test") {
        throw "expected Litecoin testnet chain, got $($chain.chain)"
    }

    $loaded = @((Invoke-LitecoinRpc -Method "listwallets").result)
    if ($loaded -notcontains $RpcWallet) {
        $null = Invoke-LitecoinRpc -Method "loadwallet" -Params @($RpcWallet)
    }

    $script:SelectedAdminAddress = $AdminAddress

    $preferredAny = @(Get-AdminSpendableUtxos -MinConf 0)
    $preferredConfirmed = @(Get-AdminSpendableUtxos -MinConf 1)

    if ($preferredConfirmed.Count -eq 0 -and $preferredAny.Count -gt 0) {
        Write-Host "preflight: requested admin has only unconfirmed spendable UTXOs; using wallet-visible zero-conf funds"
    } elseif ($preferredConfirmed.Count -eq 0 -and $preferredAny.Count -eq 0) {
        Write-Host "preflight: funding requested admin address with 0.02 tLTC; not mining LTCTEST confirmations"
        $fundTxid = (Invoke-LitecoinRpc -Method "sendtoaddress" -Wallet $RpcWallet -Params @($AdminAddress, 0.02, "fund admin for local BitVM suite", "local-suite-admin-fund")).result
        $fundTxid | Out-File -FilePath (Join-Path $artifactDir "admin-funding.txid.txt") -Encoding ascii
        $preferredAny = @(Wait-ForAdminSpendableUtxos -MinConf 0)
    }

    $spendable = if ($preferredConfirmed.Count -gt 0) { $preferredConfirmed } else { $preferredAny }
    if ($spendable.Count -eq 0) {
        throw "requested admin address $AdminAddress has no wallet-visible spendable UTXO after preflight"
    }

    $script:SelectedAdminUtxo = $spendable |
        Sort-Object @{ Expression = { [decimal]$_.amount }; Descending = $true }, @{ Expression = { [int]$_.confirmations }; Descending = $true } |
        Select-Object -First 1
    Write-Host "preflight: using requested admin address $AdminAddress with spendable UTXO $($script:SelectedAdminUtxo.txid):$($script:SelectedAdminUtxo.vout) ($($script:SelectedAdminUtxo.confirmations) conf)"

    $script:SelectedAdminAddress | Out-File -FilePath (Join-Path $artifactDir "selected-admin-address.txt") -Encoding ascii
    ConvertTo-Json -InputObject $script:SelectedAdminUtxo -Depth 6 | Out-File -FilePath (Join-Path $artifactDir "selected-admin-utxo.json") -Encoding ascii
    ConvertTo-Json -InputObject $script:PreflightMinedBlocks -Depth 6 | Out-File -FilePath (Join-Path $artifactDir "preflight-mined-blocks.json") -Encoding ascii

    $activationProbe = @(& node (Join-Path $repoRoot "scripts\litecoin-bitvm\check_tx30_activation.js") 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "unable to query tx30 activation state"
    }

    $activationStart = -1
    for ($i = $activationProbe.Count - 1; $i -ge 0; $i--) {
        if ($activationProbe[$i].Trim() -eq "{") {
            $activationStart = $i
            break
        }
    }
    if ($activationStart -lt 0) {
        throw "unable to locate tx30 activation JSON payload"
    }

    $script:Tx30ActivationState = (($activationProbe[$activationStart..($activationProbe.Count - 1)] -join "`n") | ConvertFrom-Json)
    ($script:Tx30ActivationState | ConvertTo-Json -Depth 6) | Out-File -FilePath (Join-Path $artifactDir "tx30-activation-state.json") -Encoding ascii

    if ($script:Tx30ActivationState.tx30Active) {
        $script:RunActivation = $false
        Write-Host "preflight: tx30 already active; repeated suite will skip activation"
    } elseif ($script:SelectedAdminAddress -eq $script:Tx30ActivationState.admin) {
        $script:RunActivation = $true
        Write-Host "preflight: tx30 inactive; suite will activate from protocol admin $($script:Tx30ActivationState.admin)"
    } else {
        throw "tx30 inactive and selected admin $($script:SelectedAdminAddress) is not protocol admin $($script:Tx30ActivationState.admin)"
    }
}

function Invoke-LoggedNodeRun {
    param(
        [string]$Name,
        [string]$WorkingDir,
        [string[]]$Arguments,
        [hashtable]$ExtraEnv = @{}
    )

    $logPath = Join-Path $artifactDir "$Name.log"
    $mergedEnv = [ordered]@{
        CHAIN                   = "LTCTEST"
        RPC_HOST                = "127.0.0.1"
        RPC_PORT                = "19332"
        RPC_USER                = "user"
        RPC_PASS                = "pass"
        TIMEOUT_MS              = "180000"
        WALLET_NAME             = $RpcWallet
        RPC_WALLET              = $RpcWallet
        TL_APPLY_IMMEDIATE      = "true"
        TL_ADMIN_ADDRESS        = $script:SelectedAdminAddress
        TL_ORACLE_ADMIN_ADDRESS = $script:SelectedAdminAddress
        TL_LOSER_ADDRESS        = $script:SelectedAdminAddress
        TL_WINNER_ADDRESS       = $ChallengerAddress
        TL_CHALLENGER_ADDRESS   = $ChallengerAddress
        TL_BITVM_AMOUNT         = "0.01"
        TL_ORACLE_ID            = "1"
        TL_UTXO_MINCONF         = "1"
        TRADELAYER_REPO         = $TradelayerRepo
    }

    foreach ($pair in $ExtraEnv.GetEnumerator()) {
        $mergedEnv[$pair.Key] = [string]$pair.Value
    }

    $previous = @{}
    foreach ($key in $mergedEnv.Keys) {
        $previous[$key] = [Environment]::GetEnvironmentVariable($key, "Process")
        [Environment]::SetEnvironmentVariable($key, $mergedEnv[$key], "Process")
    }

    try {
        Push-Location $WorkingDir
        & node @Arguments 2>&1 | Tee-Object -FilePath $logPath | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "$Name failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
        foreach ($key in $mergedEnv.Keys) {
            [Environment]::SetEnvironmentVariable($key, $previous[$key], "Process")
        }
    }

    return $logPath
}

function Get-SingleRegexValue {
    param(
        [string[]]$Lines,
        [string]$Pattern,
        [int]$Group = 1
    )

    foreach ($line in $Lines) {
        $match = [regex]::Match($line, $Pattern)
        if ($match.Success) {
            return $match.Groups[$Group].Value
        }
    }
    return $null
}

function Get-PlanSummary {
    param(
        [string]$Verdict,
        [string]$LogPath
    )

    $lines = Get-Content $LogPath
    $status = if ($lines -match "status: 'blocked'") {
        "blocked"
    } elseif ($lines -match "status: 'released'") {
        "released"
    } else {
        "unknown"
    }

    [pscustomobject]@{
        name                 = "plan-a-$Verdict"
        verdict              = $Verdict
        log_path             = $LogPath
        activated_txid       = Get-SingleRegexValue -Lines $lines -Pattern "\[bitvm-plan-a-live\] activated tx30 ([0-9a-f]+)"
        cache_txid           = Get-SingleRegexValue -Lines $lines -Pattern "\[bitvm-plan-a-live\] cache lock tx ([0-9a-f]+)"
        challenge_txid       = Get-SingleRegexValue -Lines $lines -Pattern "\[bitvm-plan-a-live\] challenge tx ([0-9a-f]+)"
        resolve_txid         = Get-SingleRegexValue -Lines $lines -Pattern "\[bitvm-plan-a-live\] resolve\($Verdict\) tx ([0-9a-f]+)"
        final_payout_txid    = Get-SingleRegexValue -Lines $lines -Pattern "blockedPayoutTx: '([0-9a-f]+)'"
        final_status         = $status
        scam_rejection_seen  = [bool]($lines -match "\[bitvm-plan-a-live\] early/scam payout rejected")
    }
}

function Get-WatchtowerSummary {
    param(
        [string]$SeedLogPath,
        [string]$WatchtowerLogPath
    )

    $seedLines = Get-Content $SeedLogPath
    $seedStart = -1
    for ($i = $seedLines.Count - 1; $i -ge 0; $i--) {
        if ($seedLines[$i].Trim() -eq "{") {
            $seedStart = $i
            break
        }
    }
    if ($seedStart -lt 0) {
        throw "unable to locate seed JSON payload in $SeedLogPath"
    }

    $seedJson = (($seedLines[$seedStart..($seedLines.Count - 1)] -join "`n") | ConvertFrom-Json)
    $watchtowerLines = Get-Content $WatchtowerLogPath
    $submissionTxids = @([regex]::Matches(($watchtowerLines -join "`n"), "txid: '([0-9a-f]+)'") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)

    [pscustomobject]@{
        name                     = "watchtower-challenge"
        seed_log_path            = $SeedLogPath
        log_path                 = $WatchtowerLogPath
        seeded_cache_txid        = $seedJson.seedCacheTxid
        seeded_cache_id          = $seedJson.cacheId
        seeded_dlc_ref           = $seedJson.dlcRef
        challenge_submission_ids = $submissionTxids
        due_event_count          = @($watchtowerLines | Select-String "\[bitvm-watchtower\] due").Count
    }
}

function Write-SummaryArtifacts {
    param(
        $Summary
    )

    $jsonPath = Join-Path $artifactDir "run-summary.json"
    $mdPath = Join-Path $artifactDir "run-summary.md"

    $Summary | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding ascii

    $md = @(
        "# Litecoin BitVM Live Suite",
        "",
        "- Generated: $($Summary.generated_at)",
        "- Artifact dir: $artifactDir",
        "- Requested admin address: $($Summary.requested_admin_address)",
        "- Selected admin address: $($Summary.selected_admin_address)",
        "- Challenger address: $($Summary.challenger_address)",
        "- Selected admin UTXO: $($Summary.selected_admin_utxo.txid):$($Summary.selected_admin_utxo.vout) ($($Summary.selected_admin_utxo.amount) tLTC, $($Summary.selected_admin_utxo.confirmations) conf)",
        "- Preflight mined blocks: $($Summary.preflight_mined_blocks -join ", ")",
        "- Protocol admin address: $($Summary.tx30_activation_state.admin)",
        "- tx30 active before run: $($Summary.tx30_activation_state.tx30Active)",
        "- Activation attempted in suite: $($Summary.run_activation)",
        "",
        "## Plan A Uphold",
        "",
        "- Log: $($Summary.plan_uphold.log_path)",
        "- Activation tx: $($Summary.plan_uphold.activated_txid)",
        "- Cache tx: $($Summary.plan_uphold.cache_txid)",
        "- Challenge tx: $($Summary.plan_uphold.challenge_txid)",
        "- Resolve tx: $($Summary.plan_uphold.resolve_txid)",
        "- Final payout tx: $($Summary.plan_uphold.final_payout_txid)",
        "- Final status: $($Summary.plan_uphold.final_status)",
        "",
        "## Plan A Reject",
        "",
        "- Log: $($Summary.plan_reject.log_path)",
        "- Cache tx: $($Summary.plan_reject.cache_txid)",
        "- Challenge tx: $($Summary.plan_reject.challenge_txid)",
        "- Resolve tx: $($Summary.plan_reject.resolve_txid)",
        "- Final payout tx: $($Summary.plan_reject.final_payout_txid)",
        "- Final status: $($Summary.plan_reject.final_status)",
        "",
        "## Watchtower",
        "",
        "- Seed log: $($Summary.watchtower.seed_log_path)",
        "- Watchtower log: $($Summary.watchtower.log_path)",
        "- Seeded cache tx: $($Summary.watchtower.seeded_cache_txid)",
        "- Seeded cache id: $($Summary.watchtower.seeded_cache_id)",
        "- Seeded dlc ref: $($Summary.watchtower.seeded_dlc_ref)",
        "- Due events seen: $($Summary.watchtower.due_event_count)",
        "- Challenge submissions: $($Summary.watchtower.challenge_submission_ids -join ", ")",
        ""
    )

    $md | Out-File -FilePath $mdPath -Encoding ascii
}

Ensure-LitecoinPreflight

$planUpholdLog = Invoke-LoggedNodeRun `
    -Name "plan-a-uphold" `
    -WorkingDir $TradelayerRepo `
    -Arguments @("--unhandled-rejections=strict", (Join-Path $repoRoot "tests\litecoin-bitvm\tx30_plan_a_live.js")) `
    -ExtraEnv @{ TL_BITVM_VERDICT = "uphold"; TL_RUN_ACTIVATION = $(if ($script:RunActivation) { "true" } else { "false" }) }

$planRejectLog = Invoke-LoggedNodeRun `
    -Name "plan-a-reject" `
    -WorkingDir $TradelayerRepo `
    -Arguments @("--unhandled-rejections=strict", (Join-Path $repoRoot "tests\litecoin-bitvm\tx30_plan_a_live.js")) `
    -ExtraEnv @{ TL_BITVM_VERDICT = "reject"; TL_RUN_ACTIVATION = "false" }

$seedLog = Invoke-LoggedNodeRun `
    -Name "watchtower-seed" `
    -WorkingDir $repoRoot `
    -Arguments @("--unhandled-rejections=strict", (Join-Path $repoRoot "scripts\litecoin-bitvm\seed_watchtower_cache.js"))

$watchtowerLog = Invoke-LoggedNodeRun `
    -Name "watchtower-challenge" `
    -WorkingDir $TradelayerRepo `
    -Arguments @("--unhandled-rejections=strict", (Join-Path $repoRoot "tests\litecoin-bitvm\watchtower_live.js")) `
    -ExtraEnv @{ TL_WATCH_MODE = "challenge"; TL_WATCH_WINDOW_BLOCKS = "10" }

$summary = [pscustomobject]@{
    generated_at       = (Get-Date).ToString("o")
    artifact_dir       = $artifactDir
    requested_admin_address = $AdminAddress
    selected_admin_address = $script:SelectedAdminAddress
    selected_admin_utxo = $script:SelectedAdminUtxo
    preflight_mined_blocks = $script:PreflightMinedBlocks
    tx30_activation_state = $script:Tx30ActivationState
    run_activation = $script:RunActivation
    challenger_address = $ChallengerAddress
    plan_uphold        = Get-PlanSummary -Verdict "uphold" -LogPath $planUpholdLog
    plan_reject        = Get-PlanSummary -Verdict "reject" -LogPath $planRejectLog
    watchtower         = Get-WatchtowerSummary -SeedLogPath $seedLog -WatchtowerLogPath $watchtowerLog
}

Write-SummaryArtifacts -Summary $summary
Write-Host "suite complete: $artifactDir"
