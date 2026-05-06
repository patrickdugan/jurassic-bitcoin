param(
    [string]$TradelayerRepo = "C:\projects\tradelayer.js",
    [string]$ArtifactDate = (Get-Date -Format "yyyy-MM-dd"),
    [string]$RpcWallet = "wallet.dat",
    [string]$AdminAddress = "",
    [ValidateSet("all", "receipt", "router", "transcript", "identifier", "hybrid", "oracle", "taprootassets", "watchtower", "statechain")]
    [string]$Scenario = "all"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$artifactDir = Join-Path $repoRoot "artifacts\litecoin-bitvm\procedural\$ArtifactDate"
$script:SelectedAdminAddress = $null
$script:SelectedOracleAdminAddress = $null
$script:SelectedAdminUtxo = $null
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null

function Invoke-LitecoinRpc {
    param(
        [string]$Method,
        [object[]]$Params = @(),
        [string]$Wallet
    )

    $body = @{
        jsonrpc = "1.0"
        id = "litecoin-procedural-suite"
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

function Get-SpendableUtxos {
    param(
        [string]$Address,
        [int]$MinConf
    )

    @((Invoke-LitecoinRpc -Method "listunspent" -Wallet $RpcWallet -Params @($MinConf, 9999999, @($Address), $true, @{ minimumAmount = 0.00010000 })).result) |
        Where-Object { $_.spendable -eq $true -and $_.safe -ne $false }
}

function Wait-ForSpendableUtxos {
    param(
        [string]$Address,
        [int]$MinConf = 1,
        [int]$Attempts = 30,
        [int]$DelaySeconds = 2
    )

    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        $confirmed = @(Get-SpendableUtxos -Address $Address -MinConf $MinConf)
        if ($confirmed.Count -gt 0) {
            return $confirmed
        }
        Start-Sleep -Seconds $DelaySeconds
    }

    return @(Get-SpendableUtxos -Address $Address -MinConf $MinConf)
}

function Ensure-SpendableUtxos {
    param(
        [string]$Address,
        [int]$TargetCount,
        [double]$FundAmount,
        [string]$Label
    )

    $spendable = @(Get-SpendableUtxos -Address $Address -MinConf 0)
    if ($spendable.Count -ge $TargetCount) {
        return $spendable
    }

    $needed = $TargetCount - $spendable.Count
    Write-Host "preflight: provisioning $needed wallet-visible UTXOs for $Label at $Address; not mining LTCTEST confirmations"
    for ($i = 0; $i -lt $needed; $i++) {
        $comment = "$Label fund $($i + 1)/$needed"
        $null = Invoke-LitecoinRpc -Method "sendtoaddress" -Wallet $RpcWallet -Params @($Address, $FundAmount, $comment, "jurassic-procedural")
    }
    $spendable = @(Wait-ForSpendableUtxos -Address $Address -MinConf 0)
    if ($spendable.Count -lt $TargetCount) {
        throw "address $Address has $($spendable.Count) wallet-visible spendable UTXOs after provisioning; expected $TargetCount"
    }

    return $spendable
}

function Get-FundingTargets {
    switch ($Scenario) {
        "receipt" { return @{ admin = 4; oracle = 10 } }
        "router" { return @{ admin = 4; oracle = 10 } }
        "transcript" { return @{ admin = 4; oracle = 6 } }
        "identifier" { return @{ admin = 4; oracle = 6 } }
        "hybrid" { return @{ admin = 4; oracle = 10 } }
        "oracle" { return @{ admin = 4; oracle = 6 } }
        "taprootassets" { return @{ admin = 4; oracle = 6 } }
        "watchtower" { return @{ admin = 4; oracle = 6 } }
        "statechain" { return @{ admin = 4; oracle = 6 } }
        default { return @{ admin = 10; oracle = 20 } }
    }
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

    $chain | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $artifactDir "chain-info.json") -Encoding ascii
}

function New-ParticipantAddress {
    param(
        [string]$Role
    )

    $label = "jurassic-procedural-$ArtifactDate-$Role"
    return (Invoke-LitecoinRpc -Method "getnewaddress" -Wallet $RpcWallet -Params @($label, "bech32")).result
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
        TL_ORACLE_ADMIN_ADDRESS = $script:SelectedOracleAdminAddress
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

function Get-JsonTailObject {
    param(
        [string]$LogPath
    )

    $lines = Get-Content $LogPath
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        if ($lines[$i].Trim() -ne "{") {
            continue
        }

        try {
            return (($lines[$i..($lines.Count - 1)] -join "`n") | ConvertFrom-Json)
        } catch {
            continue
        }
    }

    throw "unable to locate trailing JSON object in $LogPath"
}

function Get-ReceiptSummary {
    param(
        [string]$LogPath,
        [object]$Payload
    )

    [pscustomobject]@{
        scenario             = "receipt"
        log_path             = $LogPath
        state_oracle_id      = [int]$Payload.stateOracleId
        price_oracle_id      = [int]$Payload.priceOracleId
        short_property_id    = [int]$Payload.shortPropertyId
        long_property_id     = [int]$Payload.longPropertyId
        grant_count          = @($Payload.shortGrantTxs).Count
        grant_txids          = @($Payload.shortGrantTxs | ForEach-Object { $_.txid })
        roll_txids           = @($Payload.rollTxA, $Payload.rollTxB)
        redeem_txid          = [string]$Payload.redeemTx
        price_txid           = [string]$Payload.priceTx
        create_series_txid   = [string]$Payload.createSeriesTx
        contract_id          = [int]$Payload.contractId
        contract_ticker      = [string]$Payload.contractTicker
        contract_expiry      = [int]$Payload.contractExpiryPeriod
    }
}

function Get-RouterSummary {
    param(
        [string]$LogPath,
        [object]$Payload
    )

    [pscustomobject]@{
        scenario               = "router"
        log_path               = $LogPath
        state_oracle_id        = [int]$Payload.stateOracleId
        price_oracle_id        = [int]$Payload.priceOracleId
        short_property_id      = [int]$Payload.shortPropertyId
        entry_price_txid       = [string]$Payload.entryPriceTx
        exit_price_txid        = [string]$Payload.exitPriceTx
        create_series_txid     = [string]$Payload.createSeriesTx
        contract_id            = [int]$Payload.contractId
        contract_ticker        = [string]$Payload.contractTicker
        contract_expiry        = [int]$Payload.contractExpiryPeriod
        bucket_sweep_txid      = [string]$Payload.bucketSweepTx
        excess_route_count     = @($Payload.excessRoutes).Count
        excess_cache_txids     = @($Payload.excessRoutes | ForEach-Object { $_.cacheTx })
        excess_payout_txids    = @($Payload.excessRoutes | ForEach-Object { $_.payoutTx })
        winner_balance_alice   = [double]$Payload.balances.alice.available
        loser_balance_bob      = [double]$Payload.balances.bob.available
        winner_balance_charlie = [double]$Payload.balances.charlie.available
    }
}

function Get-TranscriptSummary {
    param(
        [string]$LogPath,
        [object]$Payload
    )

    [pscustomobject]@{
        scenario             = "transcript"
        log_path             = $LogPath
        oracle_id            = [int]$Payload.oracleId
        property_id          = [int]$Payload.propertyId
        contract_ref         = [string]$Payload.contractRef
        grant_txid           = [string]$Payload.grant.txid
        state_hash           = [string]$Payload.stateHash
        payload_hash         = [string]$Payload.payloadHash
        accepted_relay_count = [int]$Payload.acceptedRelayCount
        signature_use_count  = [int]$Payload.signatureUseCount
        relay_txids          = @($Payload.relayTxs | ForEach-Object { $_.txid })
        alias_tags           = @($Payload.relayTxs | ForEach-Object { $_.aliasTag })
    }
}

function Get-IdentifierSummary {
    param(
        [string]$LogPath,
        [object]$Payload
    )

    [pscustomobject]@{
        scenario             = "identifier"
        log_path             = $LogPath
        oracle_id            = [int]$Payload.oracleId
        property_id          = [int]$Payload.propertyId
        contract_ref         = [string]$Payload.contractRef
        grant_txid           = [string]$Payload.grant.txid
        state_hash           = [string]$Payload.stateHash
        payload_hash         = [string]$Payload.payloadHash
        accepted_relay_count = [int]$Payload.acceptedRelayCount
        signature_use_count  = [int]$Payload.signatureUseCount
        relay_txids          = @($Payload.relayTxs | ForEach-Object { $_.txid })
        blob_refs            = @($Payload.relayTxs | ForEach-Object { $_.blobRef })
    }
}

function Get-HybridSummary {
    param(
        [string]$LogPath,
        [object]$Payload
    )

    [pscustomobject]@{
        scenario                  = "hybrid"
        log_path                  = $LogPath
        state_oracle_id           = [int]$Payload.stateOracleId
        price_oracle_id           = [int]$Payload.priceOracleId
        short_property_id         = [int]$Payload.shortPropertyId
        contract_ref              = [string]$Payload.contractRef
        contract_id               = [int]$Payload.contractId
        prelude_state_hash        = [string]$Payload.preludeSummary.stateHash
        prelude_payload_hash      = [string]$Payload.preludeSummary.payloadHash
        prelude_relay_doc_count   = [int]$Payload.preludeSummary.relayDocCount
        transcript_alias_tags     = @($Payload.preludeSummary.transcriptRelays | ForEach-Object { $_.aliasTag })
        transcript_relay_txids    = @($Payload.preludeSummary.transcriptRelays | ForEach-Object { $_.txid })
        identifier_blob_refs      = @($Payload.preludeSummary.namespaceRelays | ForEach-Object { $_.blobRef })
        identifier_relay_txids    = @($Payload.preludeSummary.namespaceRelays | ForEach-Object { $_.txid })
        bucket_sweep_txid         = [string]$Payload.bucketSweepTx
        route_count               = @($Payload.routes).Count
        route_labels              = @($Payload.routes | ForEach-Object { $_.label })
        route_verdicts            = @($Payload.routes | ForEach-Object { $_.verdict })
        cache_txids               = @($Payload.routes | ForEach-Object { $_.cacheTx })
        challenge_txids           = @($Payload.routes | ForEach-Object { $_.challengeTx })
        resolve_txids             = @($Payload.routes | ForEach-Object { $_.resolveTx })
        final_payout_txids        = @($Payload.routes | ForEach-Object { $_.finalPayoutTx })
        final_statuses            = @($Payload.routes | ForEach-Object { $_.finalOutcome.status })
        cache_statuses            = @($Payload.routes | ForEach-Object { $_.cacheStatus })
        alice_available_delta     = [double]$Payload.balanceDeltas.alice.available
        bob_available_delta       = [double]$Payload.balanceDeltas.bob.available
        charlie_available_delta   = [double]$Payload.balanceDeltas.charlie.available
        alice_final_available     = [double]$Payload.finalBalances.alice.available
        bob_final_available       = [double]$Payload.finalBalances.bob.available
        charlie_final_available   = [double]$Payload.finalBalances.charlie.available
    }
}

function Get-ApplicationMeshSummary {
    param(
        [string]$ScenarioName,
        [string]$LogPath,
        [object]$Payload
    )

    [pscustomobject]@{
        scenario             = $ScenarioName
        app_id               = [string]$Payload.appId
        role                 = [string]$Payload.role
        log_path             = $LogPath
        oracle_id            = [int]$Payload.oracleId
        property_id          = [int]$Payload.propertyId
        contract_ref         = [string]$Payload.contractRef
        template_id          = [string]$Payload.templateId
        template_hash        = [string]$Payload.templateHash
        grant_txid           = [string]$Payload.grant.txid
        state_hash           = [string]$Payload.stateHash
        payload_hash         = [string]$Payload.payloadHash
        accepted_relay_count = [int]$Payload.acceptedRelayCount
        signature_use_count  = [int]$Payload.signatureUseCount
        transcript_alias_tags = @($Payload.transcriptRelays | ForEach-Object { $_.aliasTag })
        transcript_relay_txids = @($Payload.transcriptRelays | ForEach-Object { $_.txid })
        namespace_blob_refs  = @($Payload.namespaceRelays | ForEach-Object { $_.blobRef })
        namespace_relay_txids = @($Payload.namespaceRelays | ForEach-Object { $_.txid })
        carrier_labels       = @($Payload.carrierHints | ForEach-Object { $_.carrierLabel })
        placement_modes      = @($Payload.carrierHints | ForEach-Object { $_.placementMode })
        publication_surfaces = @($Payload.publicationSurfaces)
    }
}

function Write-RunSummary {
    param(
        [object]$Participants,
        [object[]]$Runs
    )

    $payload = [pscustomobject]@{
        artifact_date = $ArtifactDate
        artifact_dir  = $artifactDir
        admin_address = $script:SelectedAdminAddress
        oracle_admin_address = $script:SelectedOracleAdminAddress
        participants  = $Participants
        runs          = $Runs
    }

    $payload | ConvertTo-Json -Depth 64 | Out-File -FilePath (Join-Path $artifactDir "run-summary.json") -Encoding ascii

    $lines = @(
        "# Litecoin Procedural Token Live Suite",
        "",
        "Artifact date: $ArtifactDate",
        "Artifact dir: $artifactDir",
        "",
        "## Participants",
        "- admin: $($script:SelectedAdminAddress)",
        "- oracle signer: $($script:SelectedOracleAdminAddress)",
        "- alice: $($Participants.alice)",
        "- bob: $($Participants.bob)",
        "- charlie: $($Participants.charlie)",
        ""
    )

    foreach ($run in $Runs) {
        if ($run.scenario -eq "receipt") {
            $lines += @(
                "## Receipt Contract Flow",
                "- log: $($run.log_path)",
                "- short property: $($run.short_property_id)",
                "- long property: $($run.long_property_id)",
                "- grants: $($run.grant_count)",
                "- rollover txs: $([string]::Join(', ', $run.roll_txids))",
                "- redeem tx: $($run.redeem_txid)",
                "- contract: $($run.contract_id) / $($run.contract_ticker)",
                ""
            )
        }

        if ($run.scenario -eq "router") {
            $lines += @(
                "## Short Epoch Router Flow",
                "- log: $($run.log_path)",
                "- short property: $($run.short_property_id)",
                "- bucket sweep tx: $($run.bucket_sweep_txid)",
                "- excess route count: $($run.excess_route_count)",
                "- excess cache txs: $([string]::Join(', ', $run.excess_cache_txids))",
                "- excess payout txs: $([string]::Join(', ', $run.excess_payout_txids))",
                "- balances: alice=$($run.winner_balance_alice), bob=$($run.loser_balance_bob), charlie=$($run.winner_balance_charlie)",
                "- contract: $($run.contract_id) / $($run.contract_ticker)",
                ""
            )
        }

        if ($run.scenario -eq "transcript") {
            $lines += @(
                "## Transcript Multiplicity Flow",
                "- log: $($run.log_path)",
                "- property: $($run.property_id)",
                "- contract ref: $($run.contract_ref)",
                "- relay txs: $([string]::Join(', ', $run.relay_txids))",
                "- alias tags: $([string]::Join(', ', $run.alias_tags))",
                "- accepted relay count: $($run.accepted_relay_count)",
                "- signature use count: $($run.signature_use_count)",
                ""
            )
        }

        if ($run.scenario -eq "identifier") {
            $lines += @(
                "## Identifier Bifurcation Flow",
                "- log: $($run.log_path)",
                "- property: $($run.property_id)",
                "- contract ref: $($run.contract_ref)",
                "- relay txs: $([string]::Join(', ', $run.relay_txids))",
                "- blob refs: $([string]::Join(', ', $run.blob_refs))",
                "- accepted relay count: $($run.accepted_relay_count)",
                "- signature use count: $($run.signature_use_count)",
                ""
            )
        }

        if ($run.scenario -eq "hybrid") {
            $lines += @(
                "## Hybrid Router + Dispute Flow",
                "- log: $($run.log_path)",
                "- short property: $($run.short_property_id)",
                "- contract ref: $($run.contract_ref)",
                "- contract id: $($run.contract_id)",
                "- prelude relay docs: $($run.prelude_relay_doc_count)",
                "- transcript tags: $([string]::Join(', ', $run.transcript_alias_tags))",
                "- transcript relay txs: $([string]::Join(', ', $run.transcript_relay_txids))",
                "- identifier blob refs: $([string]::Join(', ', $run.identifier_blob_refs))",
                "- identifier relay txs: $([string]::Join(', ', $run.identifier_relay_txids))",
                "- bucket sweep tx: $($run.bucket_sweep_txid)",
                "- routes: $($run.route_count)",
                "- route labels: $([string]::Join(', ', $run.route_labels))",
                "- route verdicts: $([string]::Join(', ', $run.route_verdicts))",
                "- cache txs: $([string]::Join(', ', $run.cache_txids))",
                "- challenge txs: $([string]::Join(', ', $run.challenge_txids))",
                "- resolve txs: $([string]::Join(', ', $run.resolve_txids))",
                "- final payout txs: $([string]::Join(', ', $run.final_payout_txids))",
                "- final statuses: $([string]::Join(', ', $run.final_statuses))",
                "- cache statuses: $([string]::Join(', ', $run.cache_statuses))",
                "- balance deltas: alice=$($run.alice_available_delta), bob=$($run.bob_available_delta), charlie=$($run.charlie_available_delta)",
                ""
            )
        }

        if ($run.scenario -eq "oracle" -or $run.scenario -eq "taprootassets" -or $run.scenario -eq "watchtower" -or $run.scenario -eq "statechain") {
            $title = switch ($run.scenario) {
                "oracle" { "Oracle Sidecar Mesh" }
                "taprootassets" { "Taproot Assets Anchor Mesh" }
                "watchtower" { "Watchtower Beacon Mesh" }
                default { "Statechain Handoff Mesh" }
            }
            $lines += @(
                "## $title",
                "- log: $($run.log_path)",
                "- app id: $($run.app_id)",
                "- role: $($run.role)",
                "- property: $($run.property_id)",
                "- contract ref: $($run.contract_ref)",
                "- transcript relay txs: $([string]::Join(', ', $run.transcript_relay_txids))",
                "- transcript alias tags: $([string]::Join(', ', $run.transcript_alias_tags))",
                "- namespace relay txs: $([string]::Join(', ', $run.namespace_relay_txids))",
                "- namespace blob refs: $([string]::Join(', ', $run.namespace_blob_refs))",
                "- carrier labels: $([string]::Join(', ', $run.carrier_labels))",
                "- placement modes: $([string]::Join(', ', $run.placement_modes))",
                "- publication surfaces: $([string]::Join(', ', $run.publication_surfaces))",
                "- accepted relay count: $($run.accepted_relay_count)",
                "- signature use count: $($run.signature_use_count)",
                ""
            )
        }
    }

    $lines | Out-File -FilePath (Join-Path $artifactDir "run-summary.md") -Encoding ascii
}

Ensure-LitecoinPreflight

$script:SelectedAdminAddress = if ([string]::IsNullOrWhiteSpace($AdminAddress)) {
    New-ParticipantAddress -Role "admin"
} else {
    $AdminAddress
}
$script:SelectedOracleAdminAddress = New-ParticipantAddress -Role "oracle-admin"
$fundingTargets = Get-FundingTargets
Ensure-SpendableUtxos -Address $script:SelectedOracleAdminAddress -TargetCount $fundingTargets.oracle -FundAmount 0.02 -Label "procedural-oracle" | Out-Null
$adminUtxos = Ensure-SpendableUtxos -Address $script:SelectedAdminAddress -TargetCount $fundingTargets.admin -FundAmount 0.02 -Label "procedural-admin"
$script:SelectedAdminUtxo = $adminUtxos |
    Sort-Object @{ Expression = { [decimal]$_.amount }; Descending = $true }, @{ Expression = { [int]$_.confirmations }; Descending = $true } |
    Select-Object -First 1
if (-not $script:SelectedAdminUtxo) {
    $script:SelectedAdminUtxo = @(Get-SpendableUtxos -Address $script:SelectedAdminAddress -MinConf 0) |
        Sort-Object @{ Expression = { [decimal]$_.amount }; Descending = $true }, @{ Expression = { [int]$_.confirmations }; Descending = $true } |
        Select-Object -First 1
}
$script:SelectedAdminAddress | Out-File -FilePath (Join-Path $artifactDir "selected-admin-address.txt") -Encoding ascii
ConvertTo-Json -InputObject $script:SelectedAdminUtxo -Depth 6 | Out-File -FilePath (Join-Path $artifactDir "selected-admin-utxo.json") -Encoding ascii
$script:SelectedOracleAdminAddress | Out-File -FilePath (Join-Path $artifactDir "selected-oracle-admin-address.txt") -Encoding ascii

$participants = [pscustomobject]@{
    alice   = New-ParticipantAddress -Role "alice"
    bob     = New-ParticipantAddress -Role "bob"
    charlie = New-ParticipantAddress -Role "charlie"
}

$participants | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $artifactDir "participants.json") -Encoding ascii

$runs = @()

if ($Scenario -eq "all" -or $Scenario -eq "receipt") {
    $receiptLog = Invoke-LoggedNodeRun -Name "procedural-receipt-contract" -WorkingDir $repoRoot -Arguments @(".\tests\litecoin-bitvm\procedural_receipt_contract_live.js") -ExtraEnv @{
        TL_ALICE_ADDRESS = $participants.alice
        TL_BOB_ADDRESS   = $participants.bob
    }
    $receiptPayload = Get-JsonTailObject -LogPath $receiptLog
    $runs += Get-ReceiptSummary -LogPath $receiptLog -Payload $receiptPayload
}

if ($Scenario -eq "all" -or $Scenario -eq "router") {
    $routerLog = Invoke-LoggedNodeRun -Name "procedural-short-epoch-router" -WorkingDir $repoRoot -Arguments @(".\tests\litecoin-bitvm\procedural_short_epoch_router_live.js") -ExtraEnv @{
        TL_ALICE_ADDRESS = $participants.alice
        TL_BOB_ADDRESS   = $participants.bob
        TL_CHARLIE_ADDRESS = $participants.charlie
    }
    $routerPayload = Get-JsonTailObject -LogPath $routerLog
    $runs += Get-RouterSummary -LogPath $routerLog -Payload $routerPayload
}

if ($Scenario -eq "all" -or $Scenario -eq "transcript") {
    $transcriptLog = Invoke-LoggedNodeRun -Name "procedural-transcript-alias" -WorkingDir $repoRoot -Arguments @(".\tests\litecoin-bitvm\procedural_transcript_alias_live.js") -ExtraEnv @{
        TL_ALICE_ADDRESS = $participants.alice
    }
    $transcriptPayload = Get-JsonTailObject -LogPath $transcriptLog
    $runs += Get-TranscriptSummary -LogPath $transcriptLog -Payload $transcriptPayload
}

if ($Scenario -eq "all" -or $Scenario -eq "identifier") {
    $identifierLog = Invoke-LoggedNodeRun -Name "procedural-identifier-bifurcation" -WorkingDir $repoRoot -Arguments @(".\tests\litecoin-bitvm\procedural_identifier_bifurcation_live.js") -ExtraEnv @{
        TL_ALICE_ADDRESS = $participants.alice
    }
    $identifierPayload = Get-JsonTailObject -LogPath $identifierLog
    $runs += Get-IdentifierSummary -LogPath $identifierLog -Payload $identifierPayload
}

if ($Scenario -eq "all" -or $Scenario -eq "hybrid") {
    $hybridLog = Invoke-LoggedNodeRun -Name "procedural-router-dispute" -WorkingDir $repoRoot -Arguments @(".\tests\litecoin-bitvm\procedural_router_dispute_live.js") -ExtraEnv @{
        TL_ALICE_ADDRESS = $participants.alice
        TL_BOB_ADDRESS = $participants.bob
        TL_CHARLIE_ADDRESS = $participants.charlie
    }
    $hybridPayload = Get-JsonTailObject -LogPath $hybridLog
    $runs += Get-HybridSummary -LogPath $hybridLog -Payload $hybridPayload
}

if ($Scenario -eq "all" -or $Scenario -eq "oracle") {
    $oracleLog = Invoke-LoggedNodeRun -Name "procedural-oracle-sidecar-mesh" -WorkingDir $repoRoot -Arguments @(".\tests\litecoin-bitvm\procedural_oracle_sidecar_mesh_live.js") -ExtraEnv @{
        TL_ALICE_ADDRESS = $participants.alice
        TL_BOB_ADDRESS = $participants.bob
    }
    $oraclePayload = Get-JsonTailObject -LogPath $oracleLog
    $runs += Get-ApplicationMeshSummary -ScenarioName "oracle" -LogPath $oracleLog -Payload $oraclePayload
}

if ($Scenario -eq "all" -or $Scenario -eq "taprootassets") {
    $taprootAssetsLog = Invoke-LoggedNodeRun -Name "procedural-taproot-assets-anchor-mesh" -WorkingDir $repoRoot -Arguments @(".\tests\litecoin-bitvm\procedural_taproot_assets_anchor_mesh_live.js") -ExtraEnv @{
        TL_ALICE_ADDRESS = $participants.alice
        TL_BOB_ADDRESS = $participants.bob
    }
    $taprootAssetsPayload = Get-JsonTailObject -LogPath $taprootAssetsLog
    $runs += Get-ApplicationMeshSummary -ScenarioName "taprootassets" -LogPath $taprootAssetsLog -Payload $taprootAssetsPayload
}

if ($Scenario -eq "all" -or $Scenario -eq "watchtower") {
    $watchtowerLog = Invoke-LoggedNodeRun -Name "procedural-watchtower-beacon-mesh" -WorkingDir $repoRoot -Arguments @(".\tests\litecoin-bitvm\procedural_watchtower_beacon_mesh_live.js") -ExtraEnv @{
        TL_ALICE_ADDRESS = $participants.alice
        TL_BOB_ADDRESS = $participants.bob
    }
    $watchtowerPayload = Get-JsonTailObject -LogPath $watchtowerLog
    $runs += Get-ApplicationMeshSummary -ScenarioName "watchtower" -LogPath $watchtowerLog -Payload $watchtowerPayload
}

if ($Scenario -eq "all" -or $Scenario -eq "statechain") {
    $statechainLog = Invoke-LoggedNodeRun -Name "procedural-statechain-handoff-mesh" -WorkingDir $repoRoot -Arguments @(".\tests\litecoin-bitvm\procedural_statechain_handoff_mesh_live.js") -ExtraEnv @{
        TL_ALICE_ADDRESS = $participants.alice
        TL_BOB_ADDRESS = $participants.bob
    }
    $statechainPayload = Get-JsonTailObject -LogPath $statechainLog
    $runs += Get-ApplicationMeshSummary -ScenarioName "statechain" -LogPath $statechainLog -Payload $statechainPayload
}

Write-RunSummary -Participants $participants -Runs $runs
Write-Host "procedural suite artifacts written to $artifactDir"
