param(
    [string]$LitecoindPath = "C:\Users\patri\tradelayer-wallet\dist\server\litecoind.exe",
    [string]$DataDir = "C:\Users\patri\AppData\Roaming\Litecoin",
    [string]$RpcHost = "127.0.0.1",
    [int]$RpcPort = 19332,
    [string]$RpcUser = "user",
    [string]$RpcPass = "pass",
    [int]$WaitAttempts = 30,
    [int]$WaitSeconds = 2
)

$ErrorActionPreference = "Stop"

function Invoke-LitecoinRpc {
    param(
        [string]$Method,
        [object[]]$Params = @()
    )

    $body = @{
        jsonrpc = "1.0"
        id = "litecoin-bitvm-node"
        method = $Method
        params = $Params
    } | ConvertTo-Json -Compress -Depth 20

    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$RpcUser`:$RpcPass"))
    Invoke-RestMethod -Uri "http://$RpcHost`:$RpcPort/" -Method Post -Headers @{ Authorization = "Basic $auth" } -Body $body -ContentType "text/plain"
}

function Wait-ForRpc {
    for ($attempt = 0; $attempt -lt $WaitAttempts; $attempt++) {
        try {
            return (Invoke-LitecoinRpc -Method "getblockchaininfo").result
        } catch {
            Start-Sleep -Seconds $WaitSeconds
        }
    }

    throw "litecoind RPC did not become ready on http://$RpcHost`:$RpcPort/"
}

$running = @(Get-Process | Where-Object { $_.ProcessName -eq "litecoind" })
if ($running.Count -eq 0) {
    Start-Process -FilePath $LitecoindPath -ArgumentList @(
        "-server=1",
        "-testnet=1",
        "-rpcuser=$RpcUser",
        "-rpcpassword=$RpcPass",
        "-rpcport=$RpcPort",
        "-txindex=1",
        "-datadir=$DataDir"
    ) -WindowStyle Hidden
}

$chain = Wait-ForRpc
Write-Output ($chain | ConvertTo-Json -Depth 12)
