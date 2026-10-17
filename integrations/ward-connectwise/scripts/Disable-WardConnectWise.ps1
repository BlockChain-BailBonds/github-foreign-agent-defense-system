#requires -Version 7.0
<#
.SYNOPSIS
  Carefully disables specified ConnectWise enterprise application service principals.
.DESCRIPTION
  Default is PLAN ONLY. No deletion, no role changes, no credential removal.
  Live modifications require -Apply AND exact -ApprovedTenantId match.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
    [switch]$IncludeOtherConnectWise,
    [switch]$Apply,
    [string]$ApprovedTenantId,
    [string]$AuditPath = './ward-containment-audit.json'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Apply -and $ApprovedTenantId -ine $TenantId) {
    throw 'Refusing to modify tenant: -ApprovedTenantId must exactly match -TenantId.'
}
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication
$scopes = if ($Apply) { @('Application.ReadWrite.All') } else { @('Application.Read.All') }
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -UseDeviceCode -NoWelcome
$ctx = Get-MgContext
if (-not $ctx -or $ctx.TenantId -ine $TenantId) { throw 'Connected tenant does not match requested tenant.' }
foreach ($scope in $scopes) { if ($ctx.Scopes -notcontains $scope) { throw "Missing Graph permission: $scope" } }
$ids = @('506e08f9-6e9a-4da4-942b-a099a03644ae','24205314-2b89-4e07-a2a4-579e898a5640')
if ($IncludeOtherConnectWise) {
    $ids += @('2399d300-6fca-4e6a-a686-399fefe75b83',
              'b78f6a77-d4e5-46fb-87e5-d1648bd02519',
              '0de14c77-b9b0-4137-9360-34878a929827',
              '412dcf96-176d-4b3a-a1b0-4981ad66971e',
              'b2b55f5b-7758-4719-8d8f-88ae172e6bdb')
}
$api = 'https://graph.microsoft.com/v1.0/servicePrincipals'
$record = [System.Collections.Generic.List[object]]::new()
foreach ($id in $ids) {
    $filter = [uri]::EscapeDataString("appId eq '$id'")
    $url = $api + '?$filter=' + $filter + '&$select=id,appId,displayName,accountEnabled'
    $response = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop
    $found = @($response.value | Where-Object { $null -ne $_ })
    if ($found.Count -eq 0) {
        $record.Add(@{ appId = $id; result = 'not-installed'; timestamp = [DateTimeOffset]::UtcNow.ToString('o') })
        continue
    }
    foreach ($sp in $found) {
        if ($null -eq $sp) { continue }
        $objectId = [string]$sp.id
        $entry = @{ appId = $id; objectId = $objectId; name = [string]$sp.displayName;
                    originallyEnabled = $sp.accountEnabled; timestamp = [DateTimeOffset]::UtcNow.ToString('o'); result = 'plan-only' }
        if ($sp.accountEnabled -eq $false) {
            $entry.result = 'already-disabled'
        } elseif ($Apply) {
            if ($PSCmdlet.ShouldProcess("$($sp.displayName) [$id] in $TenantId", 'PATCH accountEnabled=false')) {
                try {
                    $body = '{"accountEnabled":false}'
                    Invoke-MgGraphRequest -Method PATCH -Uri "$api/$objectId" -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
                    $verified = Invoke-MgGraphRequest -Method GET -Uri ($api + '/' + $objectId + '?$select=id,accountEnabled') -ErrorAction Stop
                    if ($verified.accountEnabled -ne $false) { throw 'Post-change verification did not show disabled state.' }
                    $entry.result = 'disabled-verified'
                } catch {
                    $entry.result = 'ERROR: ' + [string]$_.Exception.Message
                }
            } else { $entry.result = 'not-approved' }
        }
        $record.Add($entry)
    }
}
$out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($AuditPath)
$parent = Split-Path -Parent $out
if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
@{ tenantId = $ctx.TenantId; applied = [bool]$Apply; actions = $record.ToArray() } |
    ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $out -Encoding utf8
if (-not $IsWindows) { & chmod 600 -- $out }
$record | Format-Table appId, name, originallyEnabled, result -AutoSize
Write-Host "Action log: $out"
if (@($record | Where-Object { $_.result -like 'ERROR:*' }).Count -gt 0) { exit 2 }