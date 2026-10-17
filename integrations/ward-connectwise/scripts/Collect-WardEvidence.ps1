#requires -Version 7.0
<#
.SYNOPSIS
  Collects defensive evidence from exactly one explicitly authorized Entra tenant.
.DESCRIPTION
  Read-only. Never updates, deletes, disables or creates cloud objects.
  Graph module: Microsoft.Graph.Authentication.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
    [string]$SinceUtc = '2026-10-13T00:00:00Z',
    [ValidateRange(1, 2000)][int]$MaxPagesPerQuery = 500,
    [string]$OutputPath = './ward-snapshot.json'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Microsoft.Graph.Authentication is missing. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication
$since = [DateTimeOffset]::Parse($SinceUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$scopes = @('Application.Read.All','AuditLog.Read.All','RoleManagement.Read.Directory')
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -UseDeviceCode -NoWelcome
$ctx = Get-MgContext
if (-not $ctx -or $ctx.TenantId -ine $TenantId) {
    throw "Tenant mismatch. Requested $TenantId, connected $($ctx.TenantId)."
}
foreach ($scope in $scopes) {
    if ($ctx.Scopes -notcontains $scope) { throw "Required delegated permission missing: $scope" }
}

$ids = @(
 '506e08f9-6e9a-4da4-942b-a099a03644ae',
 '24205314-2b89-4e07-a2a4-579e898a5640',
 '2399d300-6fca-4e6a-a686-399fefe75b83',
 'b78f6a77-d4e5-46fb-87e5-d1648bd02519',
 '0de14c77-b9b0-4137-9360-34878a929827',
 '412dcf96-176d-4b3a-a1b0-4981ad66971e',
 'b2b55f5b-7758-4719-8d8f-88ae172e6bdb'
)

function Invoke-GraphGetWithRetry {
    param([Parameter(Mandatory)][string]$Uri)
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try {
            return (Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop)
        } catch {
            $message = $_.Exception.Message
            $retryable = ($message -match '429|TooManyRequests|503|ServiceUnavailable|502|BadGateway|504|GatewayTimeout')
            if (-not $retryable -or $attempt -eq 4) { throw }
            Start-Sleep -Seconds ([int][math]::Pow(2, $attempt))
        }
    }
    throw 'Retry budget exhausted.'
}
function Get-GraphField {
    param([object]$Object, [string]$Field)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Field)) { return $Object[$Field] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Field]
    if ($null -eq $property) { return $null }
    return $property.Value
}
function Get-PagedGraph {
    param([Parameter(Mandatory)][string]$Uri, [int]$MaxPages = $MaxPagesPerQuery)
    $rows = [System.Collections.Generic.List[object]]::new()
    $pageNum = 0
    $next = $Uri
    while ($next) {
        if ($pageNum -ge $MaxPages) {
            return @{ complete = $false; error = "page limit $MaxPages reached"; records = $rows.ToArray(); pages = $pageNum }
        }
        try {
            $response = Invoke-GraphGetWithRetry -Uri $next
            $values = Get-GraphField -Object $response -Field 'value'
            if ($null -ne $values) {
                foreach ($item in @($values)) { if ($null -ne $item) { $rows.Add($item) } }
            }
            $next = Get-GraphField -Object $response -Field '@odata.nextLink'
            $pageNum++
        } catch {
            return @{ complete = $false; error = [string]$_.Exception.Message; records = $rows.ToArray(); pages = $pageNum }
        }
    }
    return @{ complete = $true; error = $null; records = $rows.ToArray(); pages = $pageNum }
}
function Protect-Credentials {
    param([object[]]$Objects)
    foreach ($obj in @($Objects)) {
        if ($null -eq $obj) { continue }
        $passwords = @()
        foreach ($c in @($obj.passwordCredentials)) {
            if ($null -ne $c) {
                $passwords += @{ keyId = $c.keyId; displayName = $c.displayName; startDateTime = $c.startDateTime; endDateTime = $c.endDateTime }
            }
        }
        $keys = @()
        foreach ($c in @($obj.keyCredentials)) {
            if ($null -ne $c) {
                $keys += @{ keyId = $c.keyId; displayName = $c.displayName; startDateTime = $c.startDateTime; endDateTime = $c.endDateTime; type = $c.type; usage = $c.usage }
            }
        }
        $enabled = $null
        if ($obj -is [System.Collections.IDictionary]) {
            if ($obj.Contains('accountEnabled')) { $enabled = $obj.accountEnabled }
        } elseif ($null -ne $obj.PSObject.Properties['accountEnabled']) {
            $enabled = $obj.accountEnabled
        }
        [pscustomobject]@{
            id = $obj.id; appId = $obj.appId; displayName = $obj.displayName
            accountEnabled = $enabled
            passwordCredentials = $passwords; keyCredentials = $keys
        }
    }
}

$base = 'https://graph.microsoft.com/v1.0/'
$select = [uri]::EscapeDataString('id,appId,displayName,accountEnabled,passwordCredentials,keyCredentials')
$service = Get-PagedGraph -Uri ($base + 'servicePrincipals?$select=' + $select + '&$top=100')
$appSelect = [uri]::EscapeDataString('id,appId,displayName,passwordCredentials,keyCredentials')
$apps = Get-PagedGraph -Uri ($base + 'applications?$select=' + $appSelect + '&$top=100')
$auditFilter = [uri]::EscapeDataString("activityDateTime ge $since")
$audits = Get-PagedGraph -Uri ($base + 'auditLogs/directoryAudits?$filter=' + $auditFilter + '&$top=100')
$roles = Get-PagedGraph -Uri ($base + 'roleManagement/directory/roleAssignments?$top=100')
$definitions = Get-PagedGraph -Uri ($base + 'roleManagement/directory/roleDefinitions?$top=100')

$signIns = [System.Collections.Generic.List[object]]::new()
$signFailures = [System.Collections.Generic.List[string]]::new()
$signPages = 0
foreach ($id in $ids) {
    $filter = [uri]::EscapeDataString("createdDateTime ge $since and appId eq '$id' and signInEventTypes/any(t: t eq 'servicePrincipal')")
    $request = Get-PagedGraph -Uri ($base + 'auditLogs/signIns?$filter=' + $filter + '&$top=100')
    $signPages += $request.pages
    foreach ($item in @($request.records)) { if ($null -ne $item) { $signIns.Add($item) } }
    if (-not $request.complete) { $signFailures.Add("$id : $($request.error)") }
}

$coverage = @{
    servicePrincipals = @{ complete = [bool]$service.complete; error = $service.error; pages = $service.pages; records = @($service.records).Count }
    applications = @{ complete = [bool]$apps.complete; error = $apps.error; pages = $apps.pages; records = @($apps.records).Count }
    directoryAudits = @{ complete = [bool]$audits.complete; error = $audits.error; pages = $audits.pages; records = @($audits.records).Count }
    signIns = @{ complete = ($signFailures.Count -eq 0); error = ($signFailures -join '; '); pages = $signPages; records = $signIns.Count }
    roleAssignments = @{ complete = [bool]$roles.complete; error = $roles.error; pages = $roles.pages; records = @($roles.records).Count }
    roleDefinitions = @{ complete = [bool]$definitions.complete; error = $definitions.error; pages = $definitions.pages; records = @($definitions.records).Count }
}
$spEvidence = @(Protect-Credentials -Objects @($service.records))
$appEvidence = @(Protect-Credentials -Objects @($apps.records))
# Sign-in records intentionally retain only the fields used by the detector.
$signEvidence = @($signIns | ForEach-Object {
    [pscustomobject]@{ id = $_.id; appId = $_.appId; ipAddress = $_.ipAddress;
        createdDateTime = $_.createdDateTime; status = $_.status; signInEventTypes = $_.signInEventTypes }
})
# Directory audit events hold security-sensitive context; preserve relevant fields but never tokens.
$auditEvidence = @($audits.records | ForEach-Object {
    [pscustomobject]@{ id = $_.id; activityDateTime = $_.activityDateTime;
        activityDisplayName = $_.activityDisplayName; initiatedBy = $_.initiatedBy;
        targetResources = $_.targetResources; additionalDetails = $_.additionalDetails }
})
$snapshot = @{
    schema = 'ward-entra-incident-v1'
    tenantId = $ctx.TenantId
    collectedAt = [DateTimeOffset]::UtcNow.ToString('o')
    sinceUtc = $since
    source = 'Microsoft Graph v1.0 (delegated)'
    servicePrincipals = $spEvidence
    applications = $appEvidence
    directoryAudits = $auditEvidence
    signIns = $signEvidence
    roleAssignments = @($roles.records)
    roleDefinitions = @($definitions.records)
    coverage = $coverage
}
$resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$dir = Split-Path -Parent $resolved
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$snapshot | ConvertTo-Json -Depth 75 | Set-Content -LiteralPath $resolved -Encoding utf8
if (-not $IsWindows) { & chmod 600 -- $resolved }
Write-Host "Collected for tenant $($ctx.TenantId) to $resolved"
Write-Host 'Coverage:'
$coverage | ConvertTo-Json -Depth 5 | Write-Host
if (@($coverage.Values | Where-Object { -not $_.complete }).Count -gt 0) {
    Write-Warning 'Some evidence sources failed or hit pagination limits. Snapshot is NOT a clean bill of health.'
    exit 2
}