# WARD / 918 Technologies — ConnectWise M365 Incident Defense

**Incident-specific, executable Entra ID collection, analysis and containment kit.** This is defensive infrastructure for organizations that control their own Microsoft 365 tenant; it is not a scanner for tenants you do not administer.

Status as built: **local detector tests pass; tested against synthetic JSON only.** Live Graph collection, Microsoft Sentinel queries and containment have **not** been executed or validated on a production tenant by this delivery. Merely downloading the files does not activate protection.

## Why the intervention matters

Huntress reported on October 16, 2026 that a ConnectWise Cloud Backup / former SkyKick credential was being abused to sign in to customer Microsoft 365 tenants. In one tenant, ConnectWise Cloud Management - MS Teams assigned itself Global Administrator and added credentials to other trusted applications. Its guidance: immediately disable the affected applications **without deleting them**, inspect all application credentials, and coordinate vendor recovery. The public IP `144.172.64.128` was observed; the Azure-internal IPv6 ULA described in the report is **not** a reliable unique actor indicator.

Primary application IDs:

- Cloud Backup: `506e08f9-6e9a-4da4-942b-a099a03644ae`
- Cloud Management - MS Teams: `24205314-2b89-4e07-a2a4-579e898a5640`

The kit checks five additional ConnectWise identifiers from the Huntress advisory, including older names appearing as SkyKick Cloud Manager.

## Deployment prerequisites

1. Microsoft Entra tenant that you own/administer; tenant GUID available from Entra Overview.
2. PowerShell 7+ (`pwsh`) on Windows, Linux or macOS with internet connectivity to Microsoft Graph, and Python 3.10+ for the detector. On Android, use PowerShell in your Ubuntu environment rather than assuming Termux ships `pwsh`.
3. Delegated read consent for `Application.Read.All`, `AuditLog.Read.All`, and `RoleManagement.Read.Directory`; the signed-in account also needs the appropriate Entra directory roles. Some service-principal sign-in data requires Entra licensing and adequate log retention. Grant only the permissions needed for the phase you're running.
4. To disable service principals, separate delegated `Application.ReadWrite.All` consent and a supported Entra administrative role (typically Cloud Application Administrator or Application Administrator). Use an authorized change window where possible; for an active incident prioritize urgent containment.

The authentication uses Microsoft Graph PowerShell **device-code sign-in**. No credentials or tokens are stored by the detector. Snapshot and report files can contain sensitive tenant metadata: restrict file access, retention and distribution.

## Run: collect and analyze one tenant

In PowerShell 7, from the extracted package directory:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
$tenantId = Read-Host 'Enter the GUID of the Entra tenant you administer'
./scripts/Collect-WardEvidence.ps1 -TenantId $tenantId -OutputPath ./ward-snapshot.json
```

The tool reads applications, service principals and credential metadata, directory audits since October 13, affected service-principal sign-ins, role assignments and role definitions. It records per-source completeness and continues on isolated Graph query failures. It **does not** modify your tenant. Exit code 2 for incomplete collection is intentional; do not call such a run clean.

In Python 3 (from the same directory):

```bash
python3 ward_detector.py ward-snapshot.json --out ward-report
```

This generates `ward-report.json` and `ward-report.md`. Exit codes: `0` no findings (with coverage shown in report), `2` findings, `3` error. Missing evidence triggers a high-severity finding; a green/empty report cannot establish absence of compromise.

To compare with an earlier verified snapshot from the **same** tenant (prior snapshot must have complete app, service principal and role-assignment inventory):

```bash
python3 ward_detector.py ward-snapshot.json --baseline ward-snapshot-previous.json --out ward-delta
```

The delta highlights newly observed credentials and role assignments. Credential metadata timestamps alone **do not establish the creation date or malign intent**. An older snapshot captured after an intrusion does not provide an uncompromised baseline.

## Containment — plan only by default

In PowerShell 7, plan the specific two application disables:

```powershell
./scripts/Disable-WardConnectWise.ps1 -TenantId $tenantId
```

To actually disable those two enterprise-application service principals **in the verified tenant**:

```powershell
./scripts/Disable-WardConnectWise.ps1 -TenantId $tenantId -Apply -ApprovedTenantId $tenantId
```

PowerShell asks for confirmation for each change. The two independent guards `-Apply` and `-ApprovedTenantId` must both be satisfied; the script verifies the connected tenant, re-reads each application state, PATCHes `accountEnabled=false`, then verifies the result and writes an operation log. It never deletes, rotates or silently reenables anything. To add the five other published ConnectWise apps *after verifying local impact*, also supply `-IncludeOtherConnectWise`. Do **not** pass this option reflexively, as additional business services might be affected.

**Disabling the Cloud Backup application interrupts its ongoing cloud-backup jobs.** Existing stored backups are not deleted by this script; confirm recovery-point exposure, retention and reactivation prerequisites with ConnectWise. Simply disabling the compromised original app **does not remove credentials previously planted in other trusted apps**. Security personnel must review those credentials and role assignments and revoke anything unauthorized.

## WARD component mapping

| WARD subsystem | Real operation in this kit |
|---|---|
| ADL | Event differences, credential timing and complete-baseline drift comparisons |
| GhostBridge | Correlates IOC login, privilege escalation and credential modification within one tenant; explicitly does not assert common actor attribution |
| House of Mirrors | **Not deployed**: no synthetic identities or deception infrastructure is launched into production |
| Quantum Cloak | **Not deployed**: no automatic key rotation or moving-target identity change is applied |
| WARD controller | Read-only triage, coverage checks, operator-authorized disable, state verification and an audit trail |

All applied identity controls are conventional Microsoft Entra mechanisms. Deception and moving-target controls require independent change-controlled design and testing. No speculative functionality is represented as running in production.

## Operations and next controls

- Confirm all sign-ins on the **Service principal sign-ins** tab, not only user sign-ins; review activity even if IOC IP was not seen.
- Escalate unexpected `Add member to role`, `Update application`, `Add service principal credentials` events, especially from ConnectWise apps or management apps using unusual automation.
- Compare all application registrations **and enterprise application service principals** for unexpected secrets/certificates, including other MSP and security products; remove unauthorized credentials using approved incident response procedures.
- For affected environments: review Conditional Access workload identity policies and exclusions. The observed internal Azure ULA range is shared and should not be blocked as a stand-alone IOC.
- For continuous SIEM monitoring, the `sentinel/*.kql` files are query templates. They assume the named Microsoft Sentinel tables are ingested; do not report continuous protection until you actually create, enable and validate analytics rules in your workspace.
- Do not reenroll/re-enable vendor apps solely because this detector is quiet. Wait for confirmed vendor credential reset and a reviewed recovery plan.
- Do not publish tenant exports into public GitHub repositories. Evidence may contain tenant identity and security-relevant metadata.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 ward_detector.py fixtures/synthetic_compromise.json --out sample-ward-report
```

The synthetic fixture is **not** a tenant incident or a real data source. A `2` exit status for it is expected because it contains malicious-looking example events.

## Reference documents

- Huntress, incident report: https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
- Microsoft Graph update service principal: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update
- Microsoft Graph sign-in collection: https://learn.microsoft.com/en-us/graph/api/signin-list
- Microsoft Graph PowerShell auth: https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands