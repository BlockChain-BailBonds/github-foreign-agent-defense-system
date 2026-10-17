#!/usr/bin/env python3
"""WARD identity-defense triage, offline over collected Microsoft Graph data.

Never accesses Microsoft Graph, never changes a tenant. All findings carry evidence.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

INCIDENT_START = "2026-10-13T00:00:00Z"
IOC_IP = "144.172.64.128"
PRIMARY_APP_IDS = {
    "506e08f9-6e9a-4da4-942b-a099a03644ae": "ConnectWise Cloud Backup",
    "24205314-2b89-4e07-a2a4-579e898a5640": "ConnectWise Cloud Management - MS Teams",
}
OTHER_APP_IDS = {
    "2399d300-6fca-4e6a-a686-399fefe75b83": "ConnectWise Cloud Management",
    "b78f6a77-d4e5-46fb-87e5-d1648bd02519": "ConnectWise Cloud Management - Exchange Online",
    "0de14c77-b9b0-4137-9360-34878a929827": "ConnectWise Cloud Management - MS Graph",
    "412dcf96-176d-4b3a-a1b0-4981ad66971e": "ConnectWise Cloud Management - Partner Center",
    "b2b55f5b-7758-4719-8d8f-88ae172e6bdb": "ConnectWise Cloud Management - SharePoint Online",
}
WATCHED_APPS = {**PRIMARY_APP_IDS, **OTHER_APP_IDS}


def utc_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def at_or_after(value: Any, threshold: str = INCIDENT_START) -> bool:
    parsed = utc_timestamp(value)
    target = utc_timestamp(threshold)
    return parsed is not None and target is not None and parsed >= target


def cleaned(value: Any) -> str:
    """Public incident report output never embeds arbitrary line breaks."""
    return str(value or "").replace("\n", " ").replace("\r", " ")[:280]


def normalize_id(value: Any) -> str:
    return cleaned(value).lower()


def graph_actor(event: dict) -> tuple[str, str]:
    source = event.get("initiatedBy") or {}
    app = source.get("app") or {}
    return normalize_id(app.get("appId")), cleaned(app.get("displayName"))


def target_summary(event: dict) -> tuple[list[str], list[str]]:
    resources = event.get("targetResources") or []
    ids, names = [], []
    for t in resources:
        if not isinstance(t, dict):
            continue
        ids.append(normalize_id(t.get("id")))
        names.append(cleaned(t.get("displayName")))
    return [x for x in ids if x], [x for x in names if x]


def user_agent(event: dict) -> str:
    for detail in event.get("additionalDetails") or []:
        if not isinstance(detail, dict):
            continue
        if "useragent" in str(detail.get("key", "")).lower().replace(" ", "").replace("-", "").replace("_", ""):
            return cleaned(detail.get("value"))
    return ""


def contains_credentials_change(event: dict) -> bool:
    name = cleaned(event.get("activityDisplayName")).lower()
    if "credential" in name or "add password" in name or "add key" in name:
        return True
    if "update application" not in name and "update service principal" not in name:
        return False
    for target in event.get("targetResources") or []:
        for prop in target.get("modifiedProperties") or []:
            prop_name = cleaned(prop.get("displayName")).lower()
            if any(word in prop_name for word in ("password", "credential", "keydescription", "keycredential")):
                return True
    return False


def analyze(data: dict, baseline: dict | None = None) -> dict:
    if not isinstance(data, dict) or not data.get("tenantId"):
        raise ValueError("Snapshot must be an object containing tenantId")
    findings: list[dict] = []
    seen: set[tuple] = set()
    coverage = data.get("coverage") or {}
    tenant = cleaned(data["tenantId"])

    def add(severity: str, rule: str, description: str, evidence: dict) -> None:
        evidence = {str(k): cleaned(v) for k, v in evidence.items() if v is not None}
        signature = (rule, tuple(sorted(evidence.items())))
        if signature in seen:
            return
        seen.add(signature)
        findings.append({"severity": severity, "rule": rule,
                         "description": description, "evidence": evidence})

    if baseline is not None:
        if not isinstance(baseline, dict) or normalize_id(baseline.get("tenantId")) != normalize_id(data["tenantId"]):
            raise ValueError("Baseline tenant must match current snapshot tenant")
        if not utc_timestamp(baseline.get("collectedAt")) or not utc_timestamp(data.get("collectedAt")):
            raise ValueError("Both snapshots require valid collectedAt timestamps for delta comparison")
        if utc_timestamp(baseline["collectedAt"]) >= utc_timestamp(data["collectedAt"]):
            raise ValueError("Baseline must predate current snapshot")
        for category in ("applications", "servicePrincipals", "roleAssignments"):
            if not (baseline.get("coverage", {}).get(category, {}).get("complete") and
                    data.get("coverage", {}).get(category, {}).get("complete")):
                raise ValueError(f"Baseline diff requires complete {category} coverage in both snapshots")

    principals = data.get("servicePrincipals") or []
    by_object_id = {normalize_id(s.get("id")): s for s in principals if isinstance(s, dict) and s.get("id")}
    definitions = {normalize_id(x.get("id")): x for x in (data.get("roleDefinitions") or []) if isinstance(x, dict)}

    for sp in principals:
        app_id = normalize_id(sp.get("appId"))
        label = cleaned(sp.get("displayName") or WATCHED_APPS.get(app_id))
        if app_id in WATCHED_APPS and sp.get("accountEnabled") is True:
            severity = "high" if app_id in PRIMARY_APP_IDS else "medium"
            add(severity, "EXPOSED_VENDOR_APP", "Watched vendor application is still enabled; exposure is not proof of compromise.",
                {"appId": app_id, "name": label, "objectId": sp.get("id")})

    for signin in data.get("signIns") or []:
        aid = normalize_id(signin.get("appId"))
        ip = cleaned(signin.get("ipAddress"))
        if ip == IOC_IP:
            error = (signin.get("status") or {}).get("errorCode")
            success = error == 0 or error == "0"
            add("critical" if (aid in WATCHED_APPS and success) else "high",
                "IOC_SIGNIN", "Known incident infrastructure recorded in sign-in telemetry; inspect success and correlation.",
                {"appId": aid, "ip": ip, "timestamp": signin.get("createdDateTime"),
                 "eventId": signin.get("id"), "result": "success" if success else "failed-or-unverified"})

    for event in data.get("directoryAudits") or []:
        name = cleaned(event.get("activityDisplayName"))
        name_lower = name.lower()
        actor_id, actor_name = graph_actor(event)
        if not actor_id:
            actor_sp_id = normalize_id(((event.get("initiatedBy") or {}).get("app") or {}).get("servicePrincipalId"))
            actor_id = normalize_id((by_object_id.get(actor_sp_id) or {}).get("appId"))
        targets, target_names = target_summary(event)
        ua = user_agent(event)
        e_id = cleaned(event.get("id"))
        ts = cleaned(event.get("activityDateTime"))
        if actor_id in WATCHED_APPS:
            if "add member to role" in name_lower or "add member to directory role" in name_lower:
                add("critical", "VENDOR_ROLE_ESCALATION",
                    "Watched ConnectWise identity performed a directory-role assignment; verify whether it was authorized.",
                    {"actorAppId": actor_id, "actor": actor_name, "target": ", ".join(target_names),
                     "timestamp": ts, "eventId": e_id, "userAgent": ua})
            elif contains_credentials_change(event):
                add("critical", "VENDOR_CREDENTIAL_MODIFICATION",
                    "Watched ConnectWise identity changed an application's credentials; potential persistence.",
                    {"actorAppId": actor_id, "actor": actor_name, "target": ", ".join(target_names),
                     "timestamp": ts, "eventId": e_id, "userAgent": ua})
            elif "update application" in name_lower:
                add("high", "VENDOR_APP_MODIFICATION",
                    "Watched ConnectWise identity modified an application; review audit details.",
                    {"actorAppId": actor_id, "actor": actor_name, "target": ", ".join(target_names),
                     "timestamp": ts, "eventId": e_id, "userAgent": ua})
        if contains_credentials_change(event) and ("python-urllib" in ua.lower() or "python-requests" in ua.lower()):
            add("high", "SCRIPTED_CREDENTIAL_MODIFICATION",
                "Application credential change with Python user agent; context-dependent, not unique to this incident.",
                {"actorAppId": actor_id, "target": ", ".join(target_names),
                 "timestamp": ts, "eventId": e_id, "userAgent": ua})

    for assignment in data.get("roleAssignments") or []:
        principal = by_object_id.get(normalize_id(assignment.get("principalId")))
        if not principal:
            continue
        aid = normalize_id(principal.get("appId"))
        if aid not in WATCHED_APPS:
            continue
        role = definitions.get(normalize_id(assignment.get("roleDefinitionId"))) or {}
        role_name = cleaned(role.get("displayName") or "unknown role")
        is_high = any(word in role_name.lower() for word in
                      ("global administrator", "privileged", "application administrator", "exchange administrator"))
        add("critical" if is_high else "high", "VENDOR_DIRECTORY_ROLE",
            "Watched ConnectWise service principal currently has a directory role; validate authorization.",
            {"appId": aid, "objectId": principal.get("id"), "role": role_name,
             "assignmentId": assignment.get("id")})

    for category, items in (("application", data.get("applications") or []),
                            ("servicePrincipal", principals)):
        for obj in items:
            for kind in ("passwordCredentials", "keyCredentials"):
                for cred in obj.get(kind) or []:
                    start = cred.get("startDateTime")
                    if at_or_after(start):
                        add("medium", "RECENT_CREDENTIAL",
                            "Credential effective since incident window; compare against an approved baseline. Date alone is not compromise.",
                            {"kind": category, "appId": obj.get("appId"), "name": obj.get("displayName"),
                             "credentialType": kind, "keyId": cred.get("keyId"), "start": start})

    if baseline is not None:
        for category in ("applications", "servicePrincipals"):
            old = {normalize_id(o.get("id")): o for o in baseline.get(category, []) if isinstance(o, dict)}
            for obj in data.get(category, []) or []:
                object_id = normalize_id(obj.get("id"))
                previous = old.get(object_id)
                if previous is None:
                    continue  # Newly discovered app is not proof a credential was planted.
                for key in ("passwordCredentials", "keyCredentials"):
                    previous_keys = {normalize_id(c.get("keyId")) for c in previous.get(key) or []}
                    for cred in obj.get(key) or []:
                        key_id = normalize_id(cred.get("keyId"))
                        if key_id and key_id not in previous_keys:
                            add("high", "NEW_CREDENTIAL_DELTA",
                                "Credential present now but absent from complete earlier inventory; confirm approved change.",
                                {"objectType": category, "objectId": object_id, "appId": obj.get("appId"),
                                 "credentialType": key, "keyId": key_id})
        old_role_ids = {normalize_id(x.get("id")) for x in baseline.get("roleAssignments") or []}
        for assignment in data.get("roleAssignments") or []:
            if normalize_id(assignment.get("id")) not in old_role_ids:
                add("high", "NEW_ROLE_ASSIGNMENT_DELTA",
                    "Directory role assignment absent from the earlier complete baseline; validate authorization.",
                    {"assignmentId": assignment.get("id"), "principalId": assignment.get("principalId")})

    if (any(x["rule"] == "IOC_SIGNIN" for x in findings) and
            any(x["rule"] in ("VENDOR_CREDENTIAL_MODIFICATION", "VENDOR_ROLE_ESCALATION") for x in findings)):
        add("critical", "MULTI_STAGE_SUSPICION",
            "IOC sign-in and privilege/persistence events co-occur in this tenant. Attribution to one operator is NOT established.",
            {"tenantId": tenant})

    for key in ("servicePrincipals", "applications", "directoryAudits", "signIns", "roleAssignments", "roleDefinitions"):
        detail = coverage.get(key)
        if not isinstance(detail, dict) or not detail.get("complete"):
            reason = detail.get("error") if isinstance(detail, dict) else "not collected"
            add("high", "COVERAGE_GAP", "Evidence is incomplete; absence of other findings does not establish safety.",
                {"dataset": key, "reason": reason or "pagination limit or collection failure"})

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: (order.get(x["severity"], 4), x["rule"], str(x["evidence"])))
    counts = dict(Counter(x["severity"] for x in findings))
    return {"tenantId": tenant, "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "incidentStart": INCIDENT_START, "summary": counts,
            "complete": all(isinstance(coverage.get(x), dict) and coverage[x].get("complete") for x in
                            ("servicePrincipals", "applications", "directoryAudits", "signIns", "roleAssignments", "roleDefinitions")),
            "findings": findings, "totalFindings": len(findings)}


def markdown_report(report: dict) -> str:
    lines = ["# WARD | ConnectWise M365 incident triage", "",
             f"Tenant: `{report['tenantId']}`  ",
             f"Generated UTC: `{report['generatedAt']}`  ",
             f"Evidence complete: **{'yes' if report['complete'] else 'NO'}**  ",
             f"Findings: **{report['totalFindings']}**", "",
             "Findings are investigatory, not proof of compromise.", "",
             "## Findings", ""]
    if not report["findings"]:
        lines.append("No findings from the collected evidence. This is not a guarantee of safety.")
    for i, f in enumerate(report["findings"], 1):
        lines.extend([f"### {i}. {f['severity'].upper()} — {f['rule']}", "", f["description"], ""])
        for key, value in f["evidence"].items():
            lines.append(f"- **{key}:** `{cleaned(value).replace('`', '')}`")
        lines.append("")
    lines.extend(["## Response sequence", "",
                  "1. Coordinate incident response and preserve audit evidence.",
                  "2. Disable the impacted vendor enterprise applications after tenant verification; do not delete them.",
                  "3. Review privileged role assignments and all application/service-principal credentials added since October 13.",
                  "4. Remove unauthorized credentials and role assignments under change control.",
                  "5. Confirm vendor credential rotation and service recovery before any re-enablement.",
                  "", "Source: https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="WARD local triage of authorized Graph snapshot (read-only)")
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--out", type=Path, default=Path("ward-report"))
    parser.add_argument("--baseline", type=Path, help="Optional prior full snapshot for credential/role drift detection")
    args = parser.parse_args()
    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8-sig"))
        baseline = json.loads(args.baseline.read_text(encoding="utf-8-sig")) if args.baseline else None
        report = analyze(data, baseline)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        json_path = args.out.parent / f"{args.out.name}.json"
        md_path = args.out.parent / f"{args.out.name}.md"
        json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        md_path.write_text(markdown_report(report), encoding="utf-8")
        for path in (json_path, md_path):
            try:
                path.chmod(0o600)
            except OSError:
                pass
        print(f"Tenant={report['tenantId']} findings={report['totalFindings']} evidence_complete={report['complete']}")
        print(f"Reports: {json_path} | {md_path}")
        return 2 if report["findings"] else 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"WARD error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())