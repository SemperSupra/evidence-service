#!/usr/bin/env python3
"""Convert fixed synthetic oracle to candidate-native Cerbos test fixtures.

This is a test bridge, NOT cryptographic identity verification or an authorization engine.
"""
import json
import pathlib
import sys


def quoted(value):
    return json.dumps(value, ensure_ascii=True)


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: generate_tests.py corpus.json subjects.json output.yaml")
    corpus = json.loads(pathlib.Path(sys.argv[1]).read_text())
    subjects = json.loads(pathlib.Path(sys.argv[2]).read_text())
    if corpus["schema"] != "portfolio-access-oracle/v0" or len(corpus["cases"]) != 25:
        raise SystemExit("unapproved oracle corpus")
    out = [
        "name: NativeCerbosNeutralOracleR1",
        "description: Native policy results against the fixed 25-case synthetic reference",
        "options:",
        "  strictEvaluation: true",
        "principals:",
    ]
    records = []
    trust_gates = 0
    for case in corpus["cases"]:
        alias = "case_" + case["id"].replace("-", "_")
        p = case["principal"]
        revision = case["policy_revision"]
        expected_issuer = {
            "human": "synthetic:oidc",
            "agent": "synthetic:oidc",
            "automation": "synthetic:github-oidc",
        }.get(p["kind"])
        trusted = (
            p["authenticated"]
            and p["issuer"] == expected_issuer
            and case["audience"] == "portfolio-api"
            and revision in ("policy-v0", "policy-v1")
            and case["scenario"] not in (
                "reader-expired", "reader-revoked", "reader-foreign-workset"
            )
        )
        lookup = p["subject"]
        if lookup == "dave" and revision == "policy-v1":
            lookup += "@policy-v1"
        profile = subjects.get(lookup, {}) if trusted else {}
        roles = profile.get("roles", []) or ["synthetic_no_grant"]
        if not trusted:
            trust_gates += 1
        attrs = {key: profile[key] for key in ("shelf", "org", "repo") if key in profile}
        attrs["suspended"] = case["scenario"] == "reader-with-deny"
        out.extend([
            f"  {alias}:",
            f"    id: {quoted(p['subject'])}",
            f"    roles: {quoted(roles)}",
            "    attr:",
        ])
        for key, value in attrs.items():
            out.append(f"      {key}: {quoted(value)}")
        action = case["action"]
        kind = action.partition(".")[0]
        if kind not in ("shelf", "publication", "repository"):
            raise SystemExit(f"unknown resource kind {kind}")
        resource_id = case["resource"]
        if resource_id.startswith("shelf:"):
            rattrs = {"shelf": resource_id.partition(":")[2]}
        elif resource_id.startswith("org:"):
            rattrs = {"org": resource_id.partition(":")[2]}
        elif resource_id.startswith("repo:"):
            rattrs = {"repo": resource_id.partition(":")[2]}
        else:
            raise SystemExit(f"unsupported resource {resource_id}")
        records.append((alias, kind, resource_id, rattrs, action, case["expected"]))
    out.append("resources:")
    for alias, kind, resource_id, attrs, action, verdict in records:
        out.extend([
            f"  resource_{alias}:",
            f"    id: {quoted(resource_id)}",
            f"    kind: {quoted(kind)}",
            "    attr:",
        ])
        for key, value in attrs.items():
            out.append(f"      {key}: {quoted(value)}")
    out.append("tests:")
    for alias, kind, resource_id, attrs, action, verdict in records:
        effect = "EFFECT_ALLOW" if verdict == "allow" else "EFFECT_DENY"
        out.extend([
            f"  - name: {quoted(alias)}",
            "    input:",
            f"      principals: [{quoted(alias)}]",
            f"      resources: [{quoted('resource_' + alias)}]",
            f"      actions: [{quoted(action)}]",
            "    expected:",
            f"      - principal: {quoted(alias)}",
            f"        resource: {quoted('resource_' + alias)}",
            "        actions:",
            f"          {quoted(action)}: {effect}",
        ])
    pathlib.Path(sys.argv[3]).write_text("\n".join(out) + "\n")
    print(f"CERBOS_NEUTRAL_CASES={len(records)}; SYNTHETIC_TRUST_GATES={trust_gates}; AUTHN_CRYPTO=NOT_RUN")


if __name__ == "__main__":
    main()
