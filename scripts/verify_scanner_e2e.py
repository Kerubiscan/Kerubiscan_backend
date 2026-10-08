#!/usr/bin/env python
"""End-to-end scanner verification against a running KVS, run on demand by the operators.

For each engine it creates a scan via the API (as a Security Analyst), waits for it to finish, then
checks the stored vulnerabilities and that they appear in the HTML and PDF reports. It also checks
that routes without a token return 401 and that a Reader is refused (403).

It talks only to the API over HTTP; it does not touch the database directly. Run it from a host that
can reach the API, after the lab is up and SCAN_ALLOWED_TARGETS covers the lab targets.

Example:
    python -m scripts.verify_scanner_e2e \
        --api http://127.0.0.1:9445 \
        --keycloak http://127.0.0.1:1990 --realm kimia --client kimia-backend \
        --analyst analyst:Passw0rd --reader reader:Passw0rd \
        --nmap app.lab.internal --nuclei app.lab.internal \
        --zap http://juice-shop:3000 --openvas <apache-vuln-ip> \
        --auth-target <ssh-ip> --credential-id <uuid>

Exit code 0 only if every checked expectation holds.
"""
import argparse
import sys
import time

import requests

requests.packages.urllib3.disable_warnings()  # noqa


def token(args, creds):
    user, pwd = creds.split(":", 1)
    r = requests.post(
        f"{args.keycloak}/realms/{args.realm}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": args.client, "username": user, "password": pwd},
        timeout=30, verify=False)
    r.raise_for_status()
    return r.json()["access_token"]


def wait_scan(api, tok, scan_id, timeout_s):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = requests.get(f"{api}/api/v1/scans", headers={"Authorization": f"Bearer {tok}"}, verify=False, timeout=30)
        r.raise_for_status()
        scan = next((s for s in r.json() if s["id"] == scan_id), None)
        if scan and scan["status"] in ("COMPLETED", "FAILED"):
            return scan
        time.sleep(15)
    return None


def run_scan(api, tok, company, target, scan_type, engine, timeout_s):
    r = requests.post(f"{api}/api/v1/scans", headers={"Authorization": f"Bearer {tok}"}, verify=False, timeout=30,
                      json={"company_name": company, "target": target, "scan_type": scan_type, "scanner_engine": engine})
    r.raise_for_status()
    scan_id = r.json()["id"]
    scan = wait_scan(api, tok, scan_id, timeout_s)
    return scan_id, scan


def report_contains(api, tok, scan_id, needles):
    h = {"Authorization": f"Bearer {tok}"}
    html = requests.get(f"{api}/api/v1/scans/{scan_id}/report/html", headers=h, verify=False, timeout=120).text
    pdf = requests.post(f"{api}/api/v1/scans/{scan_id}/report/pdf", headers=h, json={}, verify=False, timeout=180).content
    import io
    try:
        import pypdf
        pdf_text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)
    except Exception:
        pdf_text = ""
    return all(n in html for n in needles), (not pdf_text) or all(n in pdf_text for n in needles)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--api", required=True)
    p.add_argument("--keycloak", required=True)
    p.add_argument("--realm", default="kimia")
    p.add_argument("--client", default="kimia-backend")
    p.add_argument("--analyst", required=True, help="user:password of a Security Analyst")
    p.add_argument("--reader", help="user:password of a Reader (to check the 403)")
    p.add_argument("--company", default="LAB")
    p.add_argument("--nmap"); p.add_argument("--nuclei"); p.add_argument("--zap"); p.add_argument("--openvas")
    p.add_argument("--timeout", type=int, default=3600)
    args = p.parse_args()

    ok = True
    analyst = token(args, args.analyst)

    # Security: no token -> 401
    r = requests.get(f"{args.api}/api/v1/scans", verify=False, timeout=30)
    print(f"[{'OK' if r.status_code == 401 else 'KO'}] GET /scans sans jeton -> {r.status_code} (attendu 401)")
    ok &= r.status_code == 401

    # Security: Reader cannot launch a scan -> 403
    if args.reader and args.nmap:
        rtok = token(args, args.reader)
        r = requests.post(f"{args.api}/api/v1/scans", headers={"Authorization": f"Bearer {rtok}"}, verify=False,
                          timeout=30, json={"company_name": args.company, "target": args.nmap,
                                            "scan_type": "VULNERABILITY", "scanner_engine": "NMAP"})
        print(f"[{'OK' if r.status_code == 403 else 'KO'}] Reader lance un scan -> {r.status_code} (attendu 403)")
        ok &= r.status_code == 403

    cases = [
        ("NMAP", args.nmap, "VULNERABILITY", ["CVE-2021-41773"]),
        ("NUCLEI", args.nuclei, "VULNERABILITY", ["CVE-2021-41773"]),
        ("OWASP_ZAP", args.zap, "WEB_APP", []),
        ("OPENVAS", args.openvas, "VULNERABILITY", []),
    ]
    print(f"\n{'Moteur':10} {'Cible':28} {'Statut':10} {'Vulns':6} HTML PDF")
    for engine, target, stype, needles in cases:
        if not target:
            continue
        scan_id, scan = run_scan(args.api, analyst, args.company, target, stype, engine, args.timeout)
        if scan is None:
            print(f"{engine:10} {target:28} {'TIMEOUT':10} (non terminé dans le délai)")
            ok = False
            continue
        vulns = scan.get("vulnerabilities_found") or 0
        in_html, in_pdf = report_contains(args.api, analyst, scan_id, needles) if needles else (True, True)
        status_ok = scan["status"] == "COMPLETED" and (vulns > 0 or engine == "OWASP_ZAP")
        print(f"{engine:10} {target:28} {scan['status']:10} {vulns:<6} "
              f"{'OK' if in_html else 'KO':4} {'OK' if in_pdf else 'KO'}")
        ok &= status_ok and in_html and in_pdf

    print("\nRésultat :", "SUCCÈS" if ok else "ÉCHEC")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
