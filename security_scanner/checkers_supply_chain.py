"""
Supply-chain checkers — assess risk inherited from related/supplier domains
and from exposed third-party dependency manifests.

S-1 RelatedDomainsChecker (v1.0 — broker-declared only)
    Scans broker-declared sibling/supplier domains in LITE mode (SSL +
    DNS infrastructure ports + info_disclosure) and rolls up worst-of-N
    findings into a single supply-chain category for the primary report.

    v1.1 (deferred) — auto-discovery via cert SAN, WHOIS registrant match,
    and analytics-ID correlation; broker confirms via the existing
    pre-flight regulatory-flag UX. See project memory:
    project_related_domain_discovery.md.

    Civil-liability rationale: under aggregator / supplier-liability theory
    (a single Lloyd's Talbot precedent: mrcourier.co.uk), a breach at a
    declared supplier can be imputed back to the insured. This category
    feeds the DBI civil-liability scenario in financial_impact.

S-3 DependencyManifestChecker
    Probes the web root for exposed dependency manifests (package.json,
    composer.json, requirements.txt, Gemfile.lock, go.mod, etc.).
    Each exposed manifest reveals the exact dependency + version map an
    attacker needs to chain known CVEs into a working exploit (OSV-chain
    discovery).
"""

import json
import re

from scanner_utils import *
from checkers_core import SSLChecker
from checkers_network import DNSInfrastructureChecker
from checkers_threats import InformationDisclosureChecker


class RelatedDomainsChecker:
    LITE_TIMEOUT_PER_DOMAIN = 45  # seconds
    MAX_DOMAINS = 10              # cap broker-declared list to bound scan time

    def check(self, primary_domain: str, related_domains: list = None) -> dict:
        related = [d.strip().lower() for d in (related_domains or [])
                   if d and isinstance(d, str) and d.strip()]
        related = [d for d in related if d != primary_domain.lower()]
        related = list(dict.fromkeys(related))[:self.MAX_DOMAINS]

        result = {
            "status": "skipped" if not related else "completed",
            "declared_count": len(related),
            "scanned_count": 0,
            "dependants": [],
            "worst_domain": None,
            "critical_count": 0,
            "high_count": 0,
            "score": 100,
            "issues": [],
        }
        if not related:
            return result

        def _scan_one(d: str) -> dict:
            dep = {"domain": d, "ssl_grade": None, "ssl_score": 100,
                   "info_score": 100, "dns_risk": 0,
                   "critical_paths": 0, "lite_score": 100, "issues": []}
            try:
                ssl = SSLChecker().check(d) or {}
                dep["ssl_grade"] = ssl.get("grade")
                dep["ssl_score"] = ssl.get("score", 100)
                dep["issues"] += [f"[ssl] {i}" for i in (ssl.get("issues") or [])[:3]]
            except Exception:
                pass
            try:
                dns = DNSInfrastructureChecker().check(d) or {}
                dep["dns_risk"] = dns.get("risk_score", 0)
                dep["issues"] += [f"[dns] {i}" for i in (dns.get("issues") or [])[:3]]
            except Exception:
                pass
            try:
                info = InformationDisclosureChecker().check(d) or {}
                dep["info_score"] = info.get("score", 100)
                dep["critical_paths"] = sum(
                    1 for p in (info.get("exposed_paths") or [])
                    if p.get("risk_level") == "critical"
                )
                dep["issues"] += [f"[info] {i}" for i in (info.get("issues") or [])[:3]]
            except Exception:
                pass
            dep["lite_score"] = min(
                int(dep["ssl_score"] or 100),
                int(dep["info_score"] or 100),
                max(0, 100 - int(dep["dns_risk"] or 0)),
            )
            return dep

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(_scan_one, d): d for d in related}
            try:
                for fut in as_completed(
                        futures,
                        timeout=self.LITE_TIMEOUT_PER_DOMAIN * len(related)):
                    try:
                        result["dependants"].append(
                            fut.result(timeout=self.LITE_TIMEOUT_PER_DOMAIN))
                    except Exception:
                        pass
            except TimeoutError:
                pass

        result["scanned_count"] = len(result["dependants"])

        if result["dependants"]:
            worst = min(result["dependants"], key=lambda d: d.get("lite_score", 100))
            result["worst_domain"] = {
                "domain": worst["domain"],
                "lite_score": worst.get("lite_score", 100),
            }
            result["critical_count"] = sum(d.get("critical_paths", 0)
                                            for d in result["dependants"])
            result["high_count"] = sum(1 for d in result["dependants"]
                                        if d.get("lite_score", 100) < 60)
            result["score"] = min(d.get("lite_score", 100)
                                   for d in result["dependants"])

            if result["critical_count"] > 0:
                result["issues"].append(
                    f"CRITICAL: {result['critical_count']} critical exposure(s) "
                    f"across {result['scanned_count']} related domain(s) — "
                    "supplier-chain liability risk"
                )
            elif result["high_count"] > 0:
                result["issues"].append(
                    f"{result['high_count']} related domain(s) score below 60 — "
                    "review supplier security posture"
                )

        return result


class DependencyManifestChecker:
    # Manifests grouped by ecosystem. Each tuple is (path, ecosystem,
    # parser-key). The parser-key selects an extraction strategy in
    # _extract_dependencies. Severity reflects how much actionable
    # CVE-discovery signal the manifest gives an attacker:
    #
    #   - lockfile (package-lock.json, composer.lock, Gemfile.lock,
    #     requirements.txt, go.sum, Cargo.lock) reveals EXACT pinned
    #     versions → easily chained to OSV CVEs → "critical"
    #   - manifest (package.json, composer.json, Pipfile, Gemfile,
    #     go.mod, Cargo.toml, pom.xml) reveals dependency NAMES and
    #     SemVer ranges → narrower attacker advantage → "high"
    MANIFESTS = [
        ("/package-lock.json",  "node",   "json_lock",      "critical"),
        ("/package.json",       "node",   "json_manifest",  "high"),
        ("/yarn.lock",          "node",   "yarn_lock",      "critical"),
        ("/composer.lock",      "php",    "json_lock",      "critical"),
        ("/composer.json",      "php",    "json_manifest",  "high"),
        ("/requirements.txt",   "python", "requirements",   "critical"),
        ("/Pipfile.lock",       "python", "json_lock",      "critical"),
        ("/Pipfile",            "python", "pipfile",        "high"),
        ("/Gemfile.lock",       "ruby",   "gemfile_lock",   "critical"),
        ("/Gemfile",            "ruby",   "gemfile",        "high"),
        ("/go.mod",             "go",     "go_mod",         "high"),
        ("/go.sum",             "go",     "go_sum",         "critical"),
        ("/Cargo.lock",         "rust",   "toml_lock",      "critical"),
        ("/Cargo.toml",         "rust",   "toml_manifest",  "high"),
        ("/pom.xml",            "java",   "pom",            "high"),
    ]

    MAX_DEPS_RETURNED = 50    # cap per manifest to bound result size

    def _probe(self, url: str):
        from http_client import HTTP
        head = HTTP.head(url, timeout=8, allow_redirects=False)
        if head is None or head.status_code != 200:
            return None
        r = HTTP.get(url, timeout=8, allow_redirects=False)
        if r is None or r.status_code != 200 or len(r.text) < 10:
            return None
        text_head = r.text.lower()[:300]
        if "<html" in text_head or "<!doctype" in text_head:
            return None
        if "not found" in text_head[:200] or "404" in text_head[:50]:
            return None
        return r.text[:200_000]

    def _extract_dependencies(self, content: str, parser_key: str) -> list:
        deps = []
        try:
            if parser_key == "json_manifest":
                obj = json.loads(content)
                for section in ("dependencies", "devDependencies",
                                "require", "require-dev"):
                    for name, ver in (obj.get(section) or {}).items():
                        deps.append({"name": name, "version": str(ver),
                                      "section": section})
            elif parser_key == "json_lock":
                obj = json.loads(content)
                pkgs = obj.get("packages") or obj.get("dependencies") or {}
                if isinstance(pkgs, dict):
                    for name, meta in pkgs.items():
                        if not name:
                            continue
                        ver = ""
                        if isinstance(meta, dict):
                            ver = str(meta.get("version", ""))
                        elif isinstance(meta, str):
                            ver = meta
                        deps.append({"name": name.lstrip("/"),
                                      "version": ver})
            elif parser_key == "yarn_lock":
                for m in re.finditer(r'^"?([^@\s"]+)@[^\n"]+"?:\s*\n\s*version\s+"([^"]+)"',
                                      content, re.MULTILINE):
                    deps.append({"name": m.group(1), "version": m.group(2)})
            elif parser_key == "requirements":
                for line in content.splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line or line.startswith("-"):
                        continue
                    m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([=<>!~]=?|@)\s*(\S+)", line)
                    if m:
                        deps.append({"name": m.group(1),
                                      "version": m.group(3)})
                    else:
                        deps.append({"name": line, "version": ""})
            elif parser_key == "pipfile":
                cur = None
                for line in content.splitlines():
                    s = line.strip()
                    if s.startswith("[") and s.endswith("]"):
                        cur = s[1:-1]
                        continue
                    if cur in ("packages", "dev-packages") and "=" in s:
                        name, _, rest = s.partition("=")
                        deps.append({"name": name.strip().strip('"'),
                                      "version": rest.strip().strip('"'),
                                      "section": cur})
            elif parser_key == "gemfile_lock":
                in_specs = False
                for line in content.splitlines():
                    if line.strip() == "GEM" or line.strip().startswith("PATH"):
                        in_specs = False
                    if line.strip() == "specs:":
                        in_specs = True
                        continue
                    if in_specs:
                        m = re.match(r"^\s{4}([A-Za-z0-9_\-]+)\s+\(([^)]+)\)", line)
                        if m:
                            deps.append({"name": m.group(1),
                                          "version": m.group(2)})
            elif parser_key == "gemfile":
                for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?",
                                      content):
                    deps.append({"name": m.group(1),
                                  "version": (m.group(2) or "")})
            elif parser_key == "go_mod":
                in_block = False
                for line in content.splitlines():
                    s = line.strip()
                    if s.startswith("require ("):
                        in_block = True
                        continue
                    if in_block and s == ")":
                        in_block = False
                        continue
                    if in_block or s.startswith("require "):
                        s2 = s.removeprefix("require ").strip()
                        parts = s2.split()
                        if len(parts) >= 2:
                            deps.append({"name": parts[0], "version": parts[1]})
            elif parser_key == "go_sum":
                seen = set()
                for line in content.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and (parts[0], parts[1]) not in seen:
                        seen.add((parts[0], parts[1]))
                        deps.append({"name": parts[0],
                                      "version": parts[1].split("/")[0]})
            elif parser_key in ("toml_lock", "toml_manifest"):
                # Minimal TOML parsing — enough to extract [[package]] /
                # [dependencies] entries without a TOML lib dependency.
                if parser_key == "toml_lock":
                    blocks = re.findall(
                        r'\[\[package\]\]\s*\n([^[]+)', content)
                    for block in blocks:
                        name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
                        ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
                        if name_m:
                            deps.append({
                                "name": name_m.group(1),
                                "version": ver_m.group(1) if ver_m else "",
                            })
                else:
                    dep_block = re.search(
                        r'\[dependencies\]\s*\n(.*?)(?:\n\[|\Z)',
                        content, re.DOTALL)
                    if dep_block:
                        for m in re.finditer(
                                r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"',
                                dep_block.group(1), re.MULTILINE):
                            deps.append({"name": m.group(1),
                                          "version": m.group(2)})
            elif parser_key == "pom":
                for m in re.finditer(
                        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*"
                        r"<artifactId>([^<]+)</artifactId>\s*"
                        r"(?:<version>([^<]+)</version>)?",
                        content):
                    deps.append({"name": f"{m.group(1)}:{m.group(2)}",
                                  "version": m.group(3) or ""})
        except Exception:
            return deps[:self.MAX_DEPS_RETURNED]
        return deps[:self.MAX_DEPS_RETURNED]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "exposed_manifests": [],
            "total_dependencies": 0,
            "ecosystems": [],
            "critical_count": 0,
            "high_count": 0,
            "score": 100,
            "issues": [],
        }
        base = f"https://{domain}"

        def _check_one(entry):
            path, ecosystem, parser_key, severity = entry
            content = self._probe(f"{base}{path}")
            if not content:
                return None
            deps = self._extract_dependencies(content, parser_key)
            return {
                "path": path,
                "ecosystem": ecosystem,
                "severity": severity,
                "size_bytes": len(content),
                "dependency_count": len(deps),
                "dependencies": deps,
            }

        try:
            with ThreadPoolExecutor(max_workers=3) as ex:
                futures = {ex.submit(_check_one, m): m for m in self.MANIFESTS}
                for fut in as_completed(futures, timeout=90):
                    try:
                        out = fut.result(timeout=10)
                    except Exception:
                        continue
                    if out:
                        result["exposed_manifests"].append(out)
        except TimeoutError:
            pass

        if result["exposed_manifests"]:
            result["ecosystems"] = sorted({m["ecosystem"]
                                           for m in result["exposed_manifests"]})
            result["total_dependencies"] = sum(m["dependency_count"]
                                                for m in result["exposed_manifests"])
            result["critical_count"] = sum(1 for m in result["exposed_manifests"]
                                            if m["severity"] == "critical")
            result["high_count"] = sum(1 for m in result["exposed_manifests"]
                                        if m["severity"] == "high")
            penalty = result["critical_count"] * 30 + result["high_count"] * 15
            result["score"] = max(0, 100 - penalty)
            crit_paths = [m["path"] for m in result["exposed_manifests"]
                           if m["severity"] == "critical"]
            if crit_paths:
                result["issues"].append(
                    f"CRITICAL: {len(crit_paths)} dependency lockfile(s) exposed "
                    f"({', '.join(crit_paths)}) — exact pinned versions enable "
                    "OSV-chained CVE discovery"
                )
            high_paths = [m["path"] for m in result["exposed_manifests"]
                           if m["severity"] == "high"]
            if high_paths:
                result["issues"].append(
                    f"{len(high_paths)} dependency manifest(s) exposed "
                    f"({', '.join(high_paths)}) — dependency names + SemVer "
                    "ranges leaked"
                )

        return result
