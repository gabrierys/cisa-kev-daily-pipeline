from __future__ import annotations


class FakeResponse:
    def __init__(self, payload, status_code: int = 200, headers=None) -> None:
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self._payload

    def raise_for_status(self) -> None:
        return None


class FakeSession:
    def __init__(self, payloads_by_cve):
        self.payloads_by_cve = payloads_by_cve
        self.headers = {}

    def get(self, url, params=None, timeout=60):
        cve_id = params.get("cve_id", "")
        return FakeResponse(self.payloads_by_cve.get(cve_id, []))


def build_nvd_vulnerability(
    cve_id: str,
    severity: str = "HIGH",
    score: float = 8.1,
    last_modified: str = "2026-03-29T10:00:00.000Z",
):
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-03-28T10:00:00.000Z",
            "lastModified": last_modified,
            "descriptions": [{"lang": "en", "value": f"Description for {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseSeverity": severity,
                            "baseScore": score,
                        }
                    }
                ]
            },
        }
    }


def build_github_advisory(
    ghsa_id: str,
    cve_id: str,
    updated_at: str = "2026-03-29T12:00:00Z",
    severity: str = "high",
    score: float = 8.8,
):
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "severity": severity,
        "summary": f"Summary for {ghsa_id}",
        "published_at": "2026-03-28T12:00:00Z",
        "updated_at": updated_at,
        "github_reviewed_at": updated_at,
        "references": [f"https://github.com/advisories/{ghsa_id}"],
        "cwes": [{"cwe_id": "CWE-79"}],
        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "examplepkg"}}],
        "cvss": {"score": score},
        "epss": [{"percentage": 0.91, "percentile": "0.99"}],
        "identifiers": [{"type": "GHSA", "value": ghsa_id}, {"type": "CVE", "value": cve_id}],
    }


class FakeNvdSession:
    def __init__(self, has_kev_pages=None, last_mod_pages=None, cve_payloads=None):
        self.has_kev_pages = has_kev_pages or {}
        self.last_mod_pages = last_mod_pages or {}
        self.cve_payloads = cve_payloads or {}
        self.headers = {}
        self.calls = []

    def get(self, url, params=None, timeout=60):
        params = params or {}
        self.calls.append((url, dict(params)))

        if "cveId" in params:
            cve_id = params["cveId"]
            payload = self.cve_payloads.get(cve_id, {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []})
            return FakeResponse(payload)

        if "lastModStartDate" in params:
            start_index = int(params.get("startIndex", "0"))
            payload = self.last_mod_pages.get(
                start_index,
                {"resultsPerPage": 0, "startIndex": start_index, "totalResults": 0, "vulnerabilities": []},
            )
            return FakeResponse(payload)

        if "?hasKev" in url:
            start_index = int(params.get("startIndex", "0"))
            payload = self.has_kev_pages.get(
                start_index,
                {"resultsPerPage": 0, "startIndex": start_index, "totalResults": 0, "vulnerabilities": []},
            )
            return FakeResponse(payload)

        return FakeResponse({"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []})


class FakeGithubSession:
    def __init__(self, pages=None, cve_payloads=None):
        self.pages = pages or {}
        self.cve_payloads = cve_payloads or {}
        self.headers = {}
        self.calls = []

    def get(self, url, params=None, timeout=60):
        params = params or {}
        self.calls.append((url, dict(params)))

        if "cve_id" in params:
            cve_id = params["cve_id"]
            payload = self.cve_payloads.get(cve_id, [])
            return FakeResponse(payload)

        after = params.get("after", "")
        payload, headers = self.pages.get(after, ([], {}))
        return FakeResponse(payload, headers=headers)
