"""
Build a unified blacklist JSON from multiple public sources.

Sources merged:
  - ABE Info Service (AMF / ACPR / Banque de France) PDF
  - URLhaus (abuse.ch) — malware URLs
  - OpenPhish — phishing URLs
  - PhishTank verified phishing list (if API key available)

Output: data/blacklist.json (consumed by the web UI)
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

EMAIL_RE = re.compile(r"[\w\.\-+]+@[\w\.\-]+\.[a-z]{2,}", re.IGNORECASE)
URL_RE = re.compile(r"(?:https?://)?(?:www\.)?[a-z0-9][\w\-]*(?:\.[a-z0-9][\w\-]*)+(?:/[^\s]*)?", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^[a-z0-9][\w\-]*(?:\.[a-z0-9][\w\-]*)+$", re.IGNORECASE)


def http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; blacklist-builder/1.0)",
        "Accept": "*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def normalize_url(value: str) -> str:
    v = value.strip().lower()
    v = re.sub(r"^https?://", "", v)
    v = re.sub(r"^www\.", "", v)
    v = v.rstrip("/.")
    return v


def is_email(value: str) -> bool:
    return "@" in value and bool(EMAIL_RE.fullmatch(value.strip()))


# ---------- ABE Info Service ----------
ABE_CSV_URL = "https://www.abe-infoservice.fr/fr/abeis-liste-noire.csv"


def fetch_abe_csv() -> list[dict]:
    """Download the official ABE Info Service CSV (AMF/ACPR/Banque de France)."""
    print(f"[ABE] fetching {ABE_CSV_URL}")
    try:
        raw = http_get(ABE_CSV_URL, timeout=120)
    except Exception as e:
        print(f"[ABE] error: {e}", file=sys.stderr)
        return []

    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text), delimiter=";", quotechar='"')
    rows = list(reader)
    if not rows:
        return []

    # Skip header row
    header, rows = rows[0], rows[1:]
    print(f"[ABE] columns: {header}")

    entries: dict[tuple, dict] = {}
    for row in rows:
        if len(row) < 3:
            continue
        raw_value = row[0].strip()
        category = row[2].strip() if len(row) > 2 else ""
        if not raw_value:
            continue

        # The first column may contain multiple URLs / e-mails separated by line breaks
        # or ", " — split on whitespace and commas.
        parts = re.split(r"[\s,]+", raw_value)
        for piece in parts:
            piece = piece.strip().rstrip(",;.")
            if not piece:
                continue
            if "@" in piece and EMAIL_RE.fullmatch(piece):
                key = piece.lower()
                # Skip placeholder rows like "prénom.nom@example.com"
                lower = key
                if lower.startswith("prenom") or lower.startswith("prénom") or lower.startswith("nom@"):
                    continue
                entries[("email", key)] = {
                    "value": key,
                    "type": "email",
                    "source": "ABE Info Service",
                    "category": _normalize_abe_category(category),
                }
            else:
                norm = normalize_url(piece)
                if not norm or not DOMAIN_RE.match(norm.split("/")[0]):
                    continue
                tld = norm.split("/")[0].split(".")[-1].lower()
                if tld in {"pdf", "doc", "docx", "txt", "jpg", "png"}:
                    continue
                entries[("url", norm)] = {
                    "value": norm,
                    "type": "url",
                    "source": "ABE Info Service",
                    "category": _normalize_abe_category(category),
                }

    out = list(entries.values())
    print(f"[ABE] {len(out)} unique entries")
    return out


def _normalize_abe_category(raw: str) -> str:
    """Map raw ABE categories to a small, display-friendly set."""
    if not raw:
        return "Autres"
    low = raw.lower()
    tags: list[str] = []
    if "crédit" in low or "credit" in low or "livret" in low or "épargne" in low or "epargne" in low or "assurance" in low or "paiement" in low:
        tags.append("Crédits / Épargne / Assurance")
    if "forex" in low or "trading" in low or "crypto" in low or "options binaires" in low:
        tags.append("Forex / Trading / Crypto")
    if "usurpation autorit" in low:
        tags.append("Usurpation d'autorités")
    elif "usurpation" in low:
        tags.append("Usurpation professionnelle")
    if "financement participatif" in low:
        tags.append("Financement participatif")
    if "biens divers" in low:
        tags.append("Biens divers")
    return " · ".join(tags) if tags else raw


# ---------- URLhaus (abuse.ch) ----------
def fetch_urlhaus() -> list[dict]:
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    print(f"[URLhaus] fetching {url}")
    try:
        raw = http_get(url).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[URLhaus] error: {e}", file=sys.stderr)
        return []

    cleaned = "\n".join(l for l in raw.splitlines() if not l.startswith("#"))
    reader = csv.reader(io.StringIO(cleaned), quotechar='"')
    out: dict[str, dict] = {}
    for row in reader:
        if len(row) < 6:
            continue
        u = row[2].strip().strip('"')
        threat = row[5].strip().strip('"') if len(row) > 5 else "malware"
        norm = normalize_url(u)
        if not norm or norm in out:
            continue
        out[norm] = {
            "value": norm,
            "type": "url",
            "source": "URLhaus (abuse.ch)",
            "category": f"Malware ({threat})" if threat else "Malware",
        }
    print(f"[URLhaus] {len(out)} entries")
    return list(out.values())


# ---------- OpenPhish ----------
def fetch_openphish() -> list[dict]:
    url = "https://openphish.com/feed.txt"
    print(f"[OpenPhish] fetching {url}")
    try:
        raw = http_get(url).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[OpenPhish] error: {e}", file=sys.stderr)
        return []

    out: dict[str, dict] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        norm = normalize_url(line)
        if not norm or norm in out:
            continue
        out[norm] = {
            "value": norm,
            "type": "url",
            "source": "OpenPhish",
            "category": "Phishing",
        }
    print(f"[OpenPhish] {len(out)} entries")
    return list(out.values())


# ---------- Phishing.Database (mitchellkrogza) ----------
def fetch_phishing_database() -> list[dict]:
    url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
    print(f"[Phishing.Database] fetching {url}")
    try:
        raw = http_get(url).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[Phishing.Database] error: {e}", file=sys.stderr)
        return []

    out: dict[str, dict] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        norm = normalize_url(line)
        if not DOMAIN_RE.match(norm):
            continue
        out[norm] = {
            "value": norm,
            "type": "url",
            "source": "Phishing.Database",
            "category": "Phishing",
        }
    print(f"[Phishing.Database] {len(out)} entries")
    return list(out.values())


# ---------- Merge & write ----------
def merge(*sources: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for src in sources:
        for entry in src:
            key = (entry["type"], entry["value"])
            existing = merged.get(key)
            if existing:
                if entry["source"] not in existing["source"]:
                    existing["source"] = f"{existing['source']}, {entry['source']}"
                if entry["category"] != existing["category"] and entry["category"] not in existing["category"]:
                    existing["category"] = f"{existing['category']} / {entry['category']}"
            else:
                merged[key] = dict(entry)
    return list(merged.values())


def main() -> int:
    sources: list[list[dict]] = []

    if "--offline" in sys.argv:
        print("[main] offline mode — no remote sources fetched")
    else:
        sources.append(fetch_abe_csv())
        sources.append(fetch_urlhaus())
        sources.append(fetch_openphish())
        sources.append(fetch_phishing_database())

    entries = merge(*sources)
    entries.sort(key=lambda e: (e["type"], e["value"]))

    by_source: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_type = {"email": 0, "url": 0}
    for e in entries:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        for s in e["source"].split(", "):
            by_source[s] = by_source.get(s, 0) + 1
        by_category[e["category"]] = by_category.get(e["category"], 0) + 1

    # 1) Lightweight metadata + stats (always loaded by the UI)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(entries),
        "stats": {
            "by_type": by_type,
            "by_source": by_source,
            "by_category": by_category,
        },
        "sources": [
            {"name": "ABE Info Service",
             "url": "https://www.abe-infoservice.fr/liste-noire/listes-noires-et-mises-en-garde",
             "description": "Liste noire officielle AMF / ACPR / Banque de France (épargne, crédit, assurance, forex)."},
            {"name": "URLhaus (abuse.ch)",
             "url": "https://urlhaus.abuse.ch/",
             "description": "URLs distribuant des malwares — mise à jour permanente."},
            {"name": "OpenPhish",
             "url": "https://openphish.com/",
             "description": "Flux d'URLs de phishing récemment identifiées."},
            {"name": "Phishing.Database",
             "url": "https://github.com/mitchellkrogza/Phishing.Database",
             "description": "Base communautaire de domaines de phishing actifs."},
        ],
    }
    (DATA_DIR / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # 2) Compact lookup file — one entry per line: "type|value|source|category"
    #    Loaded as plain text by the browser, parsed into a Set for instant lookup.
    lookup_path = DATA_DIR / "blacklist.txt"
    with lookup_path.open("w", encoding="utf-8", newline="\n") as f:
        for e in entries:
            t = "e" if e["type"] == "email" else "u"
            value = e["value"].replace("|", "")
            source = e["source"].replace("|", "")
            category = e["category"].replace("|", "")
            f.write(f"{t}|{value}|{source}|{category}\n")

    # 3) ABE-only rich JSON (for the "browse the official French list" view).
    abe_entries = [e for e in entries if "ABE" in e["source"]]
    (DATA_DIR / "abe.json").write_text(
        json.dumps({"total": len(abe_entries), "entries": abe_entries},
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"\n[done] wrote {len(entries)} entries")
    print(f"       email: {by_type.get('email', 0)} | url: {by_type.get('url', 0)}")
    print(f"       meta:    {DATA_DIR / 'meta.json'}")
    print(f"       lookup:  {lookup_path}")
    print(f"       abe:     {DATA_DIR / 'abe.json'} ({len(abe_entries)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
