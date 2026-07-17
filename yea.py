#!/usr/bin/env python3
"""
yea - Yet Another AUR installer
A TUI tool for managing AUR packages with AI-powered security review.

Usage:
    yea                  # Upgrade mode: list and upgrade installed AUR packages
    yea package1 [pkg2]  # Install mode: install specified AUR packages
"""

import argparse
import curses
import json
import logging
import math
import os
import pty
import re
import select
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ─── Logging ─────────────────────────────────────────────────────────────────

logger = logging.getLogger("yea")
logger.setLevel(logging.INFO)

_handler = logging.FileHandler("/tmp/yea.log")
_handler.setLevel(logging.INFO)
_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
_handler.setFormatter(_formatter)
logger.addHandler(_handler)


# ─── Subprocess helpers ──────────────────────────────────────────────────────


# ─── Configuration ───────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "api_url": "http://localhost:8080/v1/chat/completions",
    "api_model": "llama3",
    "api_key": "",
    "cache_dir": os.path.expanduser("~/.cache/yea"),
    "prompt_template_path": "config/security_review.md",
    "vulnerability_check": True,
}


def load_config() -> dict:
    """Load configuration from ~/.config/yea/config.json or use defaults."""
    config_path = Path.home() / ".config" / "yea" / "config.json"
    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                user_config = json.load(f)
            config = {**DEFAULT_CONFIG, **user_config}
        except (json.JSONDecodeError, IOError):
            config = DEFAULT_CONFIG.copy()
    else:
        config = DEFAULT_CONFIG.copy()

    # Ensure cache dir exists
    cache_dir = Path(config["cache_dir"])
    cache_dir.mkdir(parents=True, exist_ok=True)

    return config


def load_prompt_template(config: dict) -> str:
    """Load the security review prompt template."""
    template_path = Path(config.get("prompt_template_path", ""))
    if not template_path.is_absolute():
        # Resolve relative to the yea package config directory
        template_path = Path(__file__).resolve().parent / "config" / "security_review.md"

    if template_path.exists():
        with open(template_path, "r") as f:
            return f.read()
    else:
        # Fallback inline template
        return (
            "You are a security expert reviewing an Arch Linux AUR package.\n\n"
            "Package: {pkgname} v{pkgver}\n"
            "Last Change: {last_change_date}\n"
            "Maintainer Changed: {maintainer_change_date}\n\n"
            "PKGBUILD:\n{pkgbuild}\n\n"
            "Analyze for security risks and respond with JSON:\n"
            "{{\"risk_score\": <1-100>, \"rating\": \"low|medium|high\", "
            "\"summary\": \"...\", \"details\": []}}"
        )


# ─── PKGBUILD Parsing ────────────────────────────────────────────────────────


def extract_pkgver(pkgbuild: str | None) -> str:
    """Extract pkgver from PKGBUILD content."""
    if not pkgbuild:
        return "unknown"
    match = re.search(r"^pkgver\s*=\s*[\'\"]?([^\'\"\s]+)[\'\"]?" , pkgbuild, re.MULTILINE)
    if match:
        return match.group(1)
    return "unknown"


def _fmt_list(val):
    """Format a list as a comma-separated string, or return 'N/A'."""
    return ", ".join(val) if isinstance(val, list) and val else "N/A"


def _fmt_ts(val):
    """Format a Unix timestamp as ISO format, or return 'N/A'."""
    if not val:
        return "N/A"
    return datetime.fromtimestamp(val, timezone.utc).isoformat()


def _build_metadata(aur_info: dict | None, pkgbuild: str | None, git_meta: dict,
                    pkgbuild_diff: str, download_urls: list[str], checksums: dict,
                    package_type: str, has_systemd: bool, has_install: bool) -> dict:
    """Build the full metadata dict from AUR info, PKGBUILD, git metadata, and analysis."""
    if aur_info:
        metadata = {
            "Version": extract_pkgver(pkgbuild),
            "Description": aur_info.get("Description", ""),
            "aur_maintainer": aur_info.get("Maintainer") or "N/A",
            "aur_submitter": aur_info.get("Submitter") or "N/A",
            "aur_co_maintainers": _fmt_list(aur_info.get("CoMaintainers", [])),
            "aur_license": _fmt_list(aur_info.get("License", [])),
            "aur_url": aur_info.get("URL") or "N/A",
            "aur_depends": _fmt_list(aur_info.get("Depends", [])),
            "aur_makedepends": _fmt_list(aur_info.get("MakeDepends", [])),
            "aur_num_votes": str(aur_info.get("NumVotes", "N/A")),
            "aur_popularity": str(aur_info.get("Popularity", "N/A")),
            "aur_first_submitted": _fmt_ts(aur_info.get("FirstSubmitted")),
            "aur_last_modified": _fmt_ts(aur_info.get("LastModified")),
            "pkgbuild_diff": pkgbuild_diff,
            "download_urls": ", ".join(download_urls) if download_urls else "N/A",
            "checksum_sha256": "Yes" if checksums.get("sha256") else "No",
            "checksum_sha512": "Yes" if checksums.get("sha512") else "No",
            "checksum_md5": "Yes" if checksums.get("md5") else "No",
            "checksum_pgp": "Yes" if checksums.get("pgp") else "No",
            "package_type": package_type,
            "has_systemd_service": "Yes" if has_systemd else "No",
            "has_install_script": "Yes" if has_install else "No",
        }
    else:
        metadata = {
            "Version": extract_pkgver(pkgbuild),
            "Description": "",
            "aur_maintainer": "N/A",
            "aur_submitter": "N/A",
            "aur_co_maintainers": "N/A",
            "aur_license": "N/A",
            "aur_url": "N/A",
            "aur_depends": "N/A",
            "aur_makedepends": "N/A",
            "aur_num_votes": "N/A",
            "aur_popularity": "N/A",
            "aur_first_submitted": "N/A",
            "aur_last_modified": "N/A",
            "pkgbuild_diff": pkgbuild_diff,
            "download_urls": ", ".join(download_urls) if download_urls else "N/A",
            "checksum_sha256": "Yes" if checksums.get("sha256") else "No",
            "checksum_sha512": "Yes" if checksums.get("sha512") else "No",
            "checksum_md5": "Yes" if checksums.get("md5") else "No",
            "checksum_pgp": "Yes" if checksums.get("pgp") else "No",
            "package_type": package_type,
            "has_systemd_service": "Yes" if has_systemd else "No",
            "has_install_script": "Yes" if has_install else "No",
        }
    metadata.update(git_meta)
    return metadata


# ─── AUR API ─────────────────────────────────────────────────────────────────

AUR_BASE = "https://aur.archlinux.org/rpc"


def aur_request(method: str, params: dict) -> dict:
    """Make a request to the AUR RPC API."""
    body_params = {"v": "5", "type": method, **params}
    data = urllib.parse.urlencode(body_params).encode()
    req = urllib.request.Request(f"{AUR_BASE}", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return json.loads(raw)
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        print(f"AUR API error: {e}", file=sys.stderr)
        return {"resulttype": "error", "result": []}


def get_aur_pkginfo(pkgname: str) -> dict | None:
    """Get metadata for a single AUR package."""
    result = aur_request("info", {"arg": pkgname})
    if result.get("resulttype") == "error" or not result.get("results"):
        return None
    return result["results"][0]


def get_aur_pkginfos(pkgnames: list[str]) -> dict[str, dict]:
    """Get metadata for multiple AUR packages, calling the API once per package."""
    result = {}
    for pkgname in pkgnames:
        info = get_aur_pkginfo(pkgname)
        if info:
            result[pkgname] = info
    return result


def fetch_pkgbuild(pkgname: str, cache_dir: str) -> str | None:
    """Fetch PKGBUILD content from AUR, optionally caching it."""
    cache_path = Path(cache_dir) / pkgname / "PKGBUILD"
    if cache_path.exists():
        try:
            return cache_path.read_text()
        except IOError:
            pass

    url = f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkgname}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            content = resp.read().decode()
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(content)
            return content
    except urllib.error.URLError:
        return None


# ─── Vulnerability Check ─────────────────────────────────────────────────────

COMPROMISED_LIST_URL = "https://md.archlinux.org/s/SxbqukK6IA"


def _fetch_compromised_list() -> set[str]:
    """Fetch the known compromised packages list from the remote URL.

    The remote URL returns an HTML page (HedgeDoc). Strip HTML tags,
    then extract package names from the markdown code-fence block.

    Returns an empty set if the fetch fails.
    """
    try:
        req = urllib.request.Request(COMPROMISED_LIST_URL)
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8")
        # Strip HTML tags
        text = re.sub(r"<[^>]+>", " ", html)
        # Decode common HTML entities
        text = text.replace("&thinsp;", " ").replace("&nbsp;", " ")
        # Extract content between code fences (```)
        fence_match = re.search(r"```(.*)```", text, re.DOTALL)
        if not fence_match:
            return set()
        raw = fence_match.group(1).strip()
        # Split on whitespace and filter empty
        return {name for name in raw.split() if name}
    except Exception:
        return set()


KNOWN_COMPROMISED: set[str] = set()


def check_vulnerabilities(pkgname: str, aur_info: dict | None = None) -> list[str]:
    """
    Check if a package has known vulnerabilities.
    Returns a list of vulnerability descriptions.
    """
    vulns = []

    if pkgname in KNOWN_COMPROMISED:
        vulns.append(
            f"WARNING: Package '{pkgname}' is in the known compromised packages list. "
            "This package has been reported as potentially malicious."
        )

    # Use provided aur_info if available, otherwise fetch it
    info = aur_info if aur_info is not None else get_aur_pkginfo(pkgname)
    if info and info.get("OutOfDate") and info["OutOfDate"] > 0:
        age_days = (datetime.utcnow().timestamp() - info["OutOfDate"]) / 86400
        if age_days > 365:
            vulns.append(
                f"WARNING: Package '{pkgname}' has been out of date for "
                f"{int(age_days)} days. It may contain unpatched vulnerabilities."
            )

    return vulns


# ─── Local Risk Score ────────────────────────────────────────────────────────


def compute_diff_complexity_score(pkgbuild_diff: str) -> dict:
    """Compute a risk score based on the size of the PKGBUILD diff.

    Formula: max(total_lines_changed - 2, 0) * 10, capped at 100.
    Returns a dict with 'score' (int 0-100) and 'details' string.
    """
    added = 0
    removed = 0

    for line in pkgbuild_diff.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("+") and not stripped.startswith("+++"):
            added += 1
        elif stripped.startswith("-") and not stripped.startswith("---"):
            removed += 1

    total_lines = added + removed
    score = max(total_lines - 2, 0) * 10
    score = max(0, min(100, score))

    details = f"{added} lines added, {removed} lines removed ({total_lines} total)"
    if total_lines <= 2:
        details += " — minimal change"

    return {"score": score, "details": details}


def compute_local_risk_score(
    pkgname: str,
    metadata: dict,
    aur_info: dict | None,
    pkgbuild_diff: str = "",
) -> dict:
    """Compute an internal risk score (1-100) based on package heuristics.

    Returns a dict with 'score' (int 1-100), 'factors' (list of (text, points) tuples),
    and optionally 'diff_details'.
    """
    score = 0
    factors: list[tuple[str, int]] = []

    # Binary packages carry unverifiable build risk
    if metadata.get("package_type") == "binary":
        score += 5
        factors.append(("Binary package — unverifiable build", 5))

    # Checksum analysis
    has_sha256 = metadata.get("checksum_sha256") == "Yes"
    has_sha512 = metadata.get("checksum_sha512") == "Yes"
    has_md5 = metadata.get("checksum_md5") == "Yes"
    has_pgp = metadata.get("checksum_pgp") == "Yes"

    if not has_sha256 and not has_sha512 and not has_md5:
        score += 20
        factors.append(("No checksums present", 20))
    elif not has_sha256 and not has_sha512 and has_md5:
        score += 10
        factors.append(("Only MD5 checksums — weak integrity check", 10))

    if not has_pgp:
        score += 5
        factors.append(("No PGP signature verification", 5))

    # Network download sources — informational only, no score impact
    # (omitted from factors to avoid cluttering the report)

    # Install script (.install file)
    if metadata.get("has_install_script") == "Yes":
        score += 3
        factors.append(("Has .install script — runs code during install", 3))

    # Systemd service
    if metadata.get("has_systemd_service") == "Yes":
        score += 5
        factors.append(("Installs a systemd service", 5))

    # Unknown maintainer
    aur_maint = metadata.get("aur_maintainer", "N/A")
    if aur_maint == "N/A" or not aur_maint:
        score += 10
        factors.append(("No AUR maintainer listed", 10))

    # Out of date
    if aur_info and aur_info.get("OutOfDate") and aur_info["OutOfDate"] > 0:
        age_days = (datetime.utcnow().timestamp() - aur_info["OutOfDate"]) / 86400
        if age_days > 365:
            score += 15
            factors.append((f"Out of date for {int(age_days)} days", 15))

    # Popularity risk
    aur_popularity = aur_info.get("Popularity") if aur_info else None
    if aur_popularity is not None and aur_popularity >= 0:
        pop_score = max(30 - int(aur_popularity * 15), 0)
        if pop_score > 0:
            score += pop_score
            factors.append((f"Low popularity ({aur_popularity:.2f})", pop_score))
    else:
        score += 40
        factors.append(("No popularity data available", 40))

    # Votes risk
    aur_votes = aur_info.get("NumVotes") if aur_info else None
    if aur_votes is not None and aur_votes >= 0:
        vote_score = max(30 - int(aur_votes * 0.3), 0)
        if vote_score > 0:
            score += vote_score
            factors.append((f"Low votes ({aur_votes})", vote_score))
    else:
        score += 40
        factors.append(("No votes data available", 40))

    # Known compromised
    if pkgname in KNOWN_COMPROMISED:
        score = 100
        factors.append(("Package is in the known compromised list", 100))

    # Maintainer recency: 100 / days_since_change
    maint_change = metadata.get("maintainer_change_date", "N/A")
    if maint_change and maint_change != "N/A":
        try:
            change_dt = datetime.fromisoformat(maint_change)
            days_since = (datetime.now(timezone.utc) - change_dt).days
            if days_since > 0:
                recency_score = 100 / days_since
                points = int(recency_score)
                score += points
                factors.append(
                    (f"Maintainer changed {days_since} days ago (recency risk: {recency_score:.1f})", points)
                )
        except (ValueError, TypeError):
            pass

    # Diff complexity
    diff_details = None
    if pkgbuild_diff and pkgbuild_diff not in ("N/A (no previous version available)", "No changes (identical to previous version)"):
        diff_info = compute_diff_complexity_score(pkgbuild_diff)
        score += diff_info["score"]
        if diff_info["score"] > 0:
            factors.append((f"Large PKGBUILD change: {diff_info['details']}", diff_info["score"]))
        diff_details = diff_info["details"]

    # Clamp to 1-100
    score = max(1, min(100, score))

    result = {"score": score, "factors": factors}
    if diff_details is not None:
        result["diff_details"] = diff_details
    return result


# ─── Git Manager ──────────────────────────────────────────────────────────────


def clone_or_pull_repo(pkgname: str, cache_dir: str) -> bool:
    """Clone or pull the AUR repo for a package."""
    repo_dir = Path(cache_dir) / pkgname
    repo_url = f"https://aur.archlinux.org/{pkgname}.git"

    if repo_dir.exists() and (repo_dir / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "pull"],
            capture_output=True,
            cwd=str(repo_dir),
            timeout=120,
        )
        return result.returncode == 0
    else:
        result = subprocess.run(
            ["git", "clone", repo_url, str(repo_dir)],
            capture_output=True,
            timeout=120,
        )
        return result.returncode == 0


def get_repo_metadata(pkgname: str, cache_dir: str) -> dict:
    """Get git metadata for a package repo."""
    repo_dir = Path(cache_dir) / pkgname
    metadata = {
        "last_change_date": "N/A",
        "maintainer_change_date": "N/A",
    }

    if not repo_dir.exists():
        return metadata

    try:
        # Get last commit date
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "log", "-1", "--format=%cd", "--date=iso"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            metadata["last_change_date"] = result.stdout.strip()

        # Get last maintainer change (first commit)
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_dir),
                "log",
                "--format=%cd",
                "--date=iso",
                "--reverse",
                "--author-date-order",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            dates = result.stdout.strip().split("\n")
            # Find when ownership changed
            result2 = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo_dir),
                    "log",
                    "--format=%an",
                    "--reverse",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result2.returncode == 0:
                authors = result2.stdout.strip().split("\n")
                unique_authors = []
                for a in authors:
                    if a not in unique_authors:
                        unique_authors.append(a)
                if len(unique_authors) > 1:
                    # Find the commit where maintainer changed
                    for i, author in enumerate(authors):
                        if i > 0 and author != authors[i - 1]:
                            result3 = subprocess.run(
                                [
                                    "git",
                                    "-C",
                                    str(repo_dir),
                                    "log",
                                    "-1",
                                    "--format=%cd",
                                    "--date=iso",
                                    f"{i}..HEAD",
                                ],
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )
                            if result3.returncode == 0:
                                metadata["maintainer_change_date"] = (
                                    result3.stdout.strip() or "Unknown"
                                )
                            break
                    if metadata["maintainer_change_date"] == "N/A":
                        metadata["maintainer_change_date"] = dates[0] if dates else "N/A"
                else:
                    metadata["maintainer_change_date"] = dates[0] if dates else "N/A"
            else:
                metadata["maintainer_change_date"] = dates[0] if dates else "N/A"
        else:
            metadata["maintainer_change_date"] = "N/A"

    except subprocess.TimeoutExpired:
        pass

    return metadata


def get_previous_pkgbuild(pkgname: str, cache_dir: str) -> str | None:
    """Get the PKGBUILD from the previous git commit."""
    repo_dir = Path(cache_dir) / pkgname
    if not repo_dir.exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "show", "HEAD:PKGBUILD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        pass
    return None


def get_pkgbuild_diff(pkgname: str, cache_dir: str) -> str:
    """Get the diff between the current and previous PKGBUILD."""
    current = fetch_pkgbuild(pkgname, cache_dir)
    previous = get_previous_pkgbuild(pkgname, cache_dir)
    if not previous or not current:
        return "N/A (no previous version available)"
    tmp_dir = Path(cache_dir) / pkgname / ".tmp_diff"
    tmp_dir.mkdir(exist_ok=True)
    prev_file = tmp_dir / "previous"
    curr_file = tmp_dir / "current"
    prev_file.write_text(previous)
    curr_file.write_text(current)
    try:
        result = subprocess.run(
            ["diff", "-u", str(prev_file), str(curr_file)],
            capture_output=True,
            text=True,
        )
        if result.returncode in (0, 1):
            output = result.stdout.strip()
            return output if output else "No changes (identical to previous version)"
        return "Unable to compute diff"
    finally:
        prev_file.unlink(missing_ok=True)
        curr_file.unlink(missing_ok=True)
        tmp_dir.rmdir()


def _extract_download_urls(pkgbuild: str | None) -> list[str]:
    """Extract unique hostnames from source URLs in the PKGBUILD."""
    if not pkgbuild:
        return []
    urls = set()
    # Match source entries with URLs
    for match in re.finditer(r'https?://[^\s\'")]+', pkgbuild):
        url = match.group(0)
        # Extract hostname
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname:
            urls.add(parsed.hostname)
    return sorted(urls)


def _check_checksums(pkgbuild: str | None) -> dict:
    """Check which checksum types are present in the PKGBUILD."""
    if not pkgbuild:
        return {"sha256": False, "sha512": False, "md5": False, "pgp": False}
    return {
        "sha256": bool(re.search(r"sha256sums\s*=", pkgbuild)),
        "sha512": bool(re.search(r"sha512sums\s*=", pkgbuild)),
        "md5": bool(re.search(r"md5sums\s*=", pkgbuild)),
        "pgp": bool(re.search(r"validpgpkeys\s*=", pkgbuild)),
    }


def _determine_package_type(pkgbuild: str | None) -> str:
    """Determine if package is binary or source based on source URLs."""
    if not pkgbuild:
        return "unknown"
    binary_patterns = [r"\.deb$", r"\.rpm$", r"\.pkg\.tar", r"\.AppImage$", r"\.run$",
                       r"/dl\.google\.com/", r"edge\.dropboxstatic\.com"]
    for pattern in binary_patterns:
        if re.search(pattern, pkgbuild):
            return "binary"
    return "source"


def _check_systemd_service(pkgbuild: str | None) -> bool:
    """Check if the package installs a systemd service."""
    if not pkgbuild:
        return False
    # Check for .service files in source array (not in URLs)
    if re.search(r"['\"].*\.service['\"]", pkgbuild):
        return True
    # Check for installation of .service files in package() function
    if re.search(r"systemd/system|systemd/user", pkgbuild):
        return True
    # Check for install -Dm644 ...*.service
    if re.search(r"install.*\.service", pkgbuild):
        return True
    return False


def _check_install_script(pkgbuild: str | None) -> bool:
    """Check if the package has a .install script."""
    if not pkgbuild:
        return False
    return bool(re.search(r"^install\s*=", pkgbuild, re.MULTILINE))


# ─── AI Security Review ──────────────────────────────────────────────────────


def call_ai_review(pkgname: str, pkgbuild: str, metadata: dict, config: dict) -> dict:
    """Send package info to AI for security review."""
    template = load_prompt_template(config)

    # Format the template
    prompt = template.format(
        pkgname=pkgname,
        pkgver=metadata.get("Version", "unknown"),
        last_change_date=metadata.get("last_change_date", "N/A"),
        maintainer_change_date=metadata.get("maintainer_change_date", "N/A"),
        aur_maintainer=metadata.get("aur_maintainer", "N/A"),
        aur_submitter=metadata.get("aur_submitter", "N/A"),
        aur_co_maintainers=metadata.get("aur_co_maintainers", "N/A"),
        aur_license=metadata.get("aur_license", "N/A"),
        aur_url=metadata.get("aur_url", "N/A"),
        aur_depends=metadata.get("aur_depends", "N/A"),
        aur_makedepends=metadata.get("aur_makedepends", "N/A"),
        aur_num_votes=metadata.get("aur_num_votes", "N/A"),
        aur_popularity=metadata.get("aur_popularity", "N/A"),
        aur_first_submitted=metadata.get("aur_first_submitted", "N/A"),
        aur_last_modified=metadata.get("aur_last_modified", "N/A"),
        pkgbuild=pkgbuild,
        pkgbuild_diff=metadata.get("pkgbuild_diff", "N/A"),
        download_urls=metadata.get("download_urls", "N/A"),
        checksum_sha256=metadata.get("checksum_sha256", "No"),
        checksum_sha512=metadata.get("checksum_sha512", "No"),
        checksum_md5=metadata.get("checksum_md5", "No"),
        checksum_pgp=metadata.get("checksum_pgp", "No"),
        package_type=metadata.get("package_type", "unknown"),
        has_systemd_service=metadata.get("has_systemd_service", "No"),
        has_install_script=metadata.get("has_install_script", "No"),
    )

    body = {
        "model": config.get("api_model", "llama3"),
        "messages": [
            {"role": "system", "content": "You are a security expert analyzing AUR packages."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
    }

    api_key = config.get("api_key", "")
    api_url = config.get("api_url", "http://localhost:8080/v1/chat/completions")

    data = json.dumps(body).encode()
    logger.info("AI REQUEST - URL: %s | Model: %s | Body: %s", api_url, config.get("api_model", "llama3"), data.decode())

    req = urllib.request.Request(api_url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode()
            logger.info("AI_RESPONSE: %s", raw)
            response = json.loads(raw)
            content = response["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"AI review failed: {e}", file=sys.stderr)
        return {
            "risk_score": 50,
            "rating": "medium",
            "summary": "AI review unavailable - defaulting to medium risk",
            "details": [],
            "ai_available": False,
        }

    # Parse the JSON response from AI
    try:
        # Strip markdown code fences if present
        cleaned = content.strip()
        if cleaned.startswith("```"):
            first_newline = cleaned.index("\n")
            cleaned = cleaned[first_newline + 1:]
            if cleaned.endswith("```\n"):
                cleaned = cleaned[:-4]
            elif cleaned.endswith("```"):
                cleaned = cleaned[:-3]
        # Try to extract JSON object
        json_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            result["ai_available"] = True
            return result
        else:
            result = json.loads(cleaned)
            result["ai_available"] = True
            return result
    except (json.JSONDecodeError, KeyError, IndexError):
        return {
            "risk_score": 50,
            "rating": "medium",
            "summary": "Failed to parse AI response - defaulting to medium risk",
            "details": [],
            "ai_available": True,
        }


# ─── System Package Detection ────────────────────────────────────────────────


def get_installed_aur_packages() -> list[str]:
    """Get list of packages installed from AUR (manually installed, not in official repos)."""
    try:
        env = os.environ.copy()
        env["PACMAN_COLOR"] = "0"  # disable colors
        result = subprocess.run(
            ["pacman", "-Qm"],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if result.returncode == 0:
            packages = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    # Strip ANSI escape sequences
                    clean = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", line)
                    clean = re.sub(r"\x1b\][^\x07]*\x07", "", clean)
                    clean = re.sub(r"\x1b[^\x07\x1b]", "", clean)
                    clean = re.sub(r"[\x00-\x08\x0e-\x1f]", "", clean)
                    clean = clean.strip()
                    if clean:
                        packages.append(clean.split()[0])
            return packages
    except Exception:
        pass
    return []


# ─── TUI Helpers ──────────────────────────────────────────────────────────────


def draw_line(stdscr, y: int, x: int, text: str, attr: int = 0):
    """Draw text at a specific position."""
    max_y, max_x = stdscr.getmaxyx()
    if x < max_x:
        try:
            stdscr.addnstr(y, x, text, max_x - x, attr)
        except curses.error:
            pass


def wrap_text(text: str, width: int) -> list[str]:
    """Wrap text to the given width, preserving word boundaries."""
    words = text.split()
    if not words:
        return []
    lines = []
    current_line = words[0]
    for word in words[1:]:
        if len(current_line) + 1 + len(word) <= width:
            current_line += " " + word
        else:
            lines.append(current_line)
            current_line = word
    lines.append(current_line)
    return lines


def draw_wrapped_text(stdscr, y: int, x: int, text: str, attr: int = 0, max_y_limit: int | None = None) -> int:
    """Draw text wrapped to terminal width, starting at (y, x).

    Returns the next available y coordinate after drawing.
    """
    max_screen_y, max_x = stdscr.getmaxyx()
    available_width = max_x - x
    if available_width < 10:
        return y
    wrapped = wrap_text(text, available_width)
    for i, line in enumerate(wrapped):
        draw_y = y + i
        if max_y_limit and draw_y >= max_y_limit:
            break
        if draw_y < max_screen_y:
            draw_line(stdscr, draw_y, x, line, attr)
    return y + len(wrapped)


def draw_checkbox(
    stdscr, y: int, x: int, checked: bool, text: str, selected: bool = False
):
    """Draw a checkbox line."""
    attr = curses.A_BOLD if selected else curses.A_NORMAL
    if selected:
        attr |= curses.A_REVERSE

    marker = "[x]" if checked else "[ ]"
    line = f"{marker} {text}"
    draw_line(stdscr, y, x, line, attr)


def draw_header(stdscr, y: int, title: str):
    """Draw a section header."""
    max_y, max_x = stdscr.getmaxyx()
    draw_line(stdscr, y, 0, "=" * max_x, curses.A_BOLD)
    draw_line(stdscr, y + 1, 2, title, curses.A_BOLD | curses.A_UNDERLINE)
    draw_line(stdscr, y + 2, 0, "=" * max_x, curses.A_BOLD)


def draw_footer(stdscr, y: int, hints: list[str]):
    """Draw footer with key hints."""
    max_y, max_x = stdscr.getmaxyx()
    if y < max_y - 1:
        hint_text = "  |  ".join(hints)
        draw_line(stdscr, max_y - 1, 0, "-" * max_x, curses.A_BOLD)
        draw_line(stdscr, max_y - 1, 2, hint_text, curses.A_BOLD)


def draw_progress(stdscr, y: int, text: str, percentage: float = 0):
    """Draw a progress indicator."""
    max_y, max_x = stdscr.getmaxyx()
    bar_width = max(20, min(40, max_x - 30))
    filled = int(bar_width * percentage)
    bar = "█" * filled + "░" * (bar_width - filled)
    line = f"{text}: [{bar}] {percentage:.0f}%"
    draw_line(stdscr, y, 2, line, curses.A_BOLD)


def draw_progress_log(
    stdscr,
    title: str,
    log: list[tuple[str, str]],
    current_idx: int = 0,
) -> None:
    """
    Draw a scrollable progress log.

    log: list of (status, message) tuples.
    status: '✓' for done, '...' for in-progress, '✗' for failed
    current_idx: index of the currently processing item, or -1 to skip highlighting
    """
    curses.curs_set(0)
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    draw_header(stdscr, 0, title)

    # Available lines for log content (header takes ~3 lines, footer 1 line)
    start_y = 4
    end_y = max_y - 2
    visible = end_y - start_y
    if visible < 1:
        visible = 1

    # Auto-scroll: keep current item visible near bottom
    if current_idx >= visible:
        scroll_offset = current_idx - visible + 1
    else:
        scroll_offset = 0

    for i in range(visible):
        log_idx = scroll_offset + i
        screen_y = start_y + i
        if log_idx < len(log):
            status, msg = log[log_idx]
            is_current = current_idx >= 0 and log_idx == current_idx
            if is_current:
                attr = curses.A_BOLD | curses.A_REVERSE
            else:
                attr = curses.A_NORMAL
            line = f" {status} {msg}"
            draw_line(stdscr, screen_y, 0, line, attr)
        else:
            draw_line(stdscr, screen_y, 0, "", curses.A_NORMAL)

    draw_footer(
        stdscr,
        max_y - 2,
        [f"{len(log)} events", "↑/↓: Scroll", "PgUp/PgDn: Page", "q: Quit"],
    )
    stdscr.refresh()


def progress_log_key_handler(stdscr, total: int, scroll_offset: int, key: int) -> tuple[int, int]:
    """Handle key presses for the progress log screen.

    Returns (new_scroll_offset, should_break).
    """
    max_y, max_x = stdscr.getmaxyx()
    visible = max_y - 6  # header(3) + footer(1) + padding
    if visible < 1:
        visible = 1

    if key == curses.KEY_UP:
        scroll_offset = max(0, scroll_offset - 1)
    elif key == curses.KEY_DOWN:
        scroll_offset = min(max(0, total - visible), scroll_offset + 1)
    elif key == curses.KEY_PPAGE:
        scroll_offset = max(0, scroll_offset - visible)
    elif key == curses.KEY_NPAGE:
        scroll_offset = min(max(0, total - visible), scroll_offset + visible)
    elif key == ord("q"):
        sys.exit(0)

    return scroll_offset, False


def draw_review_log_viewer(stdscr, log: list[tuple[str, str]]) -> None:
    """Draw a scrollable view of the complete log (read-only, no current-item highlight)."""
    curses.curs_set(0)
    max_y, max_x = stdscr.getmaxyx()

    draw_header(stdscr, 0, "Completed Security Review")

    start_y = 4
    end_y = max_y - 2
    visible = end_y - start_y
    if visible < 1:
        visible = 1

    scroll_offset = 0
    stdscr.refresh()
    stdscr.nodelay(False)

    while True:
        stdscr.erase()
        draw_header(stdscr, 0, "Completed Security Review")

        for i in range(visible):
            log_idx = scroll_offset + i
            screen_y = start_y + i
            if log_idx < len(log):
                status, msg = log[log_idx]
                attr = curses.A_NORMAL
                line = f" {status} {msg}"
                draw_line(stdscr, screen_y, 0, line, attr)
            else:
                draw_line(stdscr, screen_y, 0, "", curses.A_NORMAL)

        draw_footer(
            stdscr,
            max_y - 2,
            [f"{len(log)} events", "↑/↓: Scroll", "PgUp/PgDn: Page", "Enter: Continue"],
        )
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP:
            scroll_offset = max(0, scroll_offset - 1)
        elif key == curses.KEY_DOWN:
            scroll_offset = min(max(0, len(log) - visible), scroll_offset + 1)
        elif key == curses.KEY_PPAGE:
            scroll_offset = max(0, scroll_offset - visible)
        elif key == curses.KEY_NPAGE:
            scroll_offset = min(max(0, len(log) - visible), scroll_offset + visible)
        elif key in (ord("\n"), curses.KEY_ENTER):
            break


# ─── TUI Screens ─────────────────────────────────────────────────────────────


def screen_package_list(
    stdscr,
    packages: list[str],
    title: str,
    info_line_1: str,
    info_line_2: str,
) -> list[str]:
    """Show a checkbox list of packages for selection."""
    curses.curs_set(0)
    stdscr.clear()
    stdscr.nodelay(False)

    focused_idx = 0
    scroll_offset = 0
    checked = {pkg: False for pkg in packages}

    while True:
        stdscr.clear()
        max_y, max_x = stdscr.getmaxyx()

        draw_header(stdscr, 0, title)

        draw_line(stdscr, 4, 2, info_line_1)
        draw_line(stdscr, 5, 2, info_line_2)

        start_y = 7
        visible = max_y - start_y - 3
        visible = max(visible, 1)

        if focused_idx < scroll_offset:
            scroll_offset = focused_idx
        elif focused_idx >= scroll_offset + visible:
            scroll_offset = focused_idx - visible + 1

        for i in range(visible):
            pkg_idx = scroll_offset + i
            if pkg_idx >= len(packages):
                break
            pkg = packages[pkg_idx]
            screen_y = start_y + i
            draw_checkbox(
                stdscr,
                screen_y,
                2,
                checked.get(pkg, False),
                pkg,
                focused_idx == pkg_idx,
            )

        draw_footer(
            stdscr,
            max_y - 2,
            ["↑/↓: Navigate", "PgUp/PgDn: Page", "Space: Toggle", "Enter: Confirm", "q: Quit"],
        )

        stdscr.refresh()
        key = stdscr.getch()

        if key == curses.KEY_UP:
            focused_idx = max(0, focused_idx - 1)
        elif key == curses.KEY_DOWN:
            focused_idx = min(len(packages) - 1, focused_idx + 1)
        elif key == curses.KEY_PPAGE:
            focused_idx = max(0, focused_idx - visible)
        elif key == curses.KEY_NPAGE:
            focused_idx = min(len(packages) - 1, focused_idx + visible)
        elif key == curses.KEY_HOME:
            focused_idx = 0
        elif key == curses.KEY_END:
            focused_idx = len(packages) - 1
        elif key == ord(" "):
            if packages:
                checked[packages[focused_idx]] = not checked[packages[focused_idx]]
        elif key == ord("a"):
            checked = {pkg: True for pkg in packages}
        elif key == ord("n"):
            checked = {pkg: False for pkg in packages}
        elif key == ord("q"):
            sys.exit(0)
        elif key in (ord("\n"), curses.KEY_ENTER):
            selected = [pkg for pkg in packages if checked.get(pkg, False)]
            if selected:
                return selected


def screen_compromised_check(
    stdscr,
    packages: list[str],
) -> set[str]:
    """Fetch the compromised packages list with a progress indicator,
    then show a scrollable list of check results.

    Returns the compromised set (to be assigned to KNOWN_COMPROMISED).
    """
    curses.curs_set(0)
    stdscr.nodelay(False)

    # Phase 1: Download with progress indicator
    result = [set()]
    def fetch_thread():
        result[0] = _fetch_compromised_list()
    t = threading.Thread(target=fetch_thread, daemon=True)
    t.start()

    # Draw progress indicator while waiting for the thread
    stdscr.nodelay(True)
    while t.is_alive():
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()
        draw_header(stdscr, 0, "Compromised Package Check")
        draw_line(stdscr, 4, 2, "Downloading compromised packages list...")
        draw_line(stdscr, 5, 2, "This may take a moment.")
        draw_footer(stdscr, max_y - 2, ["Waiting..."])
        stdscr.refresh()
        time.sleep(0.5)
    stdscr.nodelay(False)

    compromised = result[0]

    # Phase 2: Show results + full compromised list in scrollable view
    hits = [pkg for pkg in packages if pkg in compromised]

    # Build all scrollable entries
    all_entries: list[tuple[str, str]] = []
    for pkg in packages:
        if pkg in compromised:
            all_entries.append(("✗", f"{pkg} — found in compromised list"))
        else:
            all_entries.append(("✓", f"{pkg} — clean"))

    # Separator + full compromised list
    sorted_compromised = sorted(compromised)
    if sorted_compromised:
        all_entries.append(("", ""))
        all_entries.append(("", "─── Full Compromised Packages List ───"))
        all_entries.append(("", f"Total known compromised: {len(sorted_compromised)}"))
        all_entries.append(("", ""))
        for pkg in sorted_compromised:
            marker = "✗" if pkg in packages else " "
            all_entries.append((marker, pkg))

    scroll_offset = 0

    while True:
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()
        end_y = max_y - 2

        draw_header(stdscr, 0, "Compromised Package Check")

        if hits:
            draw_line(stdscr, 4, 2, f"⚠ {len(hits)} package(s) found in compromised list!")
        else:
            draw_line(stdscr, 4, 2, "No packages found in the compromised list.")
        draw_line(stdscr, 5, 2, f"Total packages checked: {len(packages)}")

        content_start = 7
        content_end = max_y - 2
        content_visible = content_end - content_start
        if content_visible < 1:
            content_visible = 1

        for i in range(content_visible):
            entry_idx = scroll_offset + i
            screen_y = content_start + i
            if entry_idx < len(all_entries):
                marker, msg = all_entries[entry_idx]
                attr = curses.A_NORMAL
                if marker == "✗":
                    attr = curses.color_pair(1)
                elif msg.startswith("───"):
                    attr = curses.A_BOLD | curses.A_UNDERLINE
                elif not msg:
                    attr = curses.A_DIM
                line = f" {msg}"
                draw_line(stdscr, screen_y, 0, line, attr)
            else:
                draw_line(stdscr, screen_y, 0, "", curses.A_NORMAL)

        draw_footer(
            stdscr,
            max_y - 2,
            [f"{len(all_entries)} entries", "↑/↓: Scroll", "PgUp/PgDn: Page", "Any key: Continue"],
        )
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP:
            scroll_offset = max(0, scroll_offset - 1)
        elif key == curses.KEY_DOWN:
            scroll_offset = min(max(0, len(all_entries) - content_visible), scroll_offset + 1)
        elif key == curses.KEY_PPAGE:
            scroll_offset = max(0, scroll_offset - content_visible)
        elif key == curses.KEY_NPAGE:
            scroll_offset = min(max(0, len(all_entries) - content_visible), scroll_offset + content_visible)
        else:
            break

    return compromised


def screen_vulnerability_alert(
    stdscr, pkgname: str, vulns: list[str]
) -> bool:
    """Show vulnerability warning for a package. Returns True if user wants to continue."""
    curses.curs_set(0)
    stdscr.clear()
    stdscr.nodelay(False)

    max_y, max_x = stdscr.getmaxyx()

    draw_header(stdscr, 0, f"⚠ Vulnerability Alert: {pkgname}")

    draw_line(stdscr, 4, 2, "The following vulnerabilities were detected:")
    for i, vuln in enumerate(vulns):
        draw_line(stdscr, 6 + i, 4, f"• {vuln}")

    draw_footer(
        stdscr,
        max_y - 2,
        ["y: Continue anyway", "n: Skip this package", "q: Quit"],
    )

    stdscr.refresh()

    while True:
        key = stdscr.getch()
        if key == ord("y"):
            return True
        elif key == ord("n"):
            return False
        elif key == ord("q"):
            sys.exit(0)


def _build_review_lines(
    pkgname: str,
    pkgbuild: str,
    metadata: dict,
    vulns: list[str],
    review: dict,
    local_risk: dict | None = None,
    max_width: int = 80,
) -> list[tuple[str, int]]:
    """Build the full scrollable content for the security review screen.

    Returns a list of (text, curses_attr) tuples.
    """
    lines: list[tuple[str, int]] = []

    rating = review.get("rating", "unknown")
    ai_score = review.get("risk_score", 50)
    ai_available = review.get("ai_available", True)

    lines.append((f"Security Review: {pkgname}", curses.A_BOLD))

    # Risk scores — side by side
    ai_score_line = f"AI Risk: {ai_score}/100" if ai_available else "AI Risk: unavailable"
    if local_risk:
        local_line = f"Local Risk: {local_risk['score']}/100"
    else:
        local_line = "Local Risk: N/A"
    lines.append((f"{ai_score_line}    {local_line}", curses.A_BOLD))

    if ai_available:
        attr = curses.color_pair(1 if rating == "high" else (2 if rating == "medium" else 3))
        lines.append((f"AI Rating: {rating.upper()}", attr | curses.A_BOLD))
    else:
        lines.append(("AI Rating: unavailable", curses.A_DIM))

    if local_risk:
        local_rating = "high" if local_risk["score"] >= 70 else ("medium" if local_risk["score"] >= 40 else "low")
        local_attr = curses.color_pair(1 if local_rating == "high" else (2 if local_rating == "medium" else 3))
        lines.append((f"Local Rating: {local_rating.upper()} ({local_risk['score']}/100)", local_attr | curses.A_BOLD))

    # Metadata
    lines.append(("Package Metadata:", curses.A_BOLD))
    lines.append((f"Version: {metadata.get('Version', 'unknown')}", 0))
    lines.append((f"Last Change: {metadata.get('last_change_date', 'N/A')}", 0))
    lines.append((f"Maintainer Changed: {metadata.get('maintainer_change_date', 'N/A')}", 0))

    # AUR API Data
    lines.append(("AUR API Data:", curses.A_BOLD))
    lines.append((f"Maintainer: {metadata.get('aur_maintainer', 'N/A')}", 0))
    lines.append((f"Submitter: {metadata.get('aur_submitter', 'N/A')}", 0))
    lines.append((f"Co-Maintainers: {metadata.get('aur_co_maintainers', 'N/A')}", 0))
    lines.append((f"License: {metadata.get('aur_license', 'N/A')}", 0))
    _url = metadata.get("aur_url", "N/A")
    if _url and len(_url) > 50:
        _url = _url[:47] + "..."
    lines.append((f"URL: {_url}", 0))
    lines.append((f"Depends: {metadata.get('aur_depends', 'N/A')}", 0))
    lines.append((f"MakeDepends: {metadata.get('aur_makedepends', 'N/A')}", 0))
    lines.append((f"Num Votes: {metadata.get('aur_num_votes', 'N/A')}", 0))
    lines.append((f"Popularity: {metadata.get('aur_popularity', 'N/A')}", 0))
    lines.append((f"First Submitted: {metadata.get('aur_first_submitted', 'N/A')}", 0))
    lines.append((f"Last Modified: {metadata.get('aur_last_modified', 'N/A')}", 0))

    # Vulnerabilities
    if vulns:
        lines.append(("Vulnerabilities Detected:", curses.A_BOLD))
        for vuln in vulns:
            lines.append((f"• {vuln}", curses.color_pair(1)))

    # Local risk factors
    if local_risk and local_risk.get("factors"):
        lines.append(("Local Risk Factors:", curses.A_BOLD))
        for text, points in local_risk["factors"]:
            lines.append((f"• {text} (+{points})", curses.A_DIM))
        diff_detail = local_risk.get("diff_details", "")
        if diff_detail and "minimal change" not in diff_detail:
            lines.append((f"  Diff: {diff_detail}", curses.A_DIM))

    # AI Summary
    if ai_available:
        summary = review.get("summary", "No summary available")
        lines.append((f"AI Assessment: {summary}", curses.A_BOLD))
    else:
        lines.append(("AI Assessment: unavailable — relying on local analysis", curses.A_DIM))

    # Details
    details = review.get("details", [])
    if details:
        lines.append(("Findings:", curses.A_BOLD))
        for detail in details[:8]:  # Limit to 8 findings
            severity = detail.get("severity", "info").upper()
            finding = detail.get("finding", "")
            sev_color = 3 if severity == "INFO" else (2 if severity == "WARNING" else 1)
            lines.append((f"[{severity}] {finding}", curses.color_pair(sev_color)))

    # PKGBUILD content
    if pkgbuild:
        lines.append(("" + "─" * (max_width - 2), curses.A_DIM))
        lines.append(("PKGBUILD", curses.A_BOLD | curses.A_UNDERLINE))
        lines.append(("" + "─" * (max_width - 2), curses.A_DIM))
        for line in pkgbuild.splitlines():
            wrapped = wrap_text(line, max_width - 4)
            for w in wrapped:
                lines.append((w, curses.A_DIM))

    return lines


def screen_security_review(
    stdscr,
    pkgname: str,
    pkgbuild: str,
    metadata: dict,
    vulns: list[str],
    review: dict,
    local_risk: dict | None = None,
) -> bool:
    """Show security review result for a package with scroll support."""
    curses.curs_set(0)
    stdscr.nodelay(False)

    max_y, max_x = stdscr.getmaxyx()

    # Build all content lines
    max_width = max_x - 2  # available width for content (indented at x=2)
    all_lines = _build_review_lines(pkgname, pkgbuild, metadata, vulns, review, local_risk, max_width)
    total_lines = len(all_lines)

    # Header takes 1 line, footer takes 1 line
    scroll_offset = 0

    while True:
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()

        # Visible content area: header(1) + footer(1) = 2 reserved lines
        visible = max_y - 2
        if visible < 1:
            visible = 1

        # Clamp scroll offset
        max_offset = max(0, total_lines - visible)
        scroll_offset = max(0, min(scroll_offset, max_offset))

        # Draw header
        header_text = all_lines[0][0]
        draw_line(stdscr, 0, 0, "=" * max_x, curses.A_BOLD)
        draw_line(stdscr, 0, 2, header_text, curses.A_BOLD | curses.A_UNDERLINE)
        draw_line(stdscr, 0, 0, "=" * max_x, curses.A_BOLD)

        # Draw visible content lines
        for i in range(visible):
            line_idx = scroll_offset + i
            screen_y = 1 + i
            if line_idx < len(all_lines):
                text, attr = all_lines[line_idx]
                draw_line(stdscr, screen_y, 2, text, attr)

        # Footer
        scroll_hint = f"  ↑/↓: Scroll ({scroll_offset + 1}/{total_lines})" if total_lines > visible else ""
        draw_line(stdscr, max_y - 1, 0, "-" * max_x, curses.A_BOLD)
        draw_line(stdscr, max_y - 1, 2, f"y: Install  n: Skip  q: Quit{scroll_hint}", curses.A_BOLD)

        stdscr.refresh()

        key = stdscr.getch()
        if key == ord("y"):
            return True
        elif key == ord("n"):
            return False
        elif key == ord("q"):
            sys.exit(0)
        elif key == curses.KEY_UP:
            scroll_offset = max(0, scroll_offset - 1)
        elif key == curses.KEY_DOWN:
            scroll_offset = min(max_offset, scroll_offset + 1)
        elif key == curses.KEY_PPAGE:
            scroll_offset = max(0, scroll_offset - visible)
        elif key == curses.KEY_NPAGE:
            scroll_offset = min(max_offset, scroll_offset + visible)


def screen_confirmation(stdscr, packages: list[str]) -> list[str]:
    """Show final confirmation screen before installation."""
    curses.curs_set(0)
    stdscr.clear()
    stdscr.nodelay(False)

    max_y, max_x = stdscr.getmaxyx()

    draw_header(stdscr, 0, "Ready to Install")

    draw_line(stdscr, 4, 2, f"The following {len(packages)} package(s) will be installed:")
    for i, pkg in enumerate(packages):
        draw_line(stdscr, 6 + i, 4, f"  ✓ {pkg}")

    draw_line(stdscr, 6 + len(packages) + 2, 2, "This will require sudo privileges.")
    draw_line(stdscr, 7 + len(packages) + 2, 2, "Installation will use makepkg -si in each package directory.")

    draw_footer(
        stdscr,
        max_y - 2,
        ["y: Start Installation", "q: Cancel"],
    )

    stdscr.refresh()

    while True:
        key = stdscr.getch()
        if key == ord("y"):
            return packages
        elif key == ord("q"):
            sys.exit(0)


def screen_done(
    stdscr,
    packages: list[str],
    log: list[tuple[str, str]] | None = None,
) -> None:
    """Show completion screen with optional full event log."""
    curses.curs_set(0)
    max_y, max_x = stdscr.getmaxyx()

    draw_header(stdscr, 0, "✓ Installation Complete")

    draw_line(stdscr, 4, 2, f"Successfully installed {len(packages)} package(s):")
    for i, pkg in enumerate(packages):
        draw_line(stdscr, 6 + i, 4, f"  ✓ {pkg}")

    if log:
        draw_line(stdscr, 6 + len(packages) + 2, 2, "", curses.A_BOLD)
        draw_line(stdscr, 6 + len(packages) + 3, 2, "Event Log:", curses.A_BOLD | curses.A_UNDERLINE)
        start_y = 6 + len(packages) + 4
        end_y = max_y - 2
        visible = end_y - start_y
        if visible < 1:
            visible = 1

        scroll_offset = 0
        stdscr.refresh()
        stdscr.nodelay(False)

        while True:
            stdscr.erase()
            draw_header(stdscr, 0, "✓ Installation Complete")
            draw_line(stdscr, 4, 2, f"Successfully installed {len(packages)} package(s):")
            for i, pkg in enumerate(packages):
                draw_line(stdscr, 6 + i, 4, f"  ✓ {pkg}")
            draw_line(stdscr, 6 + len(packages) + 2, 2, "", curses.A_BOLD)
            draw_line(stdscr, 6 + len(packages) + 3, 2, "Event Log:", curses.A_BOLD | curses.A_UNDERLINE)

            for i in range(visible):
                log_idx = scroll_offset + i
                screen_y = start_y + i
                if log_idx < len(log):
                    status, msg = log[log_idx]
                    attr = curses.A_NORMAL
                    line = f" {status} {msg}"
                    draw_line(stdscr, screen_y, 0, line, attr)
                else:
                    draw_line(stdscr, screen_y, 0, "", curses.A_NORMAL)

            draw_footer(
                stdscr,
                max_y - 2,
                [f"{len(log)} events", "↑/↓: Scroll", "PgUp/PgDn: Page", "q: Quit", "Any other: Exit"],
            )
            stdscr.refresh()

            key = stdscr.getch()
            if key == curses.KEY_UP:
                scroll_offset = max(0, scroll_offset - 1)
            elif key == curses.KEY_DOWN:
                scroll_offset = min(max(0, len(log) - visible), scroll_offset + 1)
            elif key == curses.KEY_PPAGE:
                scroll_offset = max(0, scroll_offset - visible)
            elif key == curses.KEY_NPAGE:
                scroll_offset = min(max(0, len(log) - visible), scroll_offset + visible)
            elif key == ord("q"):
                sys.exit(0)
            else:
                break
    else:
        draw_footer(
            stdscr,
            max_y - 2,
            ["Press any key to exit"],
        )
        stdscr.refresh()
        stdscr.nodelay(True)
        stdscr.getch()


# ─── Installation ─────────────────────────────────────────────────────────────


def install_package(
    stdscr,
    pkgname: str,
    cache_dir: str,
) -> bool:
    """Install a package using makepkg -si.

    Temporarily exits curses mode so makepkg/sudo can use a real TTY.
    """
    repo_dir = Path(cache_dir) / pkgname

    if not repo_dir.exists():
        print(f"Repository not found: {repo_dir}", file=sys.stderr)
        return False

    try:
        # Restore terminal so makepkg/sudo can use it
        try:
            curses.endwin()
        except curses.error:
            pass

        result = subprocess.run(
            ["makepkg", "-si", "--noconfirm"],
            cwd=str(repo_dir),
        )

        return result.returncode == 0
    except Exception as e:
        print(f"Installation failed: {pkgname} — {e}", file=sys.stderr)
        return False


# ─── Main Flow ────────────────────────────────────────────────────────────────


def run_upgrade_mode(stdscr, config: dict) -> None:
    """Run the upgrade mode: detect AUR packages, review, and upgrade."""
    packages = get_installed_aur_packages()

    if not packages:
        curses.curs_set(0)
        stdscr.clear()
        draw_header(stdscr, 0, "No AUR Packages Found")
        draw_line(stdscr, 4, 2, "You have no packages installed from the AUR.")
        draw_footer(stdscr, stdscr.getmaxyx()[0] - 2, ["Press any key to exit"])
        stdscr.refresh()
        stdscr.nodelay(True)
        stdscr.getch()
        return

    selected = screen_package_list(
        stdscr,
        packages,
        "Upgrade AUR Packages",
        f"Found {len(packages)} AUR packages installed.",
        "Select packages to upgrade, then press Enter.",
    )
    if not selected:
        return

    _run_review_and_install(selected, config, stdscr)


def _fetch_pkg_data(pkg: str, config: dict) -> dict:
    """Fetch all data for a single package. Returns dict with aur_info, metadata, pkgbuild, vulns, local_risk."""
    cache_dir = config["cache_dir"]
    clone_or_pull_repo(pkg, cache_dir)
    aur_info = get_aur_pkginfo(pkg)
    git_meta = get_repo_metadata(pkg, cache_dir)
    pkgbuild = fetch_pkgbuild(pkg, cache_dir)
    pkgbuild_diff = get_pkgbuild_diff(pkg, cache_dir)
    download_urls = _extract_download_urls(pkgbuild)
    checksums = _check_checksums(pkgbuild)
    package_type = _determine_package_type(pkgbuild)
    has_systemd = _check_systemd_service(pkgbuild)
    has_install = _check_install_script(pkgbuild)
    metadata = _build_metadata(aur_info, pkgbuild, git_meta,
                               pkgbuild_diff, download_urls, checksums,
                               package_type, has_systemd, has_install)
    vulns = check_vulnerabilities(pkg, aur_info) if config.get("vulnerability_check", True) else []
    local_risk = compute_local_risk_score(pkg, metadata, aur_info, pkgbuild_diff)
    return {
        "aur_info": aur_info,
        "metadata": metadata,
        "pkgbuild": pkgbuild,
        "vulns": vulns,
        "local_risk": local_risk,
    }


def _run_review_and_install(
    selected: list[str],
    config: dict,
    stdscr,
    pkg_data: dict[str, dict] | None = None,
) -> None:
    """Shared flow: vulnerability alerts, AI review, per-package review, confirmation, install."""

    # Fetch the compromised packages list with progress and show results
    global KNOWN_COMPROMISED
    KNOWN_COMPROMISED = screen_compromised_check(stdscr, selected)

    # Fetch metadata if not pre-fetched
    if pkg_data is None:
        pkg_data = {}
        log: list[tuple[str, str]] = []
        for i, pkg in enumerate(selected):
            log.append(("...", f"{pkg} — git clone/pull"))
            pkg_data[pkg] = _fetch_pkg_data(pkg, config)
            log[-1] = ("✓", f"{pkg} — git clone/pull")
            draw_progress_log(stdscr, "Conducting Security Review", log, -1)
    else:
        log = []  # Will be populated during AI review phase

    # Vulnerability checks — build new list excluding skipped packages
    selected = [
        pkg for pkg in selected
        if pkg_data[pkg]["vulns"]
        and screen_vulnerability_alert(stdscr, pkg, pkg_data[pkg]["vulns"])
        or not pkg_data[pkg]["vulns"]
    ]

    if not selected:
        return

    # AI Security Review
    for i, pkg in enumerate(selected):
        log.append(("-", f"{pkg} — AI security review"))
        draw_progress_log(stdscr, "Conducting Security Review", log, -1)
        review = call_ai_review(
            pkg,
            pkg_data[pkg]["pkgbuild"] or "",
            pkg_data[pkg]["metadata"],
            config,
        )
        pkg_data[pkg]["review"] = review
        log[-1] = ("✓", f"{pkg} — AI security review")
        draw_progress_log(stdscr, "Conducting Security Review", log, -1)

    # Show complete log
    draw_review_log_viewer(stdscr, log)

    # Present review results
    packages_to_install = []
    for pkg in selected:
        review = pkg_data[pkg]["review"]
        local_risk = pkg_data[pkg].get("local_risk")
        proceed = screen_security_review(
            stdscr,
            pkg,
            pkg_data[pkg]["pkgbuild"] or "",
            pkg_data[pkg]["metadata"],
            pkg_data[pkg]["vulns"],
            review,
            local_risk,
        )
        if proceed:
            packages_to_install.append(pkg)

    if not packages_to_install:
        return

    # Final confirmation
    confirmed = screen_confirmation(stdscr, packages_to_install)

    # Install
    for pkg in confirmed:
        install_package(stdscr, pkg, config["cache_dir"])


def run_install_mode(stdscr, config: dict, packages: list[str]) -> None:
    """Run the install mode: install specified AUR packages."""
    # Validate that packages exist in AUR
    aur_infos = get_aur_pkginfos(packages)
    valid_packages = []
    invalid_packages = []

    for pkg in packages:
        if pkg in aur_infos:
            valid_packages.append(pkg)
        else:
            invalid_packages.append(pkg)

    if invalid_packages:
        curses.curs_set(0)
        stdscr.clear()
        draw_header(stdscr, 0, "Package Validation Failed")
        draw_line(stdscr, 4, 2, "The following packages were not found in AUR:")
        for pkg in invalid_packages:
            draw_line(stdscr, 6 + invalid_packages.index(pkg), 4, f"  ✗ {pkg}")
        draw_footer(stdscr, stdscr.getmaxyx()[0] - 2, ["Press any key to exit"])
        stdscr.refresh()
        stdscr.nodelay(True)
        stdscr.getch()
        return

    selected = screen_package_list(
        stdscr,
        valid_packages,
        "Install AUR Packages",
        f"Packages to install: {len(valid_packages)}",
        "Select packages to install, then press Enter.",
    )
    if not selected:
        return

    # Pre-fetch data using already-known aur_infos
    pkg_data = {}
    for pkg in selected:
        aur_info = aur_infos[pkg]
        clone_or_pull_repo(pkg, config["cache_dir"])
        git_meta = get_repo_metadata(pkg, config["cache_dir"])
        pkgbuild = fetch_pkgbuild(pkg, config["cache_dir"])
        pkgbuild_diff = get_pkgbuild_diff(pkg, config["cache_dir"])
        download_urls = _extract_download_urls(pkgbuild)
        checksums = _check_checksums(pkgbuild)
        package_type = _determine_package_type(pkgbuild)
        has_systemd = _check_systemd_service(pkgbuild)
        has_install = _check_install_script(pkgbuild)
        metadata = _build_metadata(aur_info, pkgbuild, git_meta,
                                   pkgbuild_diff, download_urls, checksums,
                                   package_type, has_systemd, has_install)
        vulns = check_vulnerabilities(pkg, aur_info) if config.get("vulnerability_check", True) else []
        local_risk = compute_local_risk_score(pkg, metadata, aur_info, pkgbuild_diff)
        pkg_data[pkg] = {
            "aur_info": aur_info,
            "metadata": metadata,
            "pkgbuild": pkgbuild,
            "vulns": vulns,
            "local_risk": local_risk,
        }

    _run_review_and_install(selected, config, stdscr, pkg_data)


# ─── Entry Point ──────────────────────────────────────────────────────────────


_curses_restored = False


def _restore_terminal(signum=None, frame=None):
    """Restore terminal state on exit (Ctrl+C, etc.)."""
    global _curses_restored
    if not _curses_restored:
        _curses_restored = True
        try:
            curses.nocbreak()
            curses.echo()
            curses.curs_set(1)
            curses.endwin()
        except Exception:
            pass
        sys.exit(1)


def main():
    signal.signal(signal.SIGINT, _restore_terminal)
    signal.signal(signal.SIGTERM, _restore_terminal)

    parser = argparse.ArgumentParser(
        description="yea - Yet Another AUR installer with AI security review"
    )
    parser.add_argument(
        "packages",
        nargs="*",
        help="Packages to install (omit for upgrade mode)",
    )
    args = parser.parse_args()

    config = load_config()

    stdscr = curses.initscr()
    try:
        run(stdscr, args.packages, config)
    finally:
        curses.nocbreak()
        stdscr.keypad(False)
        curses.echo()
        curses.curs_set(1)
        # Do NOT call curses.endwin() — leave terminal output visible


def run(stdscr, packages: list[str], config: dict) -> None:
    """Main TUI entry point."""
    curses.curs_set(0)
    stdscr.keypad(True)
    curses.start_color()
    curses.use_default_colors()
    try:
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
    except curses.error:
        pass
    stdscr.clear()

    if not packages:
        run_upgrade_mode(stdscr, config)
    else:
        run_install_mode(stdscr, config, packages)


if __name__ == "__main__":
    main()
