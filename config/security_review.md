You are a security expert reviewing an Arch Linux AUR package for potential risks.

## Package Metadata
- **Package Name**: {pkgname}
- **Package Version**: {pkgver}
- **Last Change Date**: {last_change_date}
- **Maintainer Change Date**: {maintainer_change_date}

## AUR API Data
- **Maintainer**: {aur_maintainer}
- **Submitter**: {aur_submitter}
- **Co-Maintainers**: {aur_co_maintainers}
- **License**: {aur_license}
- **URL**: {aur_url}
- **Depends**: {aur_depends}
- **MakeDepends**: {aur_makedepends}
- **NumVotes**: {aur_num_votes}
- **Popularity**: {aur_popularity}
- **First Submitted**: {aur_first_submitted}
- **Last Modified**: {aur_last_modified}

## Package Analysis
- **Package Type**: {package_type} (source = compiles from source, binary = pre-built)
- **Download Sources**: {download_urls}
- **SHA256 Checksum**: {checksum_sha256}
- **SHA512 Checksum**: {checksum_sha512}
- **MD5 Checksum**: {checksum_md5}
- **PGP Verification**: {checksum_pgp}
- **Systemd Service**: {has_systemd_service}
- **Install Script (.install)**: {has_install_script}

## PKGBUILD Diff (Previous → Current)
```diff
{pkgbuild_diff}
```

## PKGBUILD Content
```bash
{pkgbuild}
```

## Your Task
Analyze the PKGBUILD and metadata for security risks. Consider:
1. **Supply chain risks**: Is the source trustworthy? Are checksums present?
2. **Privilege escalation**: Does the PKGBUILD run arbitrary code as root? (e.g., in `package()`, `prepare()`, `build()`)
3. **Network requests**: Does the script download or execute anything from the internet during install?
4. **Hidden payloads**: Obfuscated commands, base64-encoded payloads, or suspicious variable names
5. **Maintainer trust**: How recent is the maintainer change? Is the package recently abandoned or transferred?
6. **Build reproducibility**: Are sources verified with checksums? Are patches applied safely?
7. **Post-install hooks**: Are there any scripts that run after installation?
8. **Changes from previous version**: What changed in this update? Are there any suspicious additions?
9. **Binary vs source risk**: Binary packages carry the risk of unverifiable builds; source packages carry the risk of build-time exploits.

## Output Format
Respond ONLY with a JSON object in the following format (no markdown, no extra text):

{{
    "risk_score": <integer 1-100>,
    "rating": "<low|medium|high>",
    "summary": "<brief summary of findings>",
    "details": [
        {{
            "finding": "<description of finding>",
            "severity": "<info|warning|critical>"
        }}
    ]
}}
