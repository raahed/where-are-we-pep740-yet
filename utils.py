import datetime
import hashlib
import json
import os
import re
from urllib.parse import urlparse

import pytz
import requests
import requests_cache

BASE_URL = "https://pypi.org"
# Provenance began to be persisted on 2024-10-03
# And `pypa/gh-action-pypi-publish` turned it automatically on 2024-10-29
ATTESTATION_ENABLEMENT = datetime.datetime(2024, 10, 29, tzinfo=datetime.timezone.utc)

PUBLISHER_URLS = (
    "https://github.com",
    "http://github.com",
    "http://gitlab.com",
    "https://gitlab.com",
)

DEPRECATED_PACKAGES = {
    "BeautifulSoup",
    "bs4",
    "distribute",
    "django-social-auth",
    "nose",
    "pep8",
    "pycrypto",
    "pypular",
    "sklearn",
}

# Keep responses for one hour
SESSION = requests_cache.CachedSession("requests-cache", expire_after=60 * 60)

# Cap for hashing release assets when their digest is not exposed inline.
MAX_ATTESTATION_ASSET_SIZE = 50 * 1024 * 1024  # 50 MiB


def _github_headers():
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _gitlab_headers():
    headers = {}
    token = os.environ.get("GITLAB_TOKEN")
    if token:
        headers["PRIVATE-TOKEN"] = token
    return headers


def get_simple_url(package_name):
    return f"{BASE_URL}/simple/{package_name}/"


def get_json_url(package_name):
    return f"{BASE_URL}/pypi/{package_name}/json"


def parse_github_url(url):
    """Extract owner/repo from GitHub URL. Returns (owner, repo) or (None, None)."""
    match = re.match(r"https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/?$", url)
    if match:
        return match.group(1), match.group(2).rstrip(".git")
    return None, None


def parse_gitlab_url(url):
    """Extract owner/repo from GitLab URL. Returns (owner, repo) or (None, None)."""
    match = re.match(r"https?://gitlab\.com/([^/]+)/([^/]+)/?$", url)
    if match:
        return match.group(1), match.group(2).rstrip(".git")
    return None, None


def _asset_looks_like_attestation(name):
    name = (name or "").lower()
    return ".intoto.jsonl" in name or ".attestation" in name or ".sigstore" in name


def _sha256_of_url(url):
    """Stream-download a URL and return its sha256 hex digest, or None."""
    try:
        with requests.get(url, stream=True, timeout=30) as resp:
            if resp.status_code != 200:
                return None
            h = hashlib.sha256()
            total = 0
            for chunk in resp.iter_content(64 * 1024):
                total += len(chunk)
                if total > MAX_ATTESTATION_ASSET_SIZE:
                    return None
                h.update(chunk)
            return h.hexdigest()
    except Exception:
        return None


def check_github_release_attestation(owner, repo):
    """Check if the latest GitHub release has attestations."""
    try:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
        response = SESSION.get(url, headers=_github_headers())
        if response.status_code != 200:
            return False

        release = response.json()
        for asset in release.get("assets", []):
            name = asset.get("name", "")
            if _asset_looks_like_attestation(name):
                return True

            # Prefer the inline digest if the uploader provided one, otherwise
            # hash the asset ourselves (subject to a size cap) and query
            # GitHub's attestations endpoint.
            digest = asset.get("digest")
            if not digest:
                size = asset.get("size") or 0
                if size and size > MAX_ATTESTATION_ASSET_SIZE:
                    continue
                download_url = asset.get("browser_download_url")
                if download_url:
                    digest = _sha256_of_url(download_url)
            if digest and _github_has_attestation(owner, repo, digest):
                return True

        return False
    except Exception:
        return False


def _github_has_attestation(owner, repo, subject_digest):
    """Query GitHub's attestations endpoint for a specific artifact digest."""
    try:
        if not subject_digest.startswith("sha256:"):
            subject_digest = f"sha256:{subject_digest}"
        url = (
            f"https://api.github.com/repos/{owner}/{repo}"
            f"/attestations/{subject_digest}"
        )
        response = SESSION.get(url, headers=_github_headers())
        if response.status_code != 200:
            return False
        return bool(response.json().get("attestations"))
    except Exception:
        return False


def check_gitlab_release_attestation(owner, repo):
    """Check if the latest GitLab release has attestations."""
    try:
        project_id = f"{owner}%2F{repo}"
        url = (
            f"https://gitlab.com/api/v4/projects/{project_id}"
            f"/releases/permalink/latest"
        )
        response = SESSION.get(url, headers=_gitlab_headers())

        if response.status_code != 200:
            return False

        release = response.json()

        assets = release.get("assets", {}) or {}
        for link in assets.get("links", []) or []:
            if _asset_looks_like_attestation(link.get("name", "")):
                return True

        return False
    except Exception:
        return False


def check_repo_attestation(repo_url):
    """Check if the latest repository release has attestations."""
    if not repo_url:
        return None  # No repository URL

    owner, repo = parse_github_url(repo_url)
    if owner and repo:
        return check_github_release_attestation(owner, repo)

    owner, repo = parse_gitlab_url(repo_url)
    if owner and repo:
        return check_gitlab_release_attestation(owner, repo)

    return None  # Unknown repository type



def annotate_wheels(packages):
    print("Getting wheel data...")
    num_packages = len(packages)
    for index, package in enumerate(packages):
        print(index + 1, num_packages, package["name"])
        has_provenance = False
        from_supported_publisher = False
        repo_attestation = None
        repo_url = None

        json_response = SESSION.get(get_json_url(package["name"]))
        json_response.raise_for_status()
        json_data = json_response.json()
        info = json_data["info"]
        project_urls = info["project_urls"] or {}

        # Extract repository URL
        for key, url in project_urls.items():
            if url.startswith(PUBLISHER_URLS):
                from_supported_publisher = True
                if not repo_url:  # Use the first supported publisher URL found
                    repo_url = url
                break

        # info["version"] is what PyPI considers the latest stable release.
        stable_filenames = {
            f["filename"] for f in json_data["releases"][info["version"]]
        }

        simple_response = SESSION.get(
            get_simple_url(package["name"]),
            headers={"Accept": "application/vnd.pypi.simple.v1+json"},
        )
        if simple_response.status_code != 200:
            print(" ! Skipping " + package["name"])
            continue
        simple = simple_response.json()

        stable_files = [
            f
            for f in simple["files"]
            if f["filename"] in stable_filenames
        ]
        if not stable_files:
            print(" ! Skipping " + package["name"] + " (no stable files)")
            continue

        if stable_files[-1].get("provenance", None):
            has_provenance = True

        latest_upload = max(
            datetime.datetime.fromisoformat(f["upload-time"]) for f in stable_files
        )

        # Check repository for attestations
        if repo_url:
            repo_attestation = check_repo_attestation(repo_url)

        package["wheel"] = has_provenance
        package["repo_attestation"] = repo_attestation
        package["attestation_location"] = "none"  # default

        if has_provenance and repo_attestation:
            package["attestation_location"] = "both"
        elif has_provenance:
            package["attestation_location"] = "pypi"
        elif repo_attestation:
            package["attestation_location"] = "repo"

        # Display logic. I know, I'm sorry.
        package["value"] = 1
        if has_provenance:
            package["css_class"] = "success"
            if repo_attestation:
                package["icon"] = "🔏"
                package["title"] = "This package provides attestations on PyPI and in the repository."
            else:
                package["icon"] = "🐍"
                package["title"] = "This package provides attestations on PyPI (but not in the repository)."
        elif repo_attestation:
            package["css_class"] = "success"
            package["icon"] = "📦"
            package["title"] = "This package provides attestations in the repository (but not on PyPI)."
        elif not from_supported_publisher:
            package["css_class"] = "unsupported"
            package["icon"] = ""
            package["title"] = (
                "This package is published from a source that doesn't support attestations (yet!)"
            )
        elif latest_upload < ATTESTATION_ENABLEMENT:
            package["css_class"] = "default"
            package["icon"] = "⏰"
            package["title"] = (
                "This package was last uploaded before PEP 740 was enabled."
            )
        else:
            package["css_class"] = "warning"
            package["icon"] = ""
            package["title"] = "This package doesn't provide attestations (yet!)"


def get_top_packages():
    print("Getting packages...")

    with open("top-pypi-packages.json") as data_file:
        packages = json.load(data_file)["rows"]

    # Rename keys
    for package in packages:
        package["downloads"] = package.pop("download_count")
        package["name"] = package.pop("project")

    return packages


def not_deprecated(package):
    return package["name"] not in DEPRECATED_PACKAGES


def remove_irrelevant_packages(packages, limit):
    print("Removing cruft...")
    active_packages = list(filter(not_deprecated, packages))
    return active_packages[:limit]


def save_to_file(packages, file_name):
    now = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
    with open(file_name, "w") as f:
        f.write(
            json.dumps(
                {
                    "data": packages,
                    "last_update": now.strftime("%A, %d %B %Y, %X %Z"),
                },
                indent=1,
            )
        )
