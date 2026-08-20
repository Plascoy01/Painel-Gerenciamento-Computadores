"""plascoy modules.external_tools

Unified wrapper for optional external recon tools.

This file must be syntactically valid because plascoy imports it lazily.

Flags used by plascoy:
  --external
  --gobuster
  --ffuf
  --nmap
  --whatweb

Safety:
- Never fails hard if a binary is missing.
- Returns dicts describing status/findings.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List, Optional

from colorama import Fore, Style, init

init(autoreset=True)


def _has(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


def _run(cmd: List[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _normalize_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def run_gobuster(target: str, threads: int = 10, timeout: int = 300, wordlist: Optional[str] = None) -> Dict[str, Any]:
    target = _normalize_target(target).rstrip("/")
    if not _has("gobuster"):
        return {"status": "missing", "tool": "gobuster"}

    cmd = ["gobuster", "dir", "-u", target, "-t", str(threads), "-q"]
    if wordlist:
        cmd += ["-w", wordlist]

    try:
        cp = _run(cmd, timeout=timeout)
        return {
            "status": "success",
            "tool": "gobuster",
            "stdout": cp.stdout,
            "stderr": cp.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "gobuster"}


def run_ffuf(target: str, threads: int = 40, timeout: int = 300, wordlist: Optional[str] = None) -> Dict[str, Any]:
    if not _has("ffuf"):
        return {"status": "missing", "tool": "ffuf"}

    target = _normalize_target(target).rstrip("/")
    url_with_fuzz = target + "/FUZZ"

    cmd = ["ffuf", "-u", url_with_fuzz, "-t", str(threads), "-c"]
    if wordlist:
        cmd += ["-w", wordlist]

    try:
        cp = _run(cmd, timeout=timeout)
        return {
            "status": "success",
            "tool": "ffuf",
            "stdout": cp.stdout,
            "stderr": cp.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "ffuf"}


def run_nmap(target: str, scan_type: str = "-sV", timeout: int = 300) -> Dict[str, Any]:
    if not _has("nmap"):
        return {"status": "missing", "tool": "nmap"}

    # allow URL or hostname
    host = target
    if target.startswith(("http://", "https://")):
        host = target.split("//", 1)[1].split("/", 1)[0]

    cmd = ["nmap", host, scan_type, "-oG", "-"]

    try:
        cp = _run(cmd, timeout=timeout)
        return {
            "status": "success",
            "tool": "nmap",
            "stdout": cp.stdout,
            "stderr": cp.stderr,
            "returncode": cp.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "nmap"}


def run_whatweb(target: str, aggression: int = 3, timeout: int = 60) -> Dict[str, Any]:
    if not _has("whatweb"):
        return {"status": "missing", "tool": "whatweb"}

    target = _normalize_target(target)
    cmd = ["whatweb", target, "-q", "-a", str(aggression)]

    try:
        cp = _run(cmd, timeout=timeout)
        return {
            "status": "success",
            "tool": "whatweb",
            "stdout": cp.stdout,
            "stderr": cp.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "whatweb"}


def run_all_external_tools(target: str, threads: int = 10) -> Dict[str, Any]:
    results: Dict[str, Any] = {"tools": {}}

    if _has("gobuster"):
        results["tools"]["gobuster"] = run_gobuster(target, threads=threads)

    if _has("ffuf"):
        results["tools"]["ffuf"] = run_ffuf(target, threads=threads)

    if _has("nmap"):
        results["tools"]["nmap"] = run_nmap(target)

    if _has("whatweb"):
        results["tools"]["whatweb"] = run_whatweb(target)

    return results


__all__ = [
    "run_gobuster",
    "run_ffuf",
    "run_nmap",
    "run_whatweb",
    "run_all_external_tools",
]

