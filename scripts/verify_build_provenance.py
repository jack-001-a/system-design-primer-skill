#!/usr/bin/env python3
"""Verify GitHub-hosted SLSA build provenance for a distribution artifact.

Cryptographic bundle, certificate, transparency-log, and trust-root verification
is delegated to a security-patched GitHub CLI. This wrapper adds a strict
repository, workflow, source-ref, source-commit, predicate, and subject policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GH_VERSION_RE = re.compile(r"^gh version (\d+)\.(\d+)\.(\d+)(?: \([^()\r\n]+\))?$")
MIN_GH_VERSION = (2, 102, 0)
GH_VERSION_TIMEOUT_SECONDS = 30
GH_VERIFY_TIMEOUT_SECONDS = 300
GH_VERSION_STDOUT_LIMIT_BYTES = 64 * 1024
GH_VERIFY_STDOUT_LIMIT_BYTES = 16 * 1024 * 1024
GH_STDERR_LIMIT_BYTES = 64 * 1024
GH_STDERR_TAIL_BYTES = 4 * 1024
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def _is_valid_git_ref(ref: str) -> bool:
    """Apply git-check-ref-format rules relevant to an untrusted CLI argument."""
    if not isinstance(ref, str) or not ref.startswith(("refs/heads/", "refs/tags/")):
        return False
    forbidden = (" ", "~", "^", ":", "?", "*", "[", chr(92))
    if any(ord(char) < 32 or ord(char) == 127 or char in forbidden for char in ref):
        return False
    if ref.endswith(("/", ".")) or "//" in ref or ".." in ref or "@{" in ref:
        return False
    components = ref.split("/")
    return all(component and component != "@" and not component.startswith(".") and not component.endswith((".", ".lock")) for component in components)



def _require_regular_file(path: Path, label: str) -> None:
    """Reject symlinks and non-regular filesystem objects at the input boundary."""
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} must identify an existing regular file") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} must identify an existing regular file, not a symlink or special file")


def _copy_regular_file_snapshot(source: Path, destination: Path, label: str) -> None:
    """Copy from one verified file descriptor, rejecting path swaps and observed writes."""
    try:
        before = source.lstat()
    except OSError as exc:
        raise ValueError(f"{label} must identify an existing regular file") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must identify an existing regular file, not a symlink or special file")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ValueError(f"{label} could not be opened as a regular file") from exc

    try:
        source_stream = os.fdopen(descriptor, "rb")
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise

    destination_created = False
    try:
        with source_stream:
            opened = os.fstat(source_stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError(f"{label} changed identity while being opened")
            destination_flags = (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            )
            destination_descriptor = os.open(destination, destination_flags, 0o600)
            destination_created = True
            try:
                destination_stream = os.fdopen(destination_descriptor, "wb")
            except Exception:
                try:
                    os.close(destination_descriptor)
                except OSError:
                    pass
                raise
            with destination_stream:
                shutil.copyfileobj(source_stream, destination_stream)
            after = os.fstat(source_stream.fileno())
            stable_fields = ("st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(opened, field, None) != getattr(after, field, None) for field in stable_fields):
                raise ValueError(f"{label} changed while being snapshotted")
    except Exception:
        if destination_created:
            try:
                destination.unlink()
            except OSError:
                # Preserve the original snapshot failure; the enclosing private
                # TemporaryDirectory remains responsible for final cleanup.
                pass
        raise



def _create_windows_job(process: subprocess.Popen[bytes]):
    """Assign the CLI to a kill-on-close Job Object so descendants cannot outlive it."""
    if os.name != "nt":
        return None

    import ctypes
    from ctypes import wintypes

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL

    def dispose_job(handle) -> list[str]:
        """Best-effort termination and checked close, retrying one failed close."""
        failures = []
        if not kernel32.TerminateJobObject(handle, 1):
            failures.append(f"TerminateJobObject failed (WinError {ctypes.get_last_error()})")
        if not kernel32.CloseHandle(handle):
            first_error = ctypes.get_last_error()
            if not kernel32.CloseHandle(handle):
                failures.append(
                    "CloseHandle(Job) failed twice "
                    f"(WinError {first_error}, {ctypes.get_last_error()})"
                )
        return failures

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    process_handle = None
    primary_error = None
    primary_traceback = None
    cleanup_errors = []
    try:
        limits = ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        # Obtain documented Win32 access rights by PID, not CPython's private Popen handle.
        process_handle = kernel32.OpenProcess(
            0x0100 | 0x0001,  # PROCESS_SET_QUOTA | PROCESS_TERMINATE
            False,
            process.pid,
        )
        if not process_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.AssignProcessToJobObject(job, process_handle):
            raise ctypes.WinError(ctypes.get_last_error())
    except BaseException as exc:
        primary_error = exc
        primary_traceback = exc.__traceback__
        cleanup_errors.extend(dispose_job(job))
    finally:
        if process_handle and not kernel32.CloseHandle(process_handle):
            first_error = ctypes.get_last_error()
            if not kernel32.CloseHandle(process_handle):
                cleanup_errors.append(
                    "CloseHandle(process) failed twice "
                    f"(WinError {first_error}, {ctypes.get_last_error()})"
                )
                # If assignment succeeded, dispose the Job so the CLI cannot
                # outlive this failed setup path.
                if primary_error is None:
                    cleanup_errors.extend(dispose_job(job))
            elif primary_error is None:
                # The first close failed but the retry succeeded; surface the
                # API failure rather than silently accepting an abnormal close.
                cleanup_errors.append(
                    f"CloseHandle(process) initially failed (WinError {first_error})"
                )
                cleanup_errors.extend(dispose_job(job))

    if primary_error is not None:
        if cleanup_errors:
            raise RuntimeError(
                "Windows Job Object setup failed and cleanup was incomplete: "
                + "; ".join(cleanup_errors)
            ) from primary_error
        raise primary_error.with_traceback(primary_traceback)
    if cleanup_errors:
        raise RuntimeError(
            "Windows Job Object setup could not release its process handle: "
            + "; ".join(cleanup_errors)
        )
    return job


def _close_windows_job(job) -> None:
    """Close a Job Object; KILL_ON_JOB_CLOSE terminates all remaining members."""
    if job is None:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    if not kernel32.CloseHandle(job):
        close_error = ctypes.WinError(ctypes.get_last_error())
        # A failed close must not degrade to killing only the CLI leader: the
        # Job may still own descendants that inherited the output handles.
        if not kernel32.TerminateJobObject(job, 1):
            terminate_error = ctypes.WinError(ctypes.get_last_error())
            raise RuntimeError(
                "could not close or terminate the GitHub CLI Job Object"
            ) from terminate_error
        if not kernel32.CloseHandle(job):
            raise ctypes.WinError(ctypes.get_last_error()) from close_error


def _kill_and_reap_cli(
    process: subprocess.Popen[bytes], windows_job=None
) -> None:
    """Stop the isolated CLI process tree where supported, then reap its leader."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            # Retain a direct-child fallback if process-group signaling is unavailable.
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
    elif windows_job is not None:
        _close_windows_job(windows_job)
    elif process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    process.wait()


def _run_cli_bounded(
    command: list[str],
    *,
    timeout: int,
    output_dir: Path,
    stdout_limit: int,
    stderr_limit: int = GH_STDERR_LIMIT_BYTES,
) -> subprocess.CompletedProcess[str]:
    """Run a CLI with bounded output checks and a wall-clock deadline."""
    stdout_path = output_dir / "cli-stdout"
    stderr_path = output_dir / "cli-stderr"
    deadline = time.monotonic() + timeout
    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        process = subprocess.Popen(
            command,
            stdout=stdout_file,
            stderr=stderr_file,
            text=False,
            start_new_session=(os.name == "posix"),
        )
        windows_job = None
        try:
            if os.name == "nt":
                windows_job = _create_windows_job(process)
        except BaseException:
            _kill_and_reap_cli(process)
            raise
        failure = None
        try:
            while True:
                try:
                    returncode = process.wait(
                        timeout=min(0.05, max(0.0, deadline - time.monotonic()))
                    )
                    break
                except subprocess.TimeoutExpired:
                    stdout_size = stdout_path.stat().st_size
                    stderr_size = stderr_path.stat().st_size
                    if stdout_size > stdout_limit:
                        failure = RuntimeError(
                            f"GitHub CLI stdout exceeded the {stdout_limit}-byte limit"
                        )
                        break
                    if stderr_size > stderr_limit:
                        failure = RuntimeError(
                            f"GitHub CLI stderr exceeded the {stderr_limit}-byte limit"
                        )
                        break
                    if time.monotonic() >= deadline:
                        failure = subprocess.TimeoutExpired(command, timeout)
                        break

            # Also stop descendants that inherited the output handles. On POSIX,
            # start_new_session gives this CLI an isolated process group.
            _kill_and_reap_cli(process, windows_job)
            windows_job = None
        except BaseException:
            try:
                _kill_and_reap_cli(process, windows_job)
                windows_job = None
            except BaseException:
                # Preserve the operation's original failure after attempting cleanup.
                if process.poll() is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                process.wait()
            raise
        stdout_file.flush()
        stderr_file.flush()

    if failure is not None:
        raise failure
    stdout_size = stdout_path.stat().st_size
    stderr_size = stderr_path.stat().st_size
    if stdout_size > stdout_limit:
        raise RuntimeError(f"GitHub CLI stdout exceeded the {stdout_limit}-byte limit")
    if stderr_size > stderr_limit:
        raise RuntimeError(f"GitHub CLI stderr exceeded the {stderr_limit}-byte limit")
    with stdout_path.open("rb") as stream:
        stdout = stream.read(stdout_limit + 1).decode("utf-8", errors="replace")
    with stderr_path.open("rb") as stream:
        stream.seek(max(0, stderr_size - GH_STDERR_TAIL_BYTES))
        stderr = stream.read(GH_STDERR_TAIL_BYTES).decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def _version_tuple(output: str) -> tuple[int, int, int]:
    first_line = output.splitlines()[0].strip() if output.splitlines() else ""
    match = GH_VERSION_RE.fullmatch(first_line)
    if not match:
        raise RuntimeError("could not parse GitHub CLI version; require gh >= 2.102.0")
    return tuple(int(part) for part in match.groups())



def _sha256_file(path: Path) -> str:
    """Hash a file incrementally so large artifacts do not require a full-size allocation."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _validate_verified_statements(
    verified: Any, expected_sha256: str, expected_repository_id: int | None = None
) -> int:
    if not isinstance(verified, list) or not verified:
        raise RuntimeError("gh attestation verify returned no verified attestations")
    for item in verified:
        if not isinstance(item, dict):
            raise RuntimeError("gh attestation verify returned an unexpected result schema")
        result = item.get("verificationResult")
        statement = result.get("statement") if isinstance(result, dict) else None
        if not isinstance(statement, dict):
            raise RuntimeError("verified attestation is missing its in-toto statement")
        if statement.get("predicateType") != PREDICATE_TYPE:
            raise RuntimeError("verified attestation has an unexpected predicate type")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not subjects:
            raise RuntimeError("verified attestation has no subject entries")
        if not any(
            isinstance(subject, dict)
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == expected_sha256
            for subject in subjects
        ):
            raise RuntimeError("verified attestation does not name the exact artifact SHA-256")
        if expected_repository_id is not None:
            signature = result.get("signature")
            certificate = signature.get("certificate") if isinstance(signature, dict) else None
            actual_repository_id = (
                certificate.get("sourceRepositoryIdentifier")
                if isinstance(certificate, dict) else None
            )
            if str(actual_repository_id) != str(expected_repository_id):
                raise RuntimeError(
                    "verified attestation certificate repository ID does not match "
                    "the expected repository ID"
                )
    return len(verified)


def verify_build_provenance(
    artifact: Path,
    *,
    repository: str,
    signer_workflow: str,
    source_ref: str,
    source_digest: str,
    bundle: Path | None = None,
    trusted_root: Path | None = None,
    repository_id: int | None = None,
    gh_bin: str = "gh",
) -> dict[str, Any]:
    _require_regular_file(artifact, "artifact")
    if not REPO_RE.fullmatch(repository):
        raise ValueError("repository must use owner/repository syntax")
    workflow_prefix = repository + "/.github/workflows/"
    if (
        not signer_workflow.startswith(workflow_prefix)
        or not signer_workflow.endswith((".yml", ".yaml"))
        or "\n" in signer_workflow
        or ".." in signer_workflow
    ):
        raise ValueError("signer_workflow must be a workflow file in the expected repository")
    if not _is_valid_git_ref(source_ref):
        raise ValueError("source_ref must be a valid fully qualified Git branch or tag ref")
    if not SHA1_RE.fullmatch(source_digest):
        raise ValueError("source_digest must be a full lowercase 40-character Git commit SHA")
    if bundle is not None:
        _require_regular_file(bundle, "bundle")
    if bundle is not None:
        if repository_id is None or repository_id <= 0:
            raise ValueError("offline bundle verification requires a positive --repository-id")
        if trusted_root is None:
            raise ValueError("offline bundle verification requires --trusted-root")
    if repository_id is not None and repository_id <= 0:
        raise ValueError("repository_id must be a positive integer")
    if repository_id is not None and bundle is None:
        raise ValueError("repository_id can only be used with an offline bundle")
    if trusted_root is not None:
        if bundle is None:
            raise ValueError("trusted_root can only be used with an offline bundle")
        _require_regular_file(trusted_root, "trusted_root")

    executable = shutil.which(gh_bin)
    if executable is None:
        raise RuntimeError("GitHub CLI (gh) is required for cryptographic attestation verification")

    # Keep CLI output files inside the private workspace and remove them on exit.
    with tempfile.TemporaryDirectory(prefix="slsa-verify-") as temp_dir:
        snapshot_dir = Path(temp_dir)
        artifact_snapshot = snapshot_dir / "artifact" / artifact.name
        artifact_snapshot.parent.mkdir()
        _copy_regular_file_snapshot(artifact, artifact_snapshot, "artifact")
        artifact_sha256 = _sha256_file(artifact_snapshot)
        bundle_snapshot = None
        if bundle is not None:
            bundle_snapshot = snapshot_dir / "bundle" / bundle.name
            bundle_snapshot.parent.mkdir()
            _copy_regular_file_snapshot(bundle, bundle_snapshot, "bundle")
        trusted_root_snapshot = None
        if trusted_root is not None:
            trusted_root_snapshot = snapshot_dir / "trusted-root" / trusted_root.name
            trusted_root_snapshot.parent.mkdir()
            _copy_regular_file_snapshot(trusted_root, trusted_root_snapshot, "trusted_root")

        try:
            version = _run_cli_bounded(
                [executable, "version"],
                timeout=GH_VERSION_TIMEOUT_SECONDS,
                output_dir=snapshot_dir,
                stdout_limit=GH_VERSION_STDOUT_LIMIT_BYTES,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("timed out while determining GitHub CLI version") from exc
        if version.returncode != 0:
            raise RuntimeError("could not determine GitHub CLI version")
        gh_version = _version_tuple(version.stdout)
        if gh_version < MIN_GH_VERSION:
            raise RuntimeError(
                "GitHub CLI >= 2.102.0 is required; older releases have vulnerable "
                "source-ref and signer-workflow identity matching"
            )

        command = [
            executable, "attestation", "verify", str(artifact_snapshot),
            "--repo", repository,
            "--signer-workflow", signer_workflow,
            "--source-ref", source_ref,
            "--source-digest", source_digest,
            "--cert-oidc-issuer", OIDC_ISSUER,
            "--predicate-type", PREDICATE_TYPE,
            "--deny-self-hosted-runners",
            "--format", "json",
        ]
        if bundle is not None:
            command.extend(["--bundle", str(bundle_snapshot)])
        if trusted_root is not None:
            command.extend(["--custom-trusted-root", str(trusted_root_snapshot)])
        try:
            completed = _run_cli_bounded(
                command,
                timeout=GH_VERIFY_TIMEOUT_SECONDS,
                output_dir=snapshot_dir,
                stdout_limit=GH_VERIFY_STDOUT_LIMIT_BYTES,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"gh attestation verify timed out after {GH_VERIFY_TIMEOUT_SECONDS} seconds"
            ) from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "no diagnostic output").strip()
            raise RuntimeError("gh attestation verify rejected the artifact: " + detail[-GH_STDERR_TAIL_BYTES:])
        try:
            verified = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("gh attestation verify returned invalid JSON despite success") from exc
        count = _validate_verified_statements(verified, artifact_sha256, repository_id if bundle is not None else None)

    return {
        "verified": True,
        "verification_tool": "gh attestation verify",
        "minimum_gh_version": "2.102.0",
        "repository": repository,
        "signer_workflow": signer_workflow,
        "source_ref": source_ref,
        "source_digest": source_digest,
        "predicate_type": PREDICATE_TYPE,
        "oidc_issuer": OIDC_ISSUER,
        "self_hosted_runners_denied": True,
        "artifact_sha256": artifact_sha256,
        "verified_attestation_count": count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--repo", required=True, dest="repository")
    parser.add_argument("--signer-workflow", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--bundle", type=Path, help="Previously downloaded attestation bundle (JSON or JSONL)")
    parser.add_argument("--trusted-root", type=Path, help="Explicit Sigstore trusted-root JSONL for offline verification; requires --bundle")
    parser.add_argument("--repository-id", type=int, help="Expected numeric GitHub repository ID; required with --bundle")
    parser.add_argument("--gh-bin", default="gh", help="GitHub CLI executable (default: gh)")
    args = parser.parse_args()
    try:
        result = verify_build_provenance(
            args.artifact,
            repository=args.repository,
            signer_workflow=args.signer_workflow,
            source_ref=args.source_ref,
            source_digest=args.source_digest,
            bundle=args.bundle,
            trusted_root=args.trusted_root,
            repository_id=args.repository_id,
            gh_bin=args.gh_bin,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
