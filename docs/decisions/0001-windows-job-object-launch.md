# ADR 0001: Race-free Windows Job Object assignment

- Status: Proposed
- Date: 2026-11-20
- Scope: `scripts/verify_build_provenance.py`

## Context

The verifier currently starts the GitHub CLI with Python's `subprocess.Popen`, then opens the process by PID and calls `AssignProcessToJobObject`. The Job Object uses `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.

This prevents descendants created after successful assignment from outliving the verifier's cleanup. It does not guarantee containment for a descendant created in the interval between process creation and Job Object assignment. The limitation is documented in `SECURITY.md`.

## Platform support

Microsoft documents `PROC_THREAD_ATTRIBUTE_JOB_LIST` as supported on Windows 10 and later and Windows Server 2016 and later. The attribute supplies an ordered list of Job Object handles to assign to the new process during process creation.

The native launch sequence is:

1. Create and configure the Job Object, including `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
2. Call `InitializeProcThreadAttributeList` to size and initialize a `STARTUPINFOEX` attribute list.
3. Add `PROC_THREAD_ATTRIBUTE_JOB_LIST` with `UpdateProcThreadAttribute`. Keep the backing array of Job handles alive until the attribute list is deleted.
4. Call `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT`, the extended startup structure, and the intended process-creation flags. The process is assigned to the Job as part of creation, before its user-mode code can create descendants.
5. Close the primary thread handle and retain the process handle and Job handle for waiting, termination, and cleanup. Always delete the attribute list and release temporary resources on every exit path.

The documented attribute key is `PROC_THREAD_ATTRIBUTE_JOB_LIST`, equivalent to `ProcThreadAttributeValue(13, FALSE, TRUE, FALSE)` (0x0002000D).

## Why Popen cannot currently provide this

Python documents `STARTUPINFO.lpAttributeList` as supporting `handle_list`; it does not expose a `job_list` key. Supplying an undocumented key or relying on CPython private process internals would be brittle and is not an acceptable security boundary.

A race-free implementation therefore needs a small native Win32 process-launch adapter rather than a post-spawn `Popen` adjustment.

## Required adapter contract

Before implementation, define and test an explicit process abstraction that provides the operations the verifier actually needs:

- process identifier and stable process handle;
- bounded wait/poll with an observable exit code;
- termination of the Job Object and guaranteed reaping of the direct child;
- deterministic close of process, thread, Job, and attribute-list resources;
- preservation of the existing command argument semantics, executable resolution, working directory, inherited environment, and Unicode handling;
- stdout and stderr redirection to the existing bounded temporary files;
- exact, minimal handle inheritance, preferably using `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` together with `bInheritHandles=TRUE`;
- cleanup that preserves the primary launch/wait error while reporting secondary cleanup failures.

The implementation must use a writable Unicode command-line buffer for `CreateProcessW`, construct a correctly terminated Unicode environment block when supplying an explicit environment, and validate all standard handles passed through `STARTF_USESTDHANDLES`. The process and primary-thread handles returned in `PROCESS_INFORMATION` must be closed on all paths.

## Compatibility and failure policy

- Do not silently fall back to post-spawn assignment when strict containment is requested; that would reintroduce the documented race while appearing successful.
- If support for Windows versions older than Windows 10 is required, make the weaker fallback an explicit, documented policy decision. The current repository CI tests only the hosted `windows-latest` environment and do not establish compatibility with older Windows releases.
- Treat Job assignment or process creation failure as launch failure. Do not run the CLI outside the intended Job.
- Account for environments where the parent process is already in a Job Object. Validate nested-job behavior and failure modes on supported Windows configurations rather than assuming assignment always succeeds.

## Validation plan

A follow-up implementation should add Windows integration tests that:

1. Launch a parent that immediately creates a child before it can execute any application-level synchronization; prove the child is already in the Job at creation.
2. Verify successful exit still terminates descendants that inherited stdout/stderr handles.
3. Verify timeout and output-limit failures terminate the complete Job and reap the direct child.
4. Exercise launch failures at each attribute-list and CreateProcess stage, checking every acquired handle is released.
5. Exercise command lines with spaces, quotes, Unicode, empty arguments, custom environments, and working directories.
6. Verify no unrelated inheritable handles leak into the child.
7. Run on the oldest supported Windows version, not only the newest hosted runner.

## Decision

Do not replace the current launcher in a small patch. Keep the existing implementation and its explicit limitation until the adapter contract and Windows integration tests are ready. Implement the native path as a separately reviewable change, with a clearly declared minimum Windows version and no silent weakening fallback.
