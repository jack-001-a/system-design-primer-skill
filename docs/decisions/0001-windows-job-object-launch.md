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
## Additional implementation hazards

### Handle inheritance is a process-wide concern

Using `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` is the correct way to constrain which inheritable handles the new child receives. It does not make temporary inheritability harmless to unrelated concurrent process creation: another component that concurrently calls a process-creation API with unrestricted handle inheritance can still receive a handle while its inherit flag is set.

The native adapter must therefore:

- create or duplicate dedicated stdout/stderr handles rather than changing inheritance on shared file handles;
- set inheritance only for the shortest possible interval around `CreateProcessW`;
- pass an explicit handle list and `bInheritHandles=TRUE`;
- restore/close every temporary handle on all success and failure paths;
- document the residual interaction with unrelated process creation in a multithreaded host.

A Python-level lock local to this adapter cannot serialize process creation performed by unrelated libraries. Do not claim that the handle list alone eliminates this cross-component inheritance race. If the host requires a strict no-leak guarantee against concurrent process creation, the launch mechanism needs a host-wide process-creation coordination policy or a different output transport design.

### Parent Job Object membership

The verifier itself may already run inside a CI runner or other host Job Object. Windows 8 and later support nested jobs, but successful association still depends on the existing job hierarchy, session, and applicable limits. The launcher must not assume that creating its own Job Object guarantees assignment will succeed.

The launch path must fail closed if the requested Job association cannot be established. It must not silently retry without `PROC_THREAD_ATTRIBUTE_JOB_LIST`. Integration tests should cover both an uncontained parent and a parent already assigned to an outer Job, and record the exact supported host configurations.

### API contract boundaries

The documented contract establishes that the listed jobs are assigned during process creation and that the attribute storage must remain alive until the attribute list is deleted. Do not infer undocumented rollback or cancellation guarantees if the creating thread/process is interrupted while `CreateProcessW` is executing. Keep the Job handle alive until the call has returned and the returned process/thread handles have been reconciled; any stronger crash-consistency claim requires separate evidence.

## Additional validation gates

Before enabling the native path by default:

- add a Windows test in which the child process immediately attempts to create a grandchild, with no application-level startup delay; assert the grandchild is terminated when the owning Job closes;
- run a concurrent process-creation stress test while stdout/stderr inheritance is enabled, and verify unrelated children do not receive the verifier's file handles;
- test launch from inside an outer Job with nested jobs allowed and with a deliberately incompatible outer-job configuration;
- test each failure point after Job creation, attribute-list allocation, each attribute update, and process creation, asserting all acquired resources are closed;
- test that a failed Job-list process creation never falls back to an uncontained launch.
## Helper-process broker alternative for strict handle isolation

A process-local lock does not protect inheritable handles from unrelated code that calls `CreateProcess(..., bInheritHandles=TRUE, ...)` concurrently. A dedicated helper process is a documented alternative worth prototyping before requiring a host-wide lock.

The proposed broker design is:

1. Start a small helper process with ordinary non-inheriting process creation. The helper holds no application file handles and remains alive while launch requests are serviced (or waits for the host process to exit).
2. Keep the verifier's stdout/stderr file handles non-inheritable in the verifier process.
3. For one launch request, duplicate only the required file handles into the helper process with `DuplicateHandle`, marking the remote duplicates inheritable.
4. Build the target's `STARTUPINFOEX` attributes with both `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (the helper-owned duplicate handles) and `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (the helper process handle).
5. Include `PROC_THREAD_ATTRIBUTE_JOB_LIST` in the same attribute list. Create the target with `bInheritHandles=TRUE` and `EXTENDED_STARTUPINFO_PRESENT`; set standard handles to the helper-owned duplicate values.
6. After `CreateProcessW` returns, close the temporary duplicate handles in the helper and retain only the target process and Job handles needed for supervision.

This follows the helper-process pattern described by Raymond Chen for avoiding the reverse handle-inheritance race: the main host's own handles remain non-inheritable, while only the helper's short-lived duplicates are eligible for inheritance. See the linked engineering note in the implementation research record.

### Important unresolved questions

- Confirm the exact access rights required for the helper process handle used by `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, and verify the helper can be opened with `PROCESS_CREATE_PROCESS`.
- Confirm the handle-list entries are interpreted in the specified parent process context as required by the helper pattern; test with real Win32 handles, not only mocks.
- Define synchronization and ownership for remote duplicate handles when multiple launch requests overlap. A per-launch helper is simpler but costs process startup; a shared broker needs request IDs, serialization or safe concurrent ownership, and crash cleanup.
- Verify how the target inherits the helper's existing Job membership while also receiving the explicit `PROC_THREAD_ATTRIBUTE_JOB_LIST`. Exercise the actual CI/outer-Job environment.
- Ensure helper startup itself does not inherit verifier handles, and ensure helper termination cannot strand remote handles or orphan the target.
- Treat helper creation, remote duplication, attribute setup, target creation, and remote-handle closure as separate failure points with explicit cleanup.

The helper-process design is a candidate, not yet an implementation decision. It may provide stronger isolation than temporarily toggling inheritability in the multithreaded host, but its lifecycle and Job Object interactions must be proven by Windows integration tests before adoption.

## Revised handle-inheritance decision gate

Do not treat a local lock plus `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` as a strict process-wide no-leak guarantee. Compare at least these two candidates in a Windows prototype:

- **Host-coordinated direct launch:** all process creation in the host must participate in one coordination policy while temporary inheritable handles exist.
- **Dedicated helper-process launch:** only the helper owns inheritable duplicates; the host's ordinary handles remain non-inheritable.

Select the simpler candidate only after a concurrent process-creation test demonstrates that unrelated children cannot acquire the verifier's stdout/stderr handles. Keep the native launch disabled until that test and the Job-list lifecycle tests pass on Windows CI.


## Helper architecture comparison: parent surrogate vs. launch broker

The helper-process candidate has two materially different forms. They must not be treated as interchangeable because they place the target's process-creation call and handle-list interpretation in different processes.

### Mode A: helper as a handle holder and designated parent

The host duplicates selected stdout/stderr handles into a helper process, then the host itself calls `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` naming that helper. The target's parent-related inherited attributes come from the helper, while the host remains the API caller.

Advantages:

- The host retains direct ownership of target creation and can keep its existing wait/termination control flow.
- A helper can isolate inheritable duplicates from unrelated process creation in the host.

Costs and proof obligations:

- The caller, designated parent, and target are three distinct process contexts. The exact interpretation and access requirements of `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` must be proven against real handles on every supported Windows version.
- The helper must remain alive and retain its duplicate handles until the target creation call has completed; the host must coordinate that lifetime over IPC.
- The target inherits parent-related attributes from the helper, including Job Object association. The interaction between helper Job membership and an explicit `PROC_THREAD_ATTRIBUTE_JOB_LIST` must be integration-tested, especially when the host itself is already in an outer Job.
- The helper's crash, host crash, and interrupted creation call require an explicit ownership/reconciliation protocol so remote duplicates and targets are not stranded.

Do not select this mode solely because it preserves the host as the direct `CreateProcessW` caller. Its cross-process parent/handle semantics are a separate correctness surface.

### Mode B: helper as a dedicated launch broker

The host starts a small helper with non-inheriting process creation and sends launch requests over a private IPC channel. For each request, the host duplicates only the required file handles into the helper with inheritable duplicates. The helper, as the process that owns those handles, builds its own `STARTUPINFOEX` handle list and calls `CreateProcessW` itself. It also applies the target Job list during that same creation call. The host receives the target PID and a duplicated process handle (or a broker-owned opaque launch identifier plus supervised operations) through the protocol.

Advantages:

- The `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` contains handles in the calling process's own handle table; no designated-parent indirection is needed.
- The host's original stdout/stderr handles remain non-inheritable, so unrelated host threads cannot leak them through ordinary process creation.
- Job assignment remains part of the target's creation call rather than a post-spawn operation.
- The helper can be intentionally small and can own all process-creation operations, making its concurrency policy auditable.

Costs and proof obligations:

- The IPC protocol must define request identity, argument/environment transport, response framing, cancellation, timeout, and error propagation.
- The protocol must define who owns the target process handle and Job handle, how the host requests termination, and how a broker crash or host crash affects the target. A broker-owned Job configured with kill-on-close can provide fail-closed cleanup, but the exact ownership transfer and host-death behavior must be tested rather than assumed.
- If one persistent broker serves concurrent requests, serialize the interval from creating inheritable duplicates through `CreateProcessW` and closing those duplicates. No other broker thread or component may create a process during that interval. A dedicated broker must not load unrelated libraries that can independently create processes.
- A per-launch broker avoids shared-request synchronization and makes crash ownership easier to reason about, but adds process startup cost. Measure that cost before preferring a persistent broker.
- Duplicating handles into the broker requires the appropriate process-handle rights and careful validation of the returned remote handle values. Only explicitly requested handles may be duplicated.
- The broker's own startup must use non-inheriting creation and must not receive host application handles.

### Initial prototype preference

Prototype Mode B first. It has the simpler handle-table model: the process that calls `CreateProcessW` also owns the handles named by its handle list. Prefer a per-launch broker for the first correctness prototype; only consider a persistent broker after the basic protocol and cleanup behavior pass Windows integration tests and its startup overhead is measured.

This is a prototype preference, not an adoption decision. Keep the existing verifier launcher unchanged until the broker proves all of the following on Windows CI:

1. The host's original output handles remain non-inheritable, including while launches overlap with unrelated host process creation.
2. The broker's child receives exactly the intended standard handles and no unrelated inheritable handles.
3. The target is in the intended Job before its first user-mode instruction can create a descendant.
4. Timeout, output-limit, normal exit, cancellation, broker crash, and host termination have deterministic target/descendant cleanup and direct-child reaping behavior.
5. Every failure after remote duplication, Job creation, attribute-list initialization/update, and `CreateProcessW` closes or reconciles every local and remote handle.
6. Command-line quoting, empty arguments, Unicode, executable resolution, working directory, environment semantics, bounded output, and exit-code reporting match the existing `subprocess.Popen` contract used by the verifier.
7. Launches from inside supported outer Job configurations behave as documented; incompatible configurations fail closed without an uncontained retry.

The broker protocol and implementation must not claim crash safety until tests exercise process termination at each ownership transition. In particular, a remote duplicate may remain open if the host dies before sending the broker its cleanup instruction; the broker therefore needs a bounded request lifecycle and an independent way to detect a dead or disconnected host.
