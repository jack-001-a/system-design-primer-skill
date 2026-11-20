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


## Broker-to-host process supervision contract

Mode B is only viable if it preserves the supervision behavior currently consumed from `subprocess.Popen` by `_run_cli_bounded`. The broker must not return only a PID: a PID is an identifier, not a stable wait/termination capability, and reopening by PID introduces an avoidable reuse race.

### Handle and object ownership

For the first per-launch prototype, use this ownership sequence:

1. The host opens the existing bounded stdout/stderr files and captures the exact standard-input handle behavior currently used by `Popen`. Do not silently change stdin to a null device; if the current behavior depends on an inherited standard input handle, include that handle explicitly after validating it.
2. The host starts the broker with non-inheriting creation and establishes a private, authenticated-by-process-lifetime IPC channel. The broker records/opens a synchronization handle for the host so it can detect host death independently of receiving another request.
3. The host obtains and retains a broker process handle with `PROCESS_DUP_HANDLE | PROCESS_TERMINATE | SYNCHRONIZE`: `PROCESS_DUP_HANDLE` is required for the host-pull supervision-handle transfer, `PROCESS_TERMINATE` is required for bounded broker shutdown, and `SYNCHRONIZE` is required to wait for confirmed process termination. The handle must remain open until broker exit is confirmed and all transfer/cleanup decisions are resolved. It duplicates only the selected standard handles into the broker, with the broker-side duplicates marked inheritable. The remote handle values are sent over the private IPC channel; those numeric values are meaningful only in the broker's handle table.
4. The broker creates and configures the kill-on-close Job, builds `STARTUPINFOEX` with a `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` containing exactly the broker-owned standard handles, and adds `PROC_THREAD_ATTRIBUTE_JOB_LIST` for the target. It calls `CreateProcessW` itself with `bInheritHandles=TRUE` and `EXTENDED_STARTUPINFO_PRESENT`.
5. After successful creation, the broker closes its temporary inheritable standard-handle duplicates and the primary thread handle. It retains the target process and Job handles until it has duplicated the required supervision handles back to the host.
6. The broker sends its *broker-local* target process and Job handle values, plus the target PID and a request identifier, over the private IPC channel. These are source values only; the host must not treat them as usable local handles.
7. The host uses its broker process handle (opened with `PROCESS_DUP_HANDLE`) as the source-process argument to `DuplicateHandle`, and its own current-process pseudo handle as the target-process argument. It first duplicates the target process handle into itself with only `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION` (the host terminates through the Job, so it does not need `PROCESS_TERMINATE` on the process handle). It then duplicates the Job handle into itself with only `JOB_OBJECT_TERMINATE` if no additional Job queries are required. The host records each returned local handle immediately, before attempting the next transfer.
8. If either duplication or the IPC exchange fails, the host closes every local handle it successfully created only after resolving broker ownership. If the process handle was duplicated but the Job handle was not, the broker still owns the Job; the host closes its local process handle, requests cancellation while the channel is usable, and otherwise terminates/reaps the broker after the bounded shutdown interval. The broker's process exit closes its remaining Job handle and terminates the target. If both handles were duplicated but ACK delivery or broker shutdown is uncertain, the host must keep both local handles open, terminate/reap the broker if it does not exit within the bounded interval, and confirm broker process termination before deciding whether to commit or abort. On abort, the host closes its local Job handle only after broker exit is confirmed, ensuring no broker-owned Job handle can keep the target alive. The broker retains its original process and Job handles until it receives a valid ACK and exits.
9. After receiving the ACK, the broker closes its local target-process and Job handles. The host's Job handle then controls the lifetime of the Job; closing the final Job handle must retain the configured kill-on-close semantics. If the host dies before transfer/acknowledgement, the broker's host-process wait detects that condition and terminates/closes the still broker-owned Job.

The ACK is permission for the broker to retire its copies; it is not, by itself, proof that those copies have been closed. Because this is a per-launch broker, make broker-process termination the ownership-commit barrier: after sending `handles_ack`, the broker closes its request resources and exits; the host keeps both pulled handles open and waits on its already-open broker process handle for the broker to become signaled before reporting the launch handoff as committed. Process termination closes any broker-owned kernel handles that remain, even if an explicit cleanup path failed. If the broker does not exit within the bounded shutdown interval, the host calls `TerminateProcess` using its `PROCESS_TERMINATE` handle and then waits on the same still-open process handle with `WaitForSingleObject` using its `SYNCHRONIZE` right. `TerminateProcess` returning success is only a termination request, not completion; only `WAIT_OBJECT_0` confirms the broker process is signaled. `WAIT_TIMEOUT` means ownership is still unresolved. `WAIT_FAILED` or any unexpected wait result also does not confirm termination: preserve the pulled Job handle and broker process handle, surface a hard cleanup failure, and do not report handoff committed or close the Job on the assumption that the broker has exited. The host must not close its pulled Job handle while waiting or while broker termination is unresolved. Do not close the broker process handle until the wait has returned `WAIT_OBJECT_0` and the process exit status has been collected if required for diagnostics. If the host itself exits during this interval, its process teardown closes the pulled Job handle and the broker's independent host-process wait drives broker termination; either order must leave no surviving Job handle after both processes have terminated. Keep the ACK as a protocol sequencing event, but represent broker-exit confirmation separately in the host adapter lifecycle; do not equate `BrokerProtocolState("host").state == "complete"` with OS-level handle ownership having committed.

This host-pull handoff is preferred over broker-push duplication followed by sending remote handle values: the host can synchronously record every successfully duplicated local handle, so a truncated IPC response cannot conceal a local handle leak. The exact access masks and ACK/disconnect races must still be validated on Windows. Do not use `DUPLICATE_SAME_ACCESS` by default if a smaller explicit access mask is sufficient. `DuplicateHandle` requires `PROCESS_DUP_HANDLE` on the process whose handle table is being accessed; the returned value is valid in the target process context only. See Microsoft's [DuplicateHandle contract](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle) and [process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

### Broker process-handle serialization

The broker process handle is a shared kernel capability, not a freely closable implementation detail. The host adapter must give it one serialized lifecycle owner (for example, a per-broker mutex guarding the handle and lifecycle state). Every operation that can affect or depend on that handle—bounded wait, termination request, optional exit-code query, and close—must participate in that serialization policy.

Use the following monotonic lifecycle:

- `OPEN`: the process handle is valid and no termination outcome has been committed.
- `TERMINATION_REQUESTED`: a shutdown/termination path has been selected; repeated cancellation requests must join or observe this same path rather than starting a competing cleanup sequence.
- `EXIT_CONFIRMED`: a wait on the still-open handle returned `WAIT_OBJECT_0`.
- `CLOSED`: the handle was closed after exit confirmation and after any required diagnostics were collected.

A bounded wait may temporarily own the lifecycle lock. No other thread may call `CloseHandle` on the process handle while `WaitForSingleObject` is pending: Microsoft documents the wait behavior as undefined if that handle is closed before the wait returns. A second caller must wait for the current lifecycle operation to finish, then observe its recorded result; it must not race a second `TerminateProcess`, wait, or close against the first caller. Keep each wait bounded so this serialization cannot become an unbounded lock hold.

A successful `TerminateProcess` call only records that termination was requested. It does not transition to `EXIT_CONFIRMED`; only `WAIT_OBJECT_0` from a wait on the same still-open process handle does. `WAIT_TIMEOUT`, `WAIT_FAILED` (capture `GetLastError` immediately), and every unexpected result leave the outcome unresolved. In those cases preserve the process and pulled Job handles and report cleanup failure; do not close either handle or report ownership committed.

If an exit code is needed for diagnostics, query it only after `EXIT_CONFIRMED`. The broker process handle must then also have `PROCESS_QUERY_LIMITED_INFORMATION` (or the documented stronger query right); add that right at handle acquisition rather than assuming the existing `PROCESS_DUP_HANDLE | PROCESS_TERMINATE | SYNCHRONIZE` mask includes it. The wait result remains the authoritative termination test. Do not infer liveness from the numeric exit code: an application may itself exit with value `STILL_ACTIVE` (259), so that value is ambiguous when used as a standalone completion test. If diagnostics are not required, omit the query right and close after the successful wait.

### Popen-compatible adapter surface

The host-side adapter should expose the subset actually used by `_run_cli_bounded`, not imitate the entire `Popen` API:

- `pid`: the target PID returned by `CreateProcessW`;
- `poll()`: nonblocking process-handle wait and exit-code query, returning `None` while active;
- `wait(timeout)`: bounded wait with `subprocess.TimeoutExpired`-compatible behavior and the exact target exit code;
- `kill()`: terminate the target Job, not merely the direct CLI process;
- explicit idempotent close of the host-side process and Job handles, with cleanup errors surfaced without masking a primary operation failure.

The existing caller also closes the Job after a normal leader exit so that descendants retaining stdout/stderr cannot keep the temporary files alive. Preserve this behavior on success, timeout, output-limit failure, exceptions, and setup failure. A process wrapper must make ownership transfer explicit so the caller cannot accidentally close a handle twice or leak it on an exception.

### IPC framing and lifecycle

The first prototype should be single-request and per-launch. Define a versioned, length-prefixed message format with bounded message sizes and explicit request IDs even if only one request is initially allowed. The launch request must carry an argv array (not a shell command string), executable path, working directory, environment policy/data, and the broker-side standard-handle values. The response must distinguish launch failure from successful launch and include the PID plus duplicated host-side process and Job handle values.

The protocol must define these terminal transitions explicitly:

- launch rejected before any remote duplication;
- partial standard-handle duplication failure;
- Job creation/configuration failure;
- attribute-list allocation or update failure;
- `CreateProcessW` failure;
- process and Job handle transfer failure;
- host disconnect before and after successful transfer;
- target normal exit, timeout, output-limit termination, and explicit cancellation;
- broker crash at every point after it owns a remote handle.

Every remote handle created for a request must have exactly one owner and a documented close/transfer event. On partial duplication failure, the host closes every remote duplicate already created, using `DuplicateHandle(..., DUPLICATE_CLOSE_SOURCE)` or a broker acknowledgement; it must not guess which remote values exist.

When using `DUPLICATE_CLOSE_SOURCE`, treat the source handle as consumed regardless of the API return value: Win32 closes it even when `DuplicateHandle` reports an error. Record the close attempt as terminal for that exact source-process/handle pair; never retry the same numeric handle value or infer that it remains open from a failure return, because the value may already be invalid or may later be reused. If the implementation needs retryable cleanup semantics, use an explicit broker acknowledgement protocol instead, with a single owner responsible for closing the source handle. Serialize cleanup for each remote handle so cancellation, disconnect handling, and normal ACK processing cannot race to close it twice. The broker must close its temporary handles in a finally-style cleanup path. A disconnected host must cause the broker to stop accepting launches and terminate any Job for which ownership has not been transferred. After transfer, the host's Job handle is the authoritative kill-on-close lifetime anchor.

### Output and environment compatibility details

The current `Popen` call specifies stdout and stderr files, leaves stdin at its existing default, passes a command argument list, uses the current working directory and inherited environment, and waits for byte output in temporary files. The broker adapter must preserve these semantics exactly or document and separately approve any intentional change. In particular:

- quote the argument vector using the Windows command-line serialization rules expected by the target runtime; do not join argv with spaces;
- pass an explicit application name to `CreateProcessW` to avoid ambiguous executable-path parsing;
- use a writable Unicode command-line buffer;
- preserve inherited environment semantics, including Unicode and drive-current-directory entries, or pass a correctly sorted, double-NUL-terminated Unicode environment block;
- preserve the requested working directory and standard-handle behavior;
- use `STARTF_USESTDHANDLES` and verify each standard handle before process creation;
- keep the IPC control channel out of the target's handle list.

### Security boundary and residual risk

The broker is a narrow process-creation boundary, not a general-purpose remote execution service. It must accept only a structured launch request from its owning host, must not parse shell syntax, and must not expose arbitrary handle duplication or arbitrary process-control operations to untrusted clients. The host/broker IPC endpoint must be private to the same user/session and protected against other local processes attaching to it. The broker must not inherit host handles at startup.

Microsoft documents that `CreateProcessW` with `bInheritHandles=TRUE` ordinarily inherits all inheritable handles in the caller, while `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` narrows the intended child set; it also requires valid standard handles and a writable command-line buffer. The broker must therefore remain minimal and ensure every process-creation call it makes uses the explicit handle list. Do not load code into the broker that can create unrestricted child processes concurrently during the temporary-inheritability window.

The broker remains a proposed prototype architecture. No production path should switch to it until the ownership protocol, Windows integration tests, and existing verifier behavior have been demonstrated end-to-end.


### Broker rendezvous and client identity

The broker must be started without inheriting host application handles. Do not use inherited stdin/stdout pipe ends as the broker control channel: creating those inheritable pipe handles in the host can reintroduce a concurrent-process-creation leak at broker startup. Prefer a host-created local named-pipe server with a non-inheritable server handle, then start the broker with `bInheritHandles=FALSE` and pass only a random pipe name plus a one-time nonce in its command line.

Create the pipe with an explicit security descriptor restricted to the current logon SID (and the minimum required access), and set `PIPE_REJECT_REMOTE_CLIENTS`. Do not rely on the default named-pipe DACL: Microsoft's documentation notes that the default grants read access to Everyone and anonymous users. After connection, validate the connecting process ID with `GetNamedPipeClientProcessId` against the broker PID obtained from the process handle, and perform a nonce challenge before accepting any request. The nonce prevents accidental/stale endpoint attachment; the DACL and PID check establish the intended local process boundary. The pipe must use bounded, length-prefixed messages and reject duplicate, oversized, malformed, or out-of-order messages.

The broker should open/retain a synchronization handle to the host process and monitor it independently of pipe reads. The host must likewise monitor the broker process handle while the request is pending. A pipe disconnect is a protocol event, not proof by itself that either process has terminated; both process-liveness and pipe state must be considered when resolving ownership.

Relevant Windows contracts: [named-pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew), and [GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid).

### Transfer-state table

| State | Broker owns | Host owns | Required recovery |
| --- | --- | --- | --- |
| Broker ready | broker process, IPC endpoint | host originals, broker process handle | close broker and endpoint on setup failure |
| Standard handles duplicated | broker-side standard duplicates | host originals and recorded remote handle values | host closes each known remote duplicate if request aborts; broker closes all received duplicates in its cleanup path |
| Target created | target process + Job + temporary standard duplicates | host originals and broker process handle | broker kills/closes Job on host loss before handoff |
| Broker handles advertised | target process + Job | same as above | host may begin host-pull duplication; broker retains originals |
| Process handle pulled | target process + Job | local process handle | if next step fails, host closes process handle; broker closes Job on disconnect |
| Both handles pulled, no ACK or broker exit unconfirmed | target process + Job | local process + Job handles | host keeps local handles open, terminates/reaps broker if needed, confirms broker exit, then closes local Job on abort; never assume local Job close is final while broker may retain its copy |
| ACK received | none of target process/Job handles after broker closes originals | local process + Job handles | host owns supervision; host death closes final Job handle |

This table describes the intended protocol, not a claim that the implementation has been proven. Integration tests must kill either process between every adjacent state and assert handle-count/resource cleanup as well as target/descendant termination.


### Named Pipe IPC transport contract (Mode B prototype)

The per-launch broker prototype uses one dedicated local named-pipe instance for the host/broker handshake. This section defines the transport boundary; it does not authorize replacing the current production launcher.

#### Server creation and namespace ownership

- The host creates the pipe before starting the broker, using a per-launch name under `\\.\pipe\` with at least 256 bits of cryptographically secure randomness. The name is an identifier, not an authentication credential.
- Create exactly one instance (`nMaxInstances=1`) with `PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE`.
- Use byte-stream mode with the existing length-prefixed protocol. Set `PIPE_REJECT_REMOTE_CLIENTS`; do not use `PIPE_NOWAIT` as an asynchronous-I/O substitute.
- Supply an explicit, non-inheritable `SECURITY_ATTRIBUTES` and a protected DACL. The DACL must grant access only to SYSTEM and the current logon SID; do not use the default pipe DACL, which also grants read access to Everyone and anonymous users.
- Obtain the logon SID from the current process token's groups by selecting the group with `SE_GROUP_LOGON_ID`. Do not substitute the account user SID: the logon SID scopes access to the current logon session.
- Build and validate the security descriptor with supported Windows security APIs, keep its backing storage alive through `CreateNamedPipeW`, then release it on every path. Do not hand-roll SID parsing or native structure layouts.
- Use a restrictive pipe-object access mask rather than blindly granting `GENERIC_WRITE`: Microsoft documents that generic write includes `FILE_CREATE_PIPE_INSTANCE`. Determine the exact rights needed by the server creator and broker client, and cover them with Windows ACL integration tests.

#### Mutual process identity checks

- The host starts the broker with handle inheritance disabled and retains its stable process handle and PID.
- After `ConnectNamedPipe` completes, the host calls `GetNamedPipeClientProcessId` on the server handle and requires an exact match with the broker PID returned by process creation. A missing API result or mismatch is a hard authentication failure; no protocol bytes may be consumed first.
- Before sending any protocol message, the broker calls `GetNamedPipeServerProcessId` on its client handle and requires an exact match with the host PID supplied at launch. The broker must also hold a synchronization handle to the host process, opened before relying on the PID, and treat host-process termination as cancellation.
- Keep the host's broker process handle and the broker's host process handle open while the connection is active. Check process liveness through those handles rather than reopening a PID after a connection has been authenticated.
- Reject a connection on any identity-query failure. Do not fall back to pipe-name secrecy, session ID alone, or a successful protocol handshake as identity proof.
- The random name, protected DACL, remote-client rejection, first-instance flag, and PID checks are complementary controls. None is a substitute for the others.

#### Connection and I/O lifecycle

- The host creates the server instance first, then starts the broker with the pipe name and expected host PID. The broker opens the existing pipe with duplex access and `FILE_FLAG_OVERLAPPED`.
- Use overlapped `ConnectNamedPipe`, `ReadFile`, and `WriteFile` operations with a distinct manual-reset event and `OVERLAPPED` structure for each in-flight operation. A pending operation is indicated by `ERROR_IO_PENDING`; treat `ERROR_PIPE_CONNECTED` from the connect race as an already-established connection, then perform the same PID authentication.
- Reconnect only through the connection-level `start_connect` lifecycle: it requires a disconnected pipe and an empty operation registry, registers a fresh `OVERLAPPED`/event operation before calling `ConnectNamedPipe`, and holds the connection lock through submission. A pending connect remains in `CONNECTING` until its operation is completed and `complete_connect` commits the result. `ERROR_PIPE_CONNECTED` is a successful already-connected race and must signal the operation event; other immediate errors return to `DISCONNECTED`. Close and unregister the connect operation before beginning ordinary I/O or another reconnect. The state-only `mark_connected` transition is intentionally rejected; callers must use `start_connect` and, for pending operations, `complete_connect`.
- Register each read/write operation with its connection before submission. Submit it through the connection's serialized start method, which holds the connection lock through the native `ReadFile`/`WriteFile` call; this prevents `DisconnectNamedPipe` or connection reuse from passing its state check while a new operation is being submitted. The lower-level submission helper is not a connection-lifecycle API and must not be called directly for registered pipe operations.
- Every connect/read/write receives an absolute monotonic deadline. Wait only for the remaining deadline; never rely on `PIPE_NOWAIT`, default pipe timeouts, or an unbounded synchronous read.
- On timeout or cancellation, call `CancelIoEx` for the exact handle/OVERLAPPED pair and then observe/drain completion with `GetOverlappedResultEx` using a finite timeout before releasing the event, OVERLAPPED storage, or buffers. Reject `INFINITE` as a drain timeout. Handle `ERROR_NOT_FOUND` as a possible completion race, not proof that the operation's storage is safe to free. If the bounded drain returns `WAIT_TIMEOUT`/`ERROR_IO_INCOMPLETE`, retain all operation resources and permit a later drain retry; never free or reuse the OVERLAPPED storage while completion remains unresolved.
- Enforce the existing maximum frame size before allocating a body buffer. Keep the protocol's exact-read/exact-write semantics over the byte stream; partial completions are normal.
- A transport error, timeout, malformed frame, PID mismatch, or broker/host process exit closes the connection and fails the request. Do not retry a partially transmitted frame on a new connection.

#### Ownership, cancellation, and cleanup

- The host owns the server pipe handle and closes it on every exit path. The broker owns its client pipe handle. Neither pipe handle is inheritable.
- The host owns the broker process handle; the broker owns the host synchronization handle. Each process closes only handles in its own handle table.
- A single request owns one pipe instance. No shared multi-request multiplexing is introduced in this prototype.
- Host cancellation sends the protocol cancel message only while the authenticated connection is usable, then cancels pending I/O, disconnects/closes the pipe, and terminates/reaps the broker if it does not exit within the bounded shutdown interval.
- Broker cancellation or host death must stop launch setup and close any temporary duplicated handles and any created target/Job handles according to the launch ownership state. A transport disconnect is not by itself evidence that handle transfer completed.
- Cleanup is idempotent. Preserve the primary failure and report cleanup failures as secondary diagnostics.

#### Required Windows integration tests

1. Assert the created pipe has the intended protected DACL, denies an unrelated logon SID, rejects remote clients, and cannot be pre-created under the chosen name before the host's first-instance creation.
2. Connect the expected broker and an impostor process in separate tests; accept only the expected broker PID. Verify the broker independently rejects a server PID other than the host PID.
3. Exercise `ERROR_PIPE_CONNECTED`, pending connect, pending short reads/writes, peer disconnect, and PID-query failures.
4. Force connect/read/write deadlines to expire; verify `CancelIoEx` is followed by a finite `GetOverlappedResultEx` drain, `WAIT_TIMEOUT` retains event/OVERLAPPED/buffer resources for retry, and no worker or handle is released while completion remains unresolved.
5. Kill the host and broker at every handshake/handle-transfer phase; verify the surviving side closes only resources it owns and no target or Job is orphaned.
6. Verify malformed/oversized frames and partial-frame disconnects fail closed without protocol resynchronization.
7. Race two cancellation callers against one another; assert termination/wait/close are serialized, both callers observe one stable outcome, and the process handle is never closed while a wait is pending.
8. Force `WAIT_TIMEOUT`, `WAIT_FAILED`, unexpected wait values, and delayed process exit; assert unresolved outcomes retain both the broker process and pulled Job handles. Verify exit-code diagnostics occur only after `WAIT_OBJECT_0`, and do not use `STILL_ACTIVE` as the wait substitute.
9. Run the tests on the declared minimum supported Windows desktop version as well as the hosted Windows CI image.

The transport remains a prototype until these real Windows tests pass. Platform-neutral protocol tests and mocked Win32 calls are useful but are not evidence of DACL enforcement, process identity, overlapped cancellation, or kernel handle cleanup.
