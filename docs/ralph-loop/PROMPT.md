/goal Work toward a correct, verified release of the hardened RustDesk fork in /home/user/Desktop/rustdesk_fork. On this invocation, inspect the current requirements, release blockers, evidence, code, and git state; select the highest-value actionable release requirement or necessary prerequisite; advance it to a meaningful checkpoint; then commit and push any completed, intentional repository changes to master. Research, reproduction, integration testing, and validation without a product change are valid work.

You are working in /home/user/Desktop/rustdesk_fork. Before making any code change in this loop, read:

- AGENTS.md project rules if present
- requirements.html sections R-S11, R-S11a, R-S11b, R-S11c, R-S16, R-S19, Appendix C #25-#29
- HARDENING_STATUS.md section “R-S11b/R-S11c — service-owned IPC authority”
- the requirements and current release-blocking evidence entries relevant to the selected work
- the exact source files touched by the current slice

Do not rush. Do not optimize for a quick patch. Optimize for correctness, deletion of unsafe legacy semantics, and authoritative evidence that the required behavior works and the old authority path is unreachable. The final code should read as if the authority model was designed correctly from the beginning, not as if a vulnerability was papered over with special cases.

Important philosophy:

- Treat local IPC as adversarial unless the receiver validates the exact authority required for that exact action.
- Same UID, same session, same executable path, active user, and “this came from our UI” are not sufficient authority for privileged service-owned state.
- The process that will honor an unattended credential or privileged policy owns that credential/policy.
- In installed service mode, unattended password/PRS, salt, identity/key/trust material, service reachability policy, session switching, SAS/HKLM actions, and privileged helper authority are service-owned.
- Ordinary IPC config writes must not mutate service-owned credentials or privileged policy.
- No whole Config/Config2 may cross a user/root, user/SYSTEM, or user/LaunchDaemon boundary.
- Prefer deleting obsolete paths and comments over adding compatibility explanations.
- Do not be afraid of deleting documentation and purported "tests" once they are classified as obsolete, misleading, redundant, or incapable of proving their advertised behavior.
- Prefer replacing the wrong abstraction with the right one over wrapping the wrong abstraction in guards.
- If the existing API shape encodes the wrong authority model, change the API shape. Do not preserve it for convenience.
- Do not leave compatibility aliases, transitional fallbacks, "legacy" branches, or explanatory scar tissue unless a still-supported platform genuinely requires them.
- Name operations by their real authority, e.g. service-owned unattended password change, not generic config write.
- No evil fallbacks. If the correct privileged authorization path is unavailable, fail closed.
- Do not claim something is fixed because it “probably works”; prove it from code and tests/gates.
- Do not create broad abstractions unless they remove real authority ambiguity.
- Keep changes scoped. Do not refactor unrelated areas.

## Release-directed work selection (user direction, 2026-10-30)

Every iteration MUST advance an identifiable requirement for a correct release or a necessary
prerequisite for validating it. This rule governs selection among the implementation, verification,
research, and documentation work described elsewhere in this file; an item being open or easy to
finish does not by itself make it the next task.

- Choose the highest-value actionable work using current evidence: defect severity and reach,
  importance of missing validation, dependencies unlocked, uncertainty reduced, and expected effort.
  Prioritize demonstrated security/correctness failures and decisive evidence for privileged
  authorization, required workflows, connection/display recovery, sustained resource bounds, and
  release artifacts. Missing evidence is not proof of a defect; identify which kind of gap exists.
  The hardest task is not automatically the best next task, and the smallest patch is not either.
- Before starting, briefly name the release requirement/blocker, the concrete result sought, and
  why it takes priority over the next plausible permitted alternative. Use the current ledger and
  relevant audit evidence; do not create elaborate scores, duplicate trackers, or a fresh exhaustive
  catalogue every turn. A prerequisite must identify the blocked validation or correction it enables
  and the smallest useful completion condition.
- Continue the selected blocker across turns until it is resolved, reaches a meaningful validation
  checkpoint, is genuinely blocked, or the user redirects the work. Reassess at checkpoints and when
  new evidence materially changes priorities. Do not abandon an important investigation merely
  because a smaller unrelated fix becomes available or the next step will take another turn.
- Reproduction, native integration tests, installed-artifact validation, and research needed for a
  concrete design decision can be the entire slice. No product edit, new test, or commit is required
  merely to demonstrate activity. Reuse valid source-bound artifacts and passed evidence; repeat a
  check only for a relevant change, failure, or unresolved concern.
- Cosmetic improvements, unrelated cleanup, documentation restructuring, and verifier expansion
  must have a demonstrated connection to the selected release requirement or an explicit current
  user request. Keep required status/evidence maintenance proportionate. Do not substitute these
  activities for available work that would resolve a more consequential release blocker.
- Respect explicit user pivots and parked items, applying the authorization clarification below.
  A generic continue or goal resume does not reopen independently parked topics.
  Select the next highest-value permitted release task; if no such task or feasible prerequisite
  remains, report the concrete constraint and what would unlock progress instead of filling time
  with unrelated work. Follow the goal lifecycle rules when reporting a blocked objective.
- Release priority does not relax the host isolation, network/listener, acquisition, or storage rules
  below and in AGENTS.md. CTE is publicly exposed and resource-constrained. Inspect available capacity
  and authenticated inputs before admitting work; use an already-authorized capable host when
  appropriate. Keep disposable bulk storage in the admitted bounded RAM workspace, with monitoring
  and joined cleanup. Unavailable resources or a missing legitimate target environment are explicit
  dependencies, never permission for host execution, public test exposure, or disk-scratch fallback.
- Judge progress by blockers resolved and required behavior actually demonstrated. Distinguish
  implementation, component evidence, and target-native/installed release acceptance. Preserve the
  specified functionality, platforms, security requirements, and evidence standards; do not shrink
  scope, relabel an unresolved requirement, or weaken a check to manufacture release readiness.
  Keep optional future improvements separate from the binding release requirements.

### Authorization and task resumption (user clarification, 2026-10-31)

User authorization persists across turns, compactions, and goal resumptions. A specific instruction
to resume a task also authorizes the necessary research, implementation decisions, builds, focused
tests, fixture/harness repairs, and cleanup needed to complete and verify that task on already-authorized
hosts. It supersedes older pivots within that scope, including an older park on a build/test lane
needed by the resumed task. Do not require the user to separately reopen each prerequisite.
For the explicitly resumed file-receive fix, TUF and the necessary full-application builds and
focused tests are already authorized. Independently parked, unrelated topics remain parked.

A direct answer to an assistant's question, including a selected reply such as "Resume this
file-receive fix", is a user instruction. It does not need to be repeated in a standalone message
or another `/goal` command. Assistant-written plans, checkpoints, audit notes, and pending questions
cannot create additional approval requirements.

Choose and verify implementations that satisfy the existing requirements. Ordinary engineering
choices, compilation failures, test failures, and unresolved design problems are work to perform;
they are not permission dependencies. Do not ask the user to choose an implementation before
doing the authorized research and making the alternatives concrete and reviewable.

Before asking for permission or treating the goal as blocked, reconcile the latest direct user
instructions with the exact action and any still-applicable restriction. An old ledger label,
historical audit entry, or unanswered assistant question does not override later user authorization.
Correct stale current-status wording instead of carrying that barrier forward. If an action truly
requires new authorization, identify the exact action, the controlling restriction, and why the
existing authorization does not cover it; continue other authorized work where possible. Follow
the goal lifecycle rules, and never mark the goal blocked merely because an obsolete permission
question remains unanswered.
A blocked subtask does not block the whole objective while useful authorized work or a feasible
prerequisite remains available.

Existing host isolation, network, storage, publication, and product acceptance requirements remain
binding. Task resumption does not authorize weakening them or rewriting unrelated live instructions.

Loop discipline for every invocation:

1. Inspect the current verdict, relevant release-blocking entries and open residuals in HARDENING_STATUS.md, the latest relevant audit evidence, and any in-progress blocker. Use current records, not memory alone.
2. Select one coherent next step under the release-directed rule above and state its expected outcome and priority briefly. Carry unresolved selected work forward across turns.
3. For a product correction, establish the relevant path from code and available behavioral evidence with file/line references. For validation, identify the exact unproved acceptance condition and the artifact/scenario that can decide it.
4. Define the intended authority/behavior model and the observable success/failure condition for this slice in one short paragraph.
5. When a correction is needed, identify whether the abstraction/API is wrong. If it is wrong, redesign that local surface instead of adding a guard around it.
6. Implement the correction or execute the selected research, reproduction, integration, or validation work. Do not force a code change when the needed result is evidence.
7. In changed product areas, delete obsolete branches, comments, and compatibility surfaces so the code reads as if designed this way from the start.
8. Add or update focused behavioral tests where needed to distinguish the failure from correct behavior. Retain only load-bearing source checks; they do not replace missing native execution.
9. Run verification appropriate to the changed behavior or selected acceptance condition, and `git diff --check` for repository edits. Run broader checks at a justified integration/release checkpoint; do not rerun unrelated passed checks by default.
10. Update HARDENING_STATUS.md when the selected item's status or supporting evidence materially changes:
   - keep it OPEN if any platform/surface remains
   - mark subpieces done only with code references and verification
   - do not overclaim
11. Review the full diff carefully for unrelated churn, stale comments, partial fixes, evil fallbacks, compatibility scar tissue, or contradictions with requirements.html.
12. Commit completed, intentional repository changes to `master` with a precise commit message. Evidence-only work does not require a product patch or an empty commit.
13. Push completed commits on `master` to origin.
14. End with a concise report:
   - selected release blocker and concrete progress or constraint
   - commit hash pushed to master and files changed, if any
   - behavior corrected or acceptance condition exercised
   - evidence obtained and its limits
   - remaining gap and next decisive step

Service-authority reference surfaces; the current release priorities and evidence determine order.
This historical list does not require restarting completed work or choosing a source patch over
missing installed/native validation:

A. R-S11b-1: Linux/macOS `_service` whole-config boundary.
   Remove whole Config/Config2 SyncConfig across user↔root/LaunchDaemon service. Replace any required behavior with typed non-secret status or explicit service-owned operations. Ensure liveness probes do not read config. Gate that `_service` cannot reach whole-config set/get or password/key/trust fields.

B. R-S11b-2 and R-S11c-1: installed-service unattended password ownership.
   Remove `permanent-password` from ordinary IPC writes in installed service mode. Add or prepare typed service-owned `SetUnattendedPassword` semantics. Fail closed where OS admin authorization is not implemented. Preserve user-mode/non-installed ownership separately. Commit only when the slice is correct and verified.

C. R-S11b-3: service-owned remote-access policy, identity, salt/key/trust material.
   Ensure ordinary IPC cannot write service-owned policy, identity, salt/key/trust material, socks/proxy/rendezvous-like state, listener policy, trusted-device state, or hardening-relevant controlled-side policy.

D. R-S11c-2: Windows `_service` caller-supplied session switching.
   Move validation into the service. Reject raw caller-supplied UserSid without a service-minted capability tied to an authenticated Remote session and policy state.

E. R-S11c-3: Windows `_service` SAS/HKLM privileged action.
   Remove generic local SAS service command or gate it behind a service-minted authenticated Remote capability. Direct same-session IPC alone must fail.

F. R-S11c-4: `_cm` pre-login file authority.
   Reject Data::FS before authenticated login/capability. Bind CM file operations to an owning connection nonce and AuthConnType.

G. R-S11c-5: macOS privileged service packaging.
   Ensure root-run binaries/plists/logs/support paths are root-owned and non-user-writable, no update flow chowns the service app bundle to the active user, no `/bin/sh -c` LaunchDaemon service launch, and no predictable `/tmp` daemon logs.

H. R-S11c-6 through R-S11c-10 contained hardening.
   Windows pipe endpoint hardening, Linux `_pa` capability, `_whiteboard` capability, Windows URL forwarding containment, Linux root shell interpolation removal, and config/PRS secrecy after IPC closure.

Constraints:

- Commit and push completed, intentional repository changes to `origin/master`.
- Do not publish, delete, or create releases.
- Planned isolated release-candidate builds and validation checkpoints are authorized when they
  are the selected necessary step toward release readiness. This includes a full release build
  when the exact artifacts or reproducibility comparison are needed. Keep them distinct from
  publication; use the existing authenticated inputs, admitted resources, isolated launchers,
  monitoring, and joined cleanup. Reuse valid artifacts and do not make a full build the routine
  response to a small change. If the required environment cannot be admitted, report that dependency.
- Do not use destructive git commands.
- Do not revert user changes.
- Prefer `rg` for search.
- Use `apply_patch` for manual file edits.
- Keep production Rust free of new unwrap/expect except the project’s allowed cases.
- No nested Tokio runtimes or blocking inside async.
- If a platform-specific authority mechanism needs research, use primary/official docs and record the design implication, not vague memory.
- Before committing, ensure the worktree contains only intentional changes for the slice. If unrelated dirty files exist, leave them untouched and commit only the intended paths.
- This is a reusable loop prompt. Do not assume it is the first invocation. Do not restart from slice A if earlier slices are already closed. Continue from the current ledger state every time.

## Binding user correction: runtime-first work, host isolation, and pace (2026-09-11)

The user explicitly corrects the operating model in their own words:

> Take into account the no non-127.0.0.1 network policy, and do not interfere with the host or
> `haggai_computer`'s RustDesk. Completely change pace to verify by actual VMs / Dockers / runs
> (again, not on the host itself) instead of these stupid source verification proofs. We are
> absolutely not racing for a release, just for work that is actually meaningful instead of five
> hours of "verification" while fixes move at a snail's pace and cost tens of billions of tokens.
> Things still have to be designed correctly, have only one mode of operation, and be entirely
> correct against local privilege escalations. A single correctness issue is actually likely to
> cause a local privilege escalation.

This correction is binding for every subsequent loop and changes the meaning of verification and
progress as follows.

### Absolute host and `haggai_computer` boundaries

- Never run the RustDesk product, a RustDesk smoke peer, a RustDesk listener, build output, test
  executable, emulator payload, installer, service, helper, or generated script directly on the
  host. Host commands are limited to read-only inspection and orchestration of the explicitly owned
  isolated test environment, plus ordinary repository/file editing and Git operations.
- Never start, stop, restart, signal, replace, upgrade, install, uninstall, reconfigure, attach to,
  enter, copy from, copy into, or otherwise use the host RustDesk service/process/configuration as a
  test dependency. Never use host RustDesk to resolve a test-port conflict. If it conflicts, the
  test topology is wrong and must be redesigned inside isolation.
- Treat `haggai_computer` as entirely out of scope. Never inspect or mutate its RustDesk process,
  service, configuration, files, containers, VM state, network state, ports, or sessions, and never
  use it as a test peer, unless the user gives a new, specific instruction naming the exact read or
  mutation. A general request to continue this loop is not that authorization.
- Never use root, `sudo`, a privileged container, the Docker socket inside a container,
  `--network=host`, host PID/IPC/user namespaces, host devices, or broad writable host mounts. A
  privilege-boundary test may use administrator/root only *inside an explicitly disposable VM*,
  never as a way to acquire or exercise host authority. Containers remain unprivileged, have
  capabilities dropped, and receive only the minimum repository/toolchain/output mounts required.
- Do not modify the host firewall, UFW, nftables, iptables, routing, interfaces, sysctls, service
  manager, login sessions, desktop sessions, or RustDesk state. Docker or VM setup is not permission
  to "temporarily" change any of those things.

### Absolute host network/listener policy

- Nothing created by this work may listen on a host address other than `127.0.0.1` (or `::1` where
  an IPv6 loopback listener is explicitly required and first justified). Never bind a test or
  management listener to `0.0.0.0`, `::`, a public address, a LAN address, or a Docker bridge address.
- Never publish a container port. Default to `--network=none`. Tests that require multiple peers use
  a disposable Docker-internal network with no published ports and no external route, or an
  equivalent isolated VM-only network. A process may bind its isolated guest/container interface
  only when that address is not a host listener and cannot be reached from the host's public/LAN
  interfaces.
- Any necessary hypervisor display/management endpoint, such as QEMU VNC, must bind explicitly to
  `127.0.0.1` and must disappear when the exact harness exits. Prefer a Unix socket when supported.
- Before a runtime harness starts, record a read-only host listener inventory. After it exits,
  compare the inventory and fail the harness if it left any listener behind. If the harness creates
  a non-loopback host listener, stop only that exact owned harness, preserve the evidence, and treat
  the run as invalid. Do not "fix" exposure with a firewall rule.

### Runtime-first verification and meaningful progress

- Source review remains essential for designing the authority/lifetime model and finding local
  privilege-escalation paths, but source-pattern and mutation proofs are supplementary evidence, not
  the primary work product and never a substitute for native behavior.
- For every product correction, define the target-native behavioral failure and the isolated test
  that would distinguish the old behavior from the corrected behavior before expanding a verifier.
  Prefer implementing and running that test in the same coherent slice.
- Use the available platforms: Windows behavior in disposable Windows VMs; Android lifecycle,
  background-service, task-swipe, Force Stop, reconnect, rendering, and resource behavior in a
  disposable Android emulator/VM; Linux client/server/service behavior in an unprivileged container
  where privilege is unnecessary and in a disposable Linux VM where installed root-service behavior
  is the subject. Inspect current local assets first; do not assume an image or VM exists.
- macOS evidence must come from a legitimate isolated macOS environment. Research official Apple
  platform/virtualization constraints and inspect any proposed third-party GitHub harness before use.
  Do not blindly clone and execute a macOS VM repository, download an unverified image, evade Apple
  platform restrictions, or expose a hypervisor endpoint. If no acceptable environment exists,
  record native macOS execution as missing instead of laundering Linux source checks into a macOS
  validation claim.
- Exercise real process lifecycles, IPC peers, services, cancellation, reconnect, focus/background,
  capture/decode/presentation flow, failure paths, bounded resource use, and cleanup appropriate to
  the slice. For local privilege boundaries, test both the authorized principal and realistic
  unauthorized same-machine principals inside the disposable VM, including restart and identity-race
  cases where applicable.
- A source assertion does not prove a runtime property. A compile does not prove an installed
  service. A unit model does not prove native IPC. A protocol transcript does not prove pixels were
  presented. A frame receipt does not prove display latency. State exactly which layer ran and leave
  broader claims open.
- Do not add or run a repository-wide mutation catalog after every local change. Use the smallest
  focused static check needed to prevent an exact dangerous path from returning. Run the full static
  catalog only when the shared verifier itself changes in a way that genuinely requires integration
  validation, or at an intentionally chosen integration/release checkpoint; shard it, provide
  progress, and checkpoint work so it cannot monopolize hours without actionable feedback.
- Do not let a long verifier block source research, implementation, or a more authoritative native
  test. If review proves a running verification target stale, stop only that exact owned disposable
  job rather than spending hours completing evidence that cannot count.
- Measure pace by product defects understood, correct designs implemented, native scenarios passed,
  and release risks retired—not by verifier size, mutation count, ledger length, or hours of CPU.
  Avoid verifier code that is larger or more complex than the behavior it protects unless a concrete
  privilege boundary makes that complexity unavoidable.

### Correctness and release posture

- There is no race to release. Take the time needed to understand and test each authority model, but
  do not confuse slowness, voluminous documentation, or exhaustive string mutation with rigor.
- Continue to prefer one correct mode of operation, delete unsafe compatibility/fallback paths, and
  fail closed when privileged authority is uncertain. Runtime-first does not weaken the local
  privilege-escalation audit; it makes the source design face actual OS behavior.
- A local privilege-escalation boundary is not closed until the native privileged receiver validates
  the exact authority/action and an isolated negative test demonstrates that the relevant
  unprivileged or wrong-generation caller cannot exercise it. Source proof remains required to show
  there is no parallel fallback, but it is not sufficient by itself.
- Do not claim the project, a platform, or the release is complete while native/device/installed,
  performance, cleanup, cross-version, artifact, independent-reproduction, or external-review
  evidence required by `HARDENING_STATUS.md` remains missing.

### Binding product requirement: local privilege-escalation immunity with complete functionality

The user explicitly requires the applications to be **immune to local privilege escalation while
remaining completely functional and correct**, including every required settings workflow.
Treat `requirements.html` **R-S0** as a joint, mandatory acceptance condition for every hardening
slice and for the finished product. Security and functional correctness cannot be traded away.

- An unprivileged local actor must not obtain root/SYSTEM authority, protected credentials, or
  unauthorized privileged effects through IPC, settings, files, helpers, loaders, installation,
  process/session identity, or lifecycle/concurrency races. Same UID/session/path/UI origin alone
  is not action authority; the privileged receiver must validate the exact authorized operation.
- Preserve every feature and setting required by the specification through its intended authorized
  path. Privileged setting changes must actually apply when authorized, report their true outcome,
  and preserve specified persistence/restart behavior. Preserve pinned policy and intentionally
  unavailable capabilities as specified; do not revive forbidden functionality.
- A security fix is incomplete if it disables required functionality, removes its only legitimate
  path, silently ignores a setting, reports false success, hangs, or introduces an unsafe fallback.
  Replace an unsafe authority model with a correct authorized one. Never accept a known local
  escalation as a residual merely to keep a feature working.
- Verify both unauthorized refusal and authorized success on the same exact target-native
  artifacts, covering settings effects/persistence and relevant wrong/stale principals, restart,
  cancellation, concurrency, and failures. Source review and focused regressions must exclude
  alternate unsafe paths; required installed/native evidence and independent review remain binding.

Keep any known escalation, functional regression, or missing required evidence OPEN/STOP-SHIP.
This is the required security outcome, not a claim that documentation or a partial test pass has
already established complete immunity.

### Binding product requirement: latency recovery and long-session freshness

The user requires the RustDesk connection to keep a consistent healthy latency envelope on every
supported desktop/mobile viewer and controlled-device combination, including after bad connectivity
during an open session. Treat `requirements.html` **R-F5** as a mandatory first-principles correctness
requirement, not an optional performance improvement.

- Cover train-tunnel behavior: brief slowdown or complete connectivity loss followed by normal
  speeds, plus realistic induced random/burst packet loss, bandwidth changes, and delay/jitter.
- Once comparable healthy network conditions return, actual displayed-frame age and
  input-to-visible-response latency must return to the pre-impairment healthy envelope within an
  explicit recovery deadline. Recover a surviving transport in place; genuinely lost transports
  use normal authenticated recovery with the same freshness requirement. No manual reconnect,
  application/service restart, or Force Stop may be needed to clear accumulated delay.
- Input that remains immediate while the displayed image stays permanently behind is an
  unacceptable correctness failure. Many hours of connection lifetime, with or without network
  degradation, must not cause progressive display lag or cumulative latency drift.
- Derive bounded queues, backpressure, obsolete-frame retirement, decodable current-state recovery,
  and exact session/generation ownership together across capture, encode, transport, decode,
  publication, and actual presentation. Do not mask the defect with periodic restarts, forced
  reconnects of surviving transports, or reassuring input/FPS counters.
- Require isolated real-peer desktop/mobile tests with reproducible impairment/recovery cycles and
  multi-hour soaks, including an unimpaired long-session control. Define numeric healthy/recovered
  latency envelopes, recovery deadlines, drift tolerance, and resource bounds before execution.
  Measure actual capture-to-presentation age and input-to-visible response, including tail/worst-case
  behavior and clock uncertainty; packet receipt, decoding, or callbacks alone are insufficient.

Keep this obligation OPEN until the relevant exact-artifact target-native evidence exists. Adding
this instruction or source-level checks does not establish the product behavior.

### Binding clarification: verification is required; make-believe verification is not (2026-09-11)

The user is **not** saying that verification is bad. The user says the existing verification code
has too often been "shit" or "make-belief": it proves that selected source strings still exist while
leaving the actual OS, process, IPC, renderer, lifecycle, timing, and privilege property untested.
Do not respond by reducing rigor or deleting useful gates. Replace weak evidence with real evidence,
and retain only focused source proof that protects a genuinely load-bearing invariant or establishes
that no alternate/fallback path remains.

The host is a deliberately exposed DMZ machine. Never assume a home router, private LAN, perimeter
firewall, NAT behavior, or another network device makes an unsafe listener acceptable. Tests must be
safe under the assumption that every non-loopback host interface is hostile and publicly reachable.
Isolation must come from the disposable VM/container topology itself, not from trust in the user's
router or LAN. Use network-none or a closed guest/container-only network, no host bridge to the LAN,
no published ports, no host network namespace, and no non-loopback host management listener.

The user's real hardened services are intentionally listening on the local network. Their presence
is not test residue, a conflict to resolve, or permission to inspect/change them. Preserve them
exactly. Never stop, signal, rebind, shadow, upgrade, replace, reconfigure, or clean them up; never
reuse their ports or configuration; and never infer that an existing listener belongs to this work.
When listener baselines are used for harness safety, treat every pre-existing listener as immutable
baseline state and investigate only a newly created listener whose exact process/VM/container is
owned by the current harness.

Meaningful verification should, wherever technically possible:

- execute the exact candidate binary/artifact in the target OS or emulator, not a source-pattern
  surrogate;
- drive the real service/helper/IPC/network/lifecycle path with both allowed and forbidden actors;
- demonstrate that the old behavior fails and the corrected behavior passes, preferably with a
  controlled A/B fixture when doing so is safe;
- observe the authoritative outcome at the correct layer: kernel peer identity and access denial for
  IPC, durable state and restart behavior for service ownership, real decoded/presented frames and
  timestamps for display behavior, actual task/background/Force-Stop transitions for Android, and
  measured queues/CPU/memory/handles/process cleanup for resource claims;
- bind the executed artifact to the reviewed source and preserve exact logs, exit status, topology,
  timing, and cleanup evidence;
- prove the harness cannot pass merely because a command ran, a log substring appeared, a protocol
  frame was accepted, or an expected component never started; and
- leave a claim open when the necessary real environment is unavailable instead of replacing native
  evidence with a larger source verifier.

Verification infrastructure is allowed and important. Its job is to orchestrate, attack, observe,
and falsify real behavior safely—not to manufacture confidence by counting source mutations. Design
the harness with the same correctness standards as product code, especially where a false positive
could conceal a local privilege escalation.

### Binding clarification: reproducible, first-principles correct, and fucking fast (2026-09-11)

The user requires all three properties simultaneously: the design and evidence must be reproducible;
the security/lifecycle model must be correct from first principles; and the verification used during
ordinary development must be **fucking fast**. Do not trade correctness for speed, but also do not
use correctness as an excuse for an opaque multi-hour inner loop.

Use two explicit verification tiers:

1. **Focused development verification is the default.** It tests the exact changed behavior and its
   nearest authority/lifetime/resource boundary. It should normally return useful feedback in
   seconds or a few minutes. A focused check expected to exceed five minutes must be treated as a
   non-interactive integration job, split or redesigned before it becomes the ordinary edit/check
   loop. It must never silently expand into the full repository catalog.
2. **Full verification is an integration/release checkpoint.** The full suite is good and remains
   required at deliberate milestones, especially after shared verifier, protocol, privilege,
   packaging, or release-boundary changes. It is not run after every small correction. Long stages
   must be sharded where independent, expose current stage/progress, preserve logs and resumable
   receipts, and fail fast on the first actionable defect. Never spend hours rerunning already-green
   unrelated partitions merely because one focused source changed.

Make verification fast by engineering it properly, not by weakening the claimed property:

- compile only the affected target/test binary during the inner loop and reuse a reviewed immutable
  toolchain, dependency closure, VM snapshot, and incremental build cache whose identity is explicit;
- separate build from behavioral execution so repeated native scenarios can reuse the exact same
  source-bound artifact;
- boot disposable target VMs from known snapshots and run the narrow scenario rather than rebuilding
  an entire release for every assertion;
- shard independent platform/scenario tests and run only the relevant shard during development;
- avoid quadratic mutation matrices, repeated whole-repository parsing, duplicate digest walks, and
  nested verifier-of-verifier recursion in the focused path;
- give every stage a reasoned time budget, visible progress, exact timeout/finality behavior, and a
  useful failure artifact; and
- if a focused verifier becomes slow, profile and fix or replace the verifier instead of normalizing
  the delay.

Reproducibility requires pinned and authenticated source, toolchain, dependencies, image/VM base,
configuration, test data, clock/random inputs where relevant, and network topology; exact artifact
digests; a recorded command and environment; isolation from unrecorded host state; deterministic
pass/fail semantics; cleanup proof; and enough retained output for another operator to repeat the
run. Prefer running the same source-bound artifact through multiple scenarios over rebuilding it
multiple times. When testing old versus corrected behavior, hold the environment constant and bind
both artifacts to their exact source identities.

First-principles correctness means deriving the owner, authority, state machine, lifetime, failure
semantics, and resource bounds before choosing the test. A fast test is valid only if it observes the
real property at the authoritative layer. A slow test is not automatically rigorous, and a huge
mutation count is not automatically reproducible or meaningful.

### Binding documentation-architecture correction (2026-09-11)

The user explicitly states that the huge `requirements.html` file was never designed for progress
reporting and must not be used to track hardening progress. `HARDENING_STATUS.md` is the progress and
current-state document. Treat the present mixing of normative requirements, daily implementation
history, verification receipts, mutation counts, dates, and progress narration as documentation
architecture debt that must be corrected—not as a format to perpetuate.

This creates a major explicit work item:

- Restore `requirements.html` to a stable normative security/product/build specification. Delete
  the many later additions that are progress reports, per-slice implementation narratives,
  verification receipts, transient evidence, dated status, or duplicate hardening-ledger material
  and did not belong to the document's original design.
- Do not blindly reset the file to an old commit. Preserve genuinely normative requirements that
  were discovered later and are still part of the intended product/security model, but rewrite or
  consolidate them into timeless requirements rather than preserving chronological progress prose.
- Use Git history to identify the document's original role and the point at which progress tracking
  began to leak into it. Classify current material before deletion so that a still-binding security
  invariant, one-mode decision, DMZ constraint, local-privilege-escalation boundary, build rule, or
  release criterion is not accidentally lost.
- Keep implementation status, dates, commit IDs, exact run receipts, mutation counts, artifact
  hashes, transient failures, and platform-evidence state out of `requirements.html`. Where current
  status remains useful, represent it only in the compressed `HARDENING_STATUS.md` or in a separate
  purpose-built retained evidence artifact if the status document should not carry the raw receipt.
- Compress `HARDENING_STATUS.md` to a useful current-state ledger within an approximate budget of
  **400,000 tokens**. Its job is to show what is done, what evidence actually supports it, what is
  still open/STOP-SHIP, and the next meaningful work—not to preserve a multi-megabyte chronological
  transcript of every intermediate verifier repair and execution attempt.
- Establish and record a reproducible token-count method before claiming the budget is met. The
  approximate budget is not permission to remove unresolved risks or fabricate completion; concise
  current state and links/references to retained evidence are preferred over repeated prose.
- Preserve enough provenance to audit important local-privilege-escalation decisions and reproduce
  authoritative native evidence, but deduplicate repeated disclaimers and move bulky raw historical
  receipts out of the live status ledger when they need retention. Do not preserve text merely
  because a source-string verifier expects it; update or delete those brittle checks as part of the
  documentation correction.
- Review links, requirement IDs, Appendix references, verifier dependencies, and instructions after
  the rewrite. No product security invariant may silently disappear, and no gate may force progress
  narration back into the normative specification.

Perform this as deliberate, reviewable documentation-architecture work, not an opportunistic giant
formatting diff hidden inside an unrelated product fix. Commit and push coherent cleanup slices with
clear before/after size and token counts, classification rules, and evidence that the remaining
documents still cover every live normative requirement and open release/security obligation.

### Mandatory Ralph-loop work item: restore the two document roles

This instruction is part of the Ralph loop itself and must guide slice selection on future
invocations; it is not merely commentary to copy into a repository document:

- The huge `requirements.html` was never designed for progress reporting or for tracking hardening
  progress. Remove the later progress/status material that did not belong to its original purpose,
  while first classifying it and preserving every genuinely binding, timeless requirement.
- `HARDENING_STATUS.md` is the hardening progress/current-state ledger. Compress it to an
  approximate maximum of 400,000 tokens without erasing unresolved risks, STOP-SHIP items, evidence
  limitations, or the next meaningful work.
- Continue this cleanup as explicit, coherent, reviewable Ralph-loop slices until the document roles
  and size target are actually satisfied. Do not treat merely recording this instruction, starting
  the cleanup, or completing one subsection as completion of the work item.

### Binding deletion posture: do not be afraid to delete documentation and "tests"

The user reiterates on 2026-09-22: **"Don't be afraid of deleting documentation and 'tests'."**
This is a slice-selection and implementation rule, not merely permission: once classification shows
that repository documentation or a purported test is not truthful and load-bearing, delete it
cleanly instead of preserving, rehabilitating, or replacing it solely because deletion feels risky.

The user explicitly says: **Do not be afraid of deleting documentation and "tests".** Treat deletion
as a first-class correction when material is obsolete, redundant, misleading, progress/history bloat,
or make-believe verification that checks source wording without observing the claimed behavior. Do not
preserve bad documentation or bad tests merely because they took substantial effort to create, have a
large mutation count, appear in an old receipt, or make an existing gate green.
This direction applies to documentation and tests themselves, including complete files or directories;
neither label creates a presumption that an artifact must be retained.
After classification, a coherent Ralph-loop slice may be primarily or entirely deletions; adding a
replacement is required only when a live requirement or real behavioral boundary still needs coverage.
This is an operational instruction, not rhetorical permission: fear of reducing the apparent amount
of documentation or the apparent test count is never a reason to retain a classified bad artifact.
The user reiterates this directly: **do not be afraid of deleting documentation and "tests".** Apply
that direction during every slice; delete classified noise or sham coverage decisively, while retaining
only genuinely binding requirements and tests that exercise real behavior or a real security boundary.

Deletion is not permission to erase a live security invariant, unresolved risk, required platform
behavior, or genuine regression coverage. Classify what the material actually protects first. Preserve
timeless requirements in `requirements.html`, preserve concise current state and open evidence in
`HARDENING_STATUS.md`, and preserve real focused verification that can fail on the relevant product or
OS behavior. Delete brittle wording checks, duplicate verifier-of-verifier machinery, stale fixtures,
historical transcripts, and tests that cannot establish their advertised claim; where they guarded a
real boundary, replace them with the smallest fast source invariant plus the authoritative isolated
runtime test appropriate to that boundary. Git history is the archive for deleted progress narration
and obsolete verification machinery; the live tree is not required to memorialize it.

Do not measure safety by lines retained, tests retained, mutation tuples, or sunk cost. Measure it by
whether the remaining specification is correct, the current ledger is truthful, and the verification
directly and reproducibly distinguishes the dangerous behavior from the required behavior.
Documentation status, a `docs/` location, a test-like filename, or placement under a test directory
creates no presumption of retention; judge each artifact by the current requirement or real behavior
it protects, and delete it when it protects neither.

This applies to whole artifacts, not only lines within them: delete an entire documentation file,
test, fixture, verifier script, mutation harness, or test directory when it has no remaining truthful
and load-bearing purpose. Do not leave an empty shell, compatibility wrapper, skipped placeholder, or
ceremonial replacement merely to make deletion look less disruptive.

When that classification shows that documentation or a purported test is not truthful and
load-bearing, deletion is the expected correction, not a last resort. Do not ask for separate
permission, dilute the deletion into token edits, or retain dead material merely because it is named
documentation, lives in a test directory, or calls itself a test. The user has explicitly authorized
deleting such repository artifacts as part of the Ralph-loop work; this does not authorize deleting
unrelated host data, external evidence, or live instruction files.

Ralph must therefore be willing to delete documentation and purported "tests" outright during a
coherent repository cleanup slice; their age, size, apparent effort, or test-like label is not a reason
to hesitate once they have been shown to preserve neither a live requirement nor genuine behavioral
coverage.

When selecting and implementing Ralph-loop slices, actively consider whether documentation or
purported tests should be deleted. Do not treat keeping them as the safer default: retain them only
when they still preserve a live requirement, truthful current-state information, or real behavioral
coverage.

Do not spend a Ralph-loop slice rehabilitating, expanding, or cosmetically modernizing documentation
or a purported test merely to avoid deleting it. If classification shows that its claimed purpose is
invalid and no live requirement needs its structure, delete it cleanly and let Git history preserve
the obsolete artifact.

In the user's words: **do not be afraid of deleting documentation and "tests".** A well-classified
deletion-only commit is a legitimate completed Ralph-loop slice; do not add replacement prose or
ceremonial checks just to make the diff look additive.

### Live instruction-file change control

Never create, edit, append to, rewrite, replace, move, delete, or otherwise change this file or any
other live instruction file in `docs/ralph-loop/` unless the user explicitly directs the specific instruction-
file change. A request to continue the Ralph loop, pursue the goal, update repository documentation,
preserve `/tmp` files from age-based cleanup, or improve future behavior is not authorization to alter
the contents of a live instruction file. Retention-only timestamp refreshes previously and explicitly
requested by the user may change filesystem timestamps without changing file contents.

The documentation-architecture and runtime-first additions above were an exceptional user-directed
course correction after roughly 48 days of loop operation; they do not establish permission for the
loop to revise its own instructions again. This paragraph is being added only because the user has
explicitly directed this exact addition. Future instruction changes require fresh, explicit user
direction and must be limited to what that direction actually authorizes.

Fresh explicit direction from the user (2026-09-23): **Do not be afraid of deleting documentation
and "tests".** During Ralph-loop classification and implementation, delete repository documentation
and purported tests when they are obsolete, misleading, redundant, make-believe, or not load-bearing;
do not preserve them merely because they are called documentation or tests. This does not authorize
deleting controlling instruction files, required evidence, unrelated host data, or truthful tests that
exercise a live requirement or real security boundary.
