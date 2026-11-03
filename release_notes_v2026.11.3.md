# AutoCommand III - v2026.11.3

Blocking now finishes the job: a firewall rule only stops NEW connections,
so this release offers to close the running instances whose established
flows the rule cannot touch - and the monitor line finally sees UDP, the
piece the fork left behind.

## What changed

- **Sever-on-block.** When you block a process or an IP from the monitor,
  the confirmation dialog now lists every running instance still holding
  connections (pid, flows, image path, kill tier) with an "also close"
  checkbox - unchecked by default. Ticking it creates the rules AND closes
  those instances tree-aware (children go with the host), so the block
  bites immediately instead of waiting for established flows to die on
  their own. Anything that respawns starts clean, inside the block. Kill
  tiers are policy, not prompt text: OS-critical processes (lsass,
  services, svchost, csrss...) are refused even with consent; Windows
  components (Defender, SearchHost, webviews) are only ever killed by the
  consent that listed them by name. A pid-reuse guard re-checks every
  image at kill time, a residual-flow verify loop reports what actually
  closed, and every sever lands as one line in blocks-events.log. The
  app's auto-block paths (Sysmon coverage, reconcile) never sever -
  killing is a human decision. Don't-ask prefs silence the block warning,
  never the kill decision: killable instances always surface.
- **`sever_blocked` on the AI bridge.** The same sever, behind the same
  per-call confirmation gate as `open_gate`: the user sees the exact
  instances before anything dies. `dry_run=true` previews them without
  acting; never-tier targets are refused by policy, not by prompt. And
  `list_blocks` rows now carry `live_instances` and `flows` - what a
  sever would close, straight from the kernel socket table.
- **UDP endpoints, at last.** The Engines.Watch kernel-table family was
  established-TCP only; UDP visibility lived entirely in Sysmon events.
  `UdpEndpointTable` enumerates every bound UDP endpoint (IPv4 AND IPv6,
  one syscall per family, race-checked) with owning pid, and
  `investigate_process` surfaces it as an `udp_endpoints` facet with the
  honesty label it deserves: bound is not transmitting - sends still
  belong to Sysmon EID 3 and trace captures.
- **Bridge: 411 rejections stopped RST-ing responses away.** A chunked
  POST's terminator bytes sat unread at close, flipping FIN to RST -
  intermittently costing the client the 411 body it was owed (caught as a
  flaky self-test crash, 2 failures in 3 runs). The 411 path now drains
  like its sibling rejections; 5/5 suite runs green after the fix.
- **ContainSelfTest pins the kill policy offline** - 12 new checks
  covering the tier matrix and the plan-decision table (never-tier with
  consent, ask-tier without, system pids), so the safety semantics cannot
  regress silently.

## Verification

Release + Debug builds clean; the full strict CI suite (8 projects) green
locally; sever consent flows and the UDP table verified live against the
running system (canary: ephemeral UDP port enumerated with correct pid,
both address families).
