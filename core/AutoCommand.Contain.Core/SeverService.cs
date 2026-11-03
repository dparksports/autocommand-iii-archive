using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// Kill policy tiers for sever-on-block. A fresh firewall block rule
    /// stops NEW connections only — Windows never severs established flows —
    /// so "block it" is only half the job while the target keeps live
    /// sockets. Closing the owning processes is the userspace lever that
    /// finishes it. The tiers decide WHO may be closed, so the feature can
    /// never take down the OS on the user's behalf:
    ///
    ///   never   — OS-critical (lsass, services, svchost, csrss, wininit…).
    ///             Refused even with explicit consent: killing these is not
    ///             a "block + sever", it is a bluesky. The block rule alone
    ///             still protects.
    ///   ask     — Windows components (Defender, SearchHost, webviews,
    ///             taskhostw…). Killable, but only behind the same explicit
    ///             per-action confirmation every mutating action carries;
    ///             they are listed BY NAME in whatever dialog asks.
    ///   allowed — everything else: killable with the standard consent.
    /// </summary>
    public static class ProcessKillPolicy
    {
        public const string Never = "never";
        public const string Ask = "ask";
        public const string Allowed = "allowed";

        /// <summary>Killing one of these destabilizes Windows itself. The
        /// block rule stays; only the kill is refused.</summary>
        public static readonly IReadOnlyCollection<string> NeverKill = new[]
        {
            "system", "registry", "memory compression", "memcompression", "smss", "csrss",
            "wininit", "winlogon", "services", "lsass", "svchost", "dwm", "audiodg", "fontdrvhost",
        };

        /// <summary>Windows components: blockable, killable only behind an
        /// explicit consent that listed them by name.</summary>
        public static readonly IReadOnlyCollection<string> AskFirst = new[]
        {
            "msmpeng", "mpcmdrun", "mpdefendercoreservice", "mssense", "smartscreen",
            "taskhostw", "searchhost", "startmenuexperiencehost", "systemsettings",
            "shellexperiencehost", "backgroundtaskhost", "backgroundtransferhost",
            "wermgr", "msedgewebview2", "msedge", "runtimebroker", "sihost",
        };

        /// <summary>Tier for one image name (".exe" suffix optional). An
        /// unreadable identity is treated as ask-tier: never assume a process
        /// the system cannot describe is safe to shoot.</summary>
        public static string TierFor(string exeName)
        {
            if (string.IsNullOrWhiteSpace(exeName)) return Ask;
            string n = exeName.Trim().ToLowerInvariant();
            if (n.EndsWith(".exe")) n = n[..^4];
            if (NeverKill.Contains(n)) return Never;
            if (AskFirst.Contains(n)) return Ask;
            return Allowed;
        }
    }

    /// <summary>One running instance a sever would consider closing.</summary>
    public sealed class SeverCandidate
    {
        public int Pid;
        public string Name = "";      // ProcessName (no .exe)
        public string ExePath = "";   // best-effort; "" when the path is inaccessible to us
        public string Tier;           // ProcessKillPolicy tier
        public int EstablishedFlows;  // live TCP flows attributed to this pid at plan time
        /// <summary>Why this candidate will NOT be killed — null when
        /// killable. Populated by SeverService.PlanDecision.</summary>
        public string SkipReason;
    }

    /// <summary>Outcome of one sever action, ready for a toast/event line.</summary>
    public sealed class SeverResult
    {
        public List<SeverCandidate> Considered = new();
        public List<SeverCandidate> Killed = new();
        public List<SeverCandidate> Skipped = new();
        public List<SeverCandidate> Failed = new();
        /// <summary>Live flows under the target AFTER the kill — the verify
        /// loop. 0 means the block now bites everything; nonzero means
        /// something respawned or survived (surface it, never hide it).</summary>
        public int ResidualFlows;
    }

    /// <summary>
    /// Sever-on-block: the closing half of a block. Enumeration is one
    /// TcpConnectionTable snapshot (same kernel table the monitor and the
    /// containment join read, so the three views cannot disagree); kills are
    /// tree-aware (Process.Kill(entireProcessTree)) because a blocked
    /// browser/webview host keeps its utility children — and a respawned
    /// child is harmless: fresh processes only make NEW connections, which
    /// the rule already blocks, so one kill at block time is a complete fix
    /// for the stale-flow class.
    ///
    /// Called ONLY from user-initiated surfaces (the Blocks/monitor block
    /// buttons and the confirmation-gated bridge tool). The app's auto-block
    /// paths (Sysmon-driven coverage, reconcile) never come through here —
    /// they must never kill.
    /// </summary>
    public static class SeverService
    {
        // ── pure plan decision (pinned by ContainSelfTest) ────────────────

        /// <summary>Returns why this candidate must NOT be killed, or null
        /// when it may be. Pure so the safety matrix is test-offline.</summary>
        public static string PlanDecision(string tier, int pid, bool allowAskTier)
        {
            if (pid <= 4) return "system process (pid ≤ 4)";
            if (tier == ProcessKillPolicy.Never)
                return "never-kill tier — OS-critical process, the block rule alone protects";
            if (tier == ProcessKillPolicy.Ask && !allowAskTier)
                return "ask-tier Windows component — needs explicit consent";
            return null;
        }

        // ── live snapshots ────────────────────────────────────────────────

        private static Dictionary<int, int> FlowCountsByPid()
        {
            var counts = new Dictionary<int, int>();
            foreach (var row in TcpConnectionTable.GetEstablished())
            {
                counts.TryGetValue(row.Pid, out int c);
                counts[row.Pid] = c + 1;
            }
            return counts;
        }

        /// <summary>Best-effort image path for a pid — protected/system
        /// processes deny MainModule to a non-elevated caller; "" then.</summary>
        private static string PathOf(Process p)
        {
            try { return p.MainModule?.FileName ?? ""; }
            catch { return ""; }
        }

        private static bool IsSelfOrHost(Process p)
        {
            try
            {
                if (p.Id == Process.GetCurrentProcess().Id) return true;
                return p.ProcessName.StartsWith("AutoCommand", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>Read-only map for the bridge's list_blocks rows: who is
        /// running (by exe stem) and how many established flows each pid /
        /// destination carries. One snapshot per call, not per row.</summary>
        public sealed class LiveMap
        {
            public Dictionary<string, List<int>> PidsByExeStem = new(StringComparer.OrdinalIgnoreCase);
            public Dictionary<int, int> FlowsByPid = new();
            public Dictionary<string, int> FlowsByIp = new(StringComparer.OrdinalIgnoreCase);

            public int InstancesForExe(string exeName)
            {
                if (string.IsNullOrWhiteSpace(exeName)) return 0;
                string stem = exeName.Trim();
                if (stem.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) stem = stem[..^4];
                return PidsByExeStem.TryGetValue(stem, out var pids) ? pids.Count : 0;
            }

            public int FlowsForExe(string exeName)
            {
                if (string.IsNullOrWhiteSpace(exeName)) return 0;
                string stem = exeName.Trim();
                if (stem.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) stem = stem[..^4];
                return PidsByExeStem.TryGetValue(stem, out var pids)
                    ? pids.Sum(pid => FlowsByPid.TryGetValue(pid, out int c) ? c : 0)
                    : 0;
            }
        }

        public static LiveMap TakeLiveMap()
        {
            var map = new LiveMap();
            foreach (var row in TcpConnectionTable.GetEstablished())
            {
                map.FlowsByPid.TryGetValue(row.Pid, out int c);
                map.FlowsByPid[row.Pid] = c + 1;
                map.FlowsByIp.TryGetValue(row.RemoteIp, out int i);
                map.FlowsByIp[row.RemoteIp] = i + 1;
            }
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4 || IsSelfOrHost(p)) continue;
                    string stem = p.ProcessName;
                    if (!map.PidsByExeStem.TryGetValue(stem, out var list))
                        map.PidsByExeStem[stem] = list = new List<int>();
                    list.Add(p.Id);
                }
                catch { /* exited between snapshot and read — skip */ }
                finally { try { p.Dispose(); } catch { } }
            }
            return map;
        }

        // ── plans (read-only) ─────────────────────────────────────────────

        /// <summary>Running instances of ONE exe name across its whole family
        /// (every path — the same semantics the family coverage and family
        /// unblock use: a name-block is a name-family block).</summary>
        public static List<SeverCandidate> PlanByName(string exeName, bool allowAskTier, LiveMap map = null)
        {
            if (string.IsNullOrWhiteSpace(exeName)) return new List<SeverCandidate>();
            string stem = exeName.Trim();
            if (stem.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) stem = stem[..^4];

            map ??= TakeLiveMap();
            if (!map.PidsByExeStem.TryGetValue(stem, out var pids)) return new List<SeverCandidate>();

            var plan = new List<SeverCandidate>();
            foreach (int pid in pids)
            {
                var c = Describe(pid, map.FlowsByPid);
                if (c == null) continue;
                c.SkipReason = PlanDecision(c.Tier, c.Pid, allowAskTier);
                plan.Add(c);
            }
            return plan;
        }

        /// <summary>Owners of established connections to ONE remote IP. The
        /// honest limit: UDP has no remote-address attribution on Windows, so
        /// QUIC flows are invisible here — they are cut by the kill itself or
        /// re-key inside the block.</summary>
        public static List<SeverCandidate> PlanByIp(string ip, bool allowAskTier, LiveMap map = null)
        {
            if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip, out var parsed))
                return new List<SeverCandidate>();
            string canonical = parsed.ToString();

            map ??= TakeLiveMap();
            var rows = TcpConnectionTable.GetEstablished()
                .Where(r => string.Equals(r.RemoteIp, canonical, StringComparison.OrdinalIgnoreCase))
                .ToList();
            var pids = rows.Select(r => r.Pid).Distinct().ToList();

            var plan = new List<SeverCandidate>();
            foreach (int pid in pids)
            {
                var c = Describe(pid, map.FlowsByPid);
                if (c == null) continue;
                // flows specific to THIS ip, not the pid's global count
                c.EstablishedFlows = rows.Count(r => r.Pid == pid);
                c.SkipReason = PlanDecision(c.Tier, c.Pid, allowAskTier);
                plan.Add(c);
            }
            return plan;
        }

        private static SeverCandidate Describe(int pid, Dictionary<int, int> flowsByPid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                var c = new SeverCandidate
                {
                    Pid = pid,
                    Name = p.ProcessName,
                    ExePath = PathOf(p),
                    EstablishedFlows = flowsByPid.TryGetValue(pid, out int f) ? f : 0,
                };
                c.Tier = ProcessKillPolicy.TierFor(c.Name);
                return c;
            }
            catch { return null; /* exited between snapshot and describe */ }
        }

        // ── execute (kill) + verify ───────────────────────────────────────

        /// <summary>
        /// Kills the killable candidates (SkipReason == null), tree-aware,
        /// then re-reads the socket table to report what still lives.
        /// Guards the plan→kill race: a pid reused by a different image
        /// between plan and kill is skipped, never shot blind. Writes one
        /// "severed" line to blocks-events.log via BlocksStore.
        /// </summary>
        public static SeverResult Execute(IEnumerable<SeverCandidate> candidates, string kind, string key, string origin)
        {
            var result = new SeverResult();
            var list = candidates?.Where(c => c != null).ToList() ?? new List<SeverCandidate>();
            result.Considered.AddRange(list);

            foreach (var c in list)
            {
                if (c.SkipReason != null) { result.Skipped.Add(c); continue; }
                try
                {
                    using var p = Process.GetProcessById(c.Pid);
                    if (!string.Equals(p.ProcessName, c.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        // pid reused between plan and kill — the original
                        // subject is gone (which severed its flows anyway)
                        c.SkipReason = $"pid reused by '{p.ProcessName}' since planning — not shot";
                        result.Skipped.Add(c);
                        continue;
                    }
                    p.Kill(entireProcessTree: true);   // children die with the host — no orphaned utility processes
                    result.Killed.Add(c);
                }
                catch (Exception ex)
                {
                    c.SkipReason = $"kill failed: {ex.Message}";
                    result.Failed.Add(c);
                }
            }

            // verify loop: fresh kernel read — did the killed/failed pids'
            // flows actually disappear? (Skipped pids were never ours to
            // close; their sockets were never part of the promise.)
            var after = FlowCountsByPid();
            var ours = result.Killed.Concat(result.Failed);
            if (kind == "ip" && IPAddress.TryParse(key, out var parsed))
            {
                string canonical = parsed.ToString();
                result.ResidualFlows = TcpConnectionTable.GetEstablished()
                    .Count(r => string.Equals(r.RemoteIp, canonical, StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                result.ResidualFlows = ours.Sum(c => after.TryGetValue(c.Pid, out int f) ? f : 0);
            }

            string detail =
                $"{result.Killed.Count} instance(s) killed tree-aware · " +
                $"{result.Skipped.Count} skipped · {result.Failed.Count} failed · " +
                $"residual flows {result.ResidualFlows}";
            try { BlocksStore.AppendEvent("severed", kind, key, detail, origin); } catch { }

            return result;
        }
    }
}
