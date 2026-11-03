// F# port of the systemmonitor ancestor's UDP endpoint enumeration
// (DeviceMonitorCS ConnectionMonitor.GetUdpConnections) into the
// Engines.Watch kernel-table family, next to TcpConnectionTable — the
// piece the autoscope→ii→iii fork left behind (the ancestor enumerates
// UDP endpoints with owning pids; this line's tables were TCP-only until
// now, with UDP visibility delegated to Sysmon EID 3 events and
// trace_analyze captures).
//
// Port fixes over the ancestor, all found in review:
//   • IPv6 — the ancestor queried AF_INET only (its AF_INET6 const was
//     defined and never used); both families here, same one-syscall
//     pattern as TcpConnectionTable.
//   • honest state — the ancestor stamped every row "Listening" (a TCP
//     concept) and filed vanished endpoints as "Closed" connections; a
//     UDP row here claims only what the kernel table gives: BOUND. A
//     bound socket may never transmit — transmit evidence belongs to
//     Sysmon EID 3 / trace_analyze, and consumers must not conflate the
//     two (the ancestor's grid merged UDP rows into its TCP connection
//     list, exactly the conflation to avoid).
//   • race-checked size query — the ancestor ignored the first call's
//     return and silently produced an EMPTY snapshot whenever the table
//     grew between sizing and fill (ERROR_INSUFFICIENT_BUFFER); here the
//     sizing failure is detected like TcpConnectionTable does, and the
//     grow-between-calls case degrades to that family's empty result
//     rather than a wrong one.
//   • no remote fields — the kernel's owner-pid UDP row HAS none; the
//     ancestor's "-" placeholder became a non-field so no consumer can
//     build a destination narrative the table cannot support. (Its
//     mute-by-"-" keying collision died with the field.)
//
// What this table is authoritative for: every UDP endpoint the OS knows,
// v4 and v6, with owning pid, at one kernel instant — the answer to "who
// holds a UDP socket", complementing the TCP table's "who holds an
// established flow". What it is NOT: traffic evidence. Sysmon EID 3 (per
// send, with image) and trace_analyze (wire capture) remain the
// transmitting truths; a row here plus zero EID 3 events is a bound and
// silent socket.

namespace AutoCommand.Engines.Watch

open System
open System.Collections.Generic
open System.Net
open System.Net.Sockets
open System.Runtime.InteropServices

/// <summary>
/// Atomic enumeration of bound UDP endpoints with their owning PID, via
/// the IP Helper API (GetExtendedUdpTable) — both address families, one
/// syscall per family, the same kernel-instant contract as
/// TcpConnectionTable.GetEstablished. Rows carry local endpoint and owner
/// only: the owner-pid UDP table has no remote, no state and no byte
/// counts, so "bound" is the entire claim.
/// </summary>
module UdpEndpointTable =

    // F# record, same shape discipline as TcpConnectionTable.Row: from C#
    // it is read-only properties + structural equality + one constructor.
    type Row =
        { LocalEndPoint: string   // "ip:port" v4, "[addr]:port" v6 — netstat display convention
          LocalIp: string
          LocalPort: int
          Pid: int
          IsIpv6: bool }

    let private afInet = 2 // AF_INET
    let private afInet6 = 23 // AF_INET6
    let private udpTableOwnerPid = 1 // UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID
    let private errorInsufficientBuffer = 122u

    module private Interop =

        // 12 bytes: DWORD localAddr, DWORD localPort (network byte order in
        // the low word), DWORD owningPid — layout-verified against the
        // ancestor's marshaling and the SDK's MIB_UDPROW_OWNER_PID.
        [<Struct; StructLayout(LayoutKind.Sequential)>]
        type MIB_UDPROW_OWNER_PID =
            val LocalAddr: uint32
            val LocalPort: uint32
            val OwningPid: uint32

        // 28 bytes: 16-byte address, scope id, port, pid — mirrors
        // TcpConnectionTable's TCP6 row marshaling.
        [<Struct; StructLayout(LayoutKind.Sequential)>]
        type MIB_UDP6ROW_OWNER_PID =
            [<MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)>]
            val LocalAddr: byte[]

            val LocalScopeId: uint32
            val LocalPort: uint32 // network byte order in the low two bytes
            val OwningPid: uint32

        [<DllImport("iphlpapi.dll")>]
        extern uint32 GetExtendedUdpTable(
            nativeint pUdpTable,
            int& dwOutBufLen,
            bool bOrder,
            int ulAf,
            int tableClass,
            uint32 reserved)

    // The DWORD carries the port in network byte order: swap the low two bytes.
    // (Parens are load-bearing: F# <<< binds LOWER than |||.)
    let private port (networkOrder: uint32) : int =
        int (((networkOrder &&& 0xFFu) <<< 8) ||| ((networkOrder >>> 8) &&& 0xFFu))

    let private getBoundV4() : ResizeArray<Row> =
        let rows = ResizeArray<Row>()
        let mutable size = 0

        if
            Interop.GetExtendedUdpTable(IntPtr.Zero, &size, false, afInet, udpTableOwnerPid, 0u)
            <> errorInsufficientBuffer
            || size < 4
        then
            rows
        else
            let buffer = Marshal.AllocHGlobal size

            try
                if
                    Interop.GetExtendedUdpTable(buffer, &size, false, afInet, udpTableOwnerPid, 0u)
                    <> 0u
                then
                    rows
                else
                    let count = Marshal.ReadInt32 buffer
                    let rowSize = Marshal.SizeOf<Interop.MIB_UDPROW_OWNER_PID>()

                    for i = 0 to count - 1 do
                        let row =
                            Marshal.PtrToStructure<Interop.MIB_UDPROW_OWNER_PID>(
                                buffer + nativeint 4 + nativeint (i * rowSize)
                            )

                        // uint in memory is already the network-order byte
                        // sequence; IPAddress(byte[]) reads index 0 as the
                        // first octet — same trick the TCP v4 row uses.
                        let ip = IPAddress(BitConverter.GetBytes row.LocalAddr)

                        rows.Add
                            { LocalEndPoint = $"{ip}:{port row.LocalPort}"
                              LocalIp = ip.ToString()
                              LocalPort = port row.LocalPort
                              Pid = int row.OwningPid
                              IsIpv6 = false }

                    rows
            finally
                Marshal.FreeHGlobal buffer

    let private getBoundV6() : ResizeArray<Row> =
        let rows = ResizeArray<Row>()
        let mutable size = 0

        if
            Interop.GetExtendedUdpTable(IntPtr.Zero, &size, false, afInet6, udpTableOwnerPid, 0u)
            <> errorInsufficientBuffer
            || size < 4
        then
            rows
        else
            let buffer = Marshal.AllocHGlobal size

            try
                if
                    Interop.GetExtendedUdpTable(buffer, &size, false, afInet6, udpTableOwnerPid, 0u)
                    <> 0u
                then
                    rows
                else
                    let count = Marshal.ReadInt32 buffer
                    let rowSize = Marshal.SizeOf<Interop.MIB_UDP6ROW_OWNER_PID>()

                    for i = 0 to count - 1 do
                        let row =
                            Marshal.PtrToStructure<Interop.MIB_UDP6ROW_OWNER_PID>(
                                buffer + nativeint 4 + nativeint (i * rowSize)
                            )

                        // scope id only meaningful on link-local addresses;
                        // zero elsewhere — construct with it when present,
                        // same discipline as the TCP6 row.
                        let ip =
                            if row.LocalScopeId = 0u then
                                IPAddress row.LocalAddr
                            else
                                IPAddress(row.LocalAddr, int64 row.LocalScopeId)

                        rows.Add
                            { LocalEndPoint = $"[{ip}]:{port row.LocalPort}"
                              LocalIp = ip.ToString()
                              LocalPort = port row.LocalPort
                              Pid = int row.OwningPid
                              IsIpv6 = true }

                    rows
            finally
                Marshal.FreeHGlobal buffer

    /// <summary>
    /// All bound UDP endpoints, IPv4 and IPv6, at one kernel instant.
    /// Filtering is the caller's policy (loopback/wildcard rows are
    /// included — a 0.0.0.0 binding is a real endpoint the owner can
    /// transmit from; TcpConnectionTable.IsLocalOrNonRoutable applies
    /// unchanged when a consumer wants the same view policy). Empty on
    /// any failure — callers degrade exactly like the TCP table's.
    /// </summary>
    let GetBound() : ResizeArray<Row> =
        let rows = ResizeArray<Row>()
        rows.AddRange(getBoundV4 ())
        rows.AddRange(getBoundV6 ())
        rows
