// Opt-in seccomp deny-list (defense in depth).
//
// A DENY-LIST (block a small set of clearly-dangerous syscalls, allow the rest)
// rather than an allow-list: it cannot break normal operation, so it is safe to
// ship without exhaustively enumerating Grimlock's syscall footprint. It hardens
// the co-located-adversary case — a hijacked neighbor (or an exploited daemon)
// cannot ptrace / read another process's memory to steal kTLS or resumption
// secrets, load kernel modules, or manipulate mounts/namespaces to break out.
// The full allow-list jail is the target (docs/privilege-separation.md); this is
// the piece that is safe to apply in-process today.

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	seccompSetModeFilter = 1          // SECCOMP_SET_MODE_FILTER
	seccompFilterTSync   = 1          // SECCOMP_FILTER_FLAG_TSYNC (apply to all threads)
	seccompRetAllow      = 0x7fff0000 // SECCOMP_RET_ALLOW
	seccompRetErrnoEPERM = 0x00050001 // SECCOMP_RET_ERRNO | EPERM(1)
)

// deniedSyscalls are dangerous and unused by Grimlock (or the Go runtime / eBPF
// loader), so blocking them is safe. Notably we do NOT block bpf/perf_event_open
// (the eBPF loader needs them).
var deniedSyscalls = []int{
	unix.SYS_PTRACE,            // no debugging others
	unix.SYS_PROCESS_VM_READV,  // no reading another process's memory
	unix.SYS_PROCESS_VM_WRITEV, // no writing another process's memory
	unix.SYS_KEXEC_LOAD,        // no kernel replacement
	unix.SYS_INIT_MODULE,       // no module load
	unix.SYS_FINIT_MODULE,      //  "
	unix.SYS_DELETE_MODULE,     // no module unload
	unix.SYS_MOUNT,             // no mounts
	unix.SYS_UMOUNT2,           //  "
	unix.SYS_PIVOT_ROOT,        // no root pivot
	unix.SYS_SETNS,             // no namespace entry
}

func sfStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}
func sfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// seccompDenylistProgram builds the classic-BPF filter: load the syscall number,
// return EPERM for any denied one, else allow. Pure/deterministic (unit-testable).
func seccompDenylistProgram() []unix.SockFilter {
	prog := []unix.SockFilter{
		sfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0), // A = seccomp_data.nr (offset 0)
	}
	for _, nr := range deniedSyscalls {
		prog = append(prog,
			sfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(nr), 0, 1), // if A==nr fall through, else skip 1
			sfStmt(unix.BPF_RET|unix.BPF_K, seccompRetErrnoEPERM),          // deny → EPERM
		)
	}
	return append(prog, sfStmt(unix.BPF_RET|unix.BPF_K, seccompRetAllow)) // default allow
}

// applySeccompDenylist installs the filter process-wide (TSYNC). Requires
// no_new_privs, which it sets first (idempotent).
func applySeccompDenylist() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	prog := seccompDenylistProgram()
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter,
		seccompFilterTSync, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER): %w", errno)
	}
	return nil
}
