// Process hardening (defense in depth).
//
// The daemon is a high-value target: it holds keys, terminates TLS, and makes
// the Forward decision. Full privilege separation — an isolated, seccomp-jailed
// certified authorization core plus an unprivileged data mover — is the target
// architecture (docs/privilege-separation.md). This file implements the pieces
// that are SAFE to apply in-process and cannot break the daemon.
//
// no_new_privs: once set, no exec of a setuid/setgid or file-capability binary
// can raise privileges. It is irreversible, does not restrict the running
// daemon's own syscalls (so it cannot brick it), and means a compromised daemon
// cannot escalate by exec'ing a helper. It is also a prerequisite for applying a
// seccomp filter without CAP_SYS_ADMIN.

package main

import (
	"log"

	"golang.org/x/sys/unix"
)

// hardenProcess applies in-process, non-fatal hardening. Called early so threads
// the Go runtime spawns afterwards inherit the settings. enableSeccomp installs
// the (safe, deny-list) syscall filter — opt-in because, although the deny-list
// cannot break normal operation, operators should validate it for their build.
func hardenProcess(enableSeccomp bool) {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		log.Printf("[HARDEN] no_new_privs not set: %v", err)
	} else {
		log.Println("[HARDEN] no_new_privs set (no privilege escalation via exec)")
	}

	// Non-dumpable: a co-located process (a hijacked neighbor) cannot ptrace the
	// daemon or read /proc/<pid>/mem to extract kTLS/resumption secrets, and no
	// core dump can leak them. Does not affect the daemon's own operation.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Printf("[HARDEN] non-dumpable not set: %v", err)
	} else {
		log.Println("[HARDEN] process set non-dumpable (no ptrace / core-dump of secrets)")
	}

	if enableSeccomp {
		if err := applySeccompDenylist(); err != nil {
			log.Printf("[HARDEN] seccomp deny-list not applied: %v", err)
		} else {
			log.Printf("[HARDEN] seccomp deny-list active (%d dangerous syscalls blocked)", len(deniedSyscalls))
		}
	}
}
