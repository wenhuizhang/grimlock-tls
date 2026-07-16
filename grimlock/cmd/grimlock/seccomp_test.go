package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSeccompDenylistProgram(t *testing.T) {
	prog := seccompDenylistProgram()
	if want := 1 + 2*len(deniedSyscalls) + 1; len(prog) != want {
		t.Fatalf("program length = %d, want %d (1 load + 2/syscall + 1 allow)", len(prog), want)
	}
	if prog[0].Code != unix.BPF_LD|unix.BPF_W|unix.BPF_ABS {
		t.Error("first instruction must load the syscall number")
	}
	if last := prog[len(prog)-1]; last.Code != unix.BPF_RET|unix.BPF_K || last.K != seccompRetAllow {
		t.Error("last instruction must be default-allow")
	}
}

// TestSeccompBlocksPtrace applies the deny-list in a subprocess (it is
// irreversible + process-wide) and checks that a denied syscall (ptrace) returns
// EPERM while a benign one (getpid) still works.
func TestSeccompBlocksPtrace(t *testing.T) {
	if os.Getenv("GRIM_SECCOMP_CHILD") == "1" {
		if err := applySeccompDenylist(); err != nil {
			os.Stderr.WriteString("APPLY-FAILED:" + err.Error())
			os.Exit(3)
		}
		if os.Getpid() <= 0 { // getpid must still work (allowed)
			os.Exit(4)
		}
		_, _, errno := unix.Syscall(unix.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0)
		if errno == unix.EPERM {
			os.Stdout.WriteString("BLOCKED")
			os.Exit(0)
		}
		os.Stderr.WriteString("NOT-BLOCKED")
		os.Exit(5)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompBlocksPtrace")
	cmd.Env = append(os.Environ(), "GRIM_SECCOMP_CHILD=1")
	out, err := cmd.CombinedOutput()
	if bytes.Contains(out, []byte("APPLY-FAILED")) {
		t.Skipf("seccomp apply not permitted in this environment: %s", out)
	}
	if err != nil || !bytes.Contains(out, []byte("BLOCKED")) {
		t.Fatalf("seccomp did not block ptrace (err=%v):\n%s", err, out)
	}
}
