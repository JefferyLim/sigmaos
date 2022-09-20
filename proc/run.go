package proc

import (
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"

	np "sigmaos/ninep"
)

// To run kernel procs
func RunKernelProc(p *Proc, namedAddr []string) (*exec.Cmd, error) {
	p.FinalizeEnv("NONE")
	env := p.GetEnv()
	env = append(env, "NAMED="+strings.Join(namedAddr, ","))
	env = append(env, "SIGMAPROGRAM="+p.Program)

	cmd := exec.Command(path.Join(np.PRIVILEGED_BIN, p.Program), p.Args...)
	// Create a process group ID to kill all children if necessary.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), env...)
	return cmd, cmd.Start()
}
