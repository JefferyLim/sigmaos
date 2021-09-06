package realm

import (
	"log"
	"os"
	"os/exec"
	"path"
	"time"

	"ulambda/fslib"
	"ulambda/kernel"
	"ulambda/named"
)

const (
	SLEEP_MS = 1000
)

// Boot a named and set up the initfs
func BootNamed(bin string, addr string) (*exec.Cmd, error) {
	cmd, err := run(bin, "/bin/kernel/named", addr, []string{"0", addr})
	if err != nil {
		return nil, err
	}
	time.Sleep(SLEEP_MS * time.Millisecond)
	fsl := fslib.MakeFsLibAddr("kernel", addr)
	if err := named.MakeInitFs(fsl); err != nil {
		return nil, err
	}
	return cmd, nil
}

func ShutdownNamed(namedAddr string) {
	fsl := fslib.MakeFsLibAddr("kernel", namedAddr)
	// Shutdown named last
	err := fsl.Remove(kernel.NAMED + "/")
	if err != nil {
		// XXX sometimes we get EOF..
		if err.Error() == "EOF" {
			log.Printf("Remove %v shutdown %v\n", kernel.NAMED, err)
		} else {
			log.Fatalf("Remove %v shutdown %v\n", kernel.NAMED, err)
		}
	}
	time.Sleep(SLEEP_MS * time.Millisecond)
}

func run(bin string, name string, namedAddr string, args []string) (*exec.Cmd, error) {
	cmd := exec.Command(path.Join(bin, name), args...)
	// Create a process group ID to kill all children if necessary.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ())
	cmd.Env = append(cmd.Env, "NAMED="+namedAddr)
	return cmd, cmd.Start()
}
