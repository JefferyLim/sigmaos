package container

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"

	db "sigmaos/debug"
	"sigmaos/fslib"
)

//
// Start kernel inside a docker container
//

const (
	SIGMAKIMAGE = "sigmaos"
)

func StartKContainer(yml string, nameds []string, env []string) (*Container, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	db.DPrintf(db.CONTAINER, "start container %v %v %v\n", yml, nameds, env)
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: SIGMAKIMAGE,
		Cmd:   []string{"bin/linux/bootkernel", yml, fslib.NamedAddrsToString(nameds)},
		Tty:   false,
		Env:   env,
	}, &container.HostConfig{
		// This is bad idea in general because it requires to give rw
		// permission on host to privileged daemon.  But maybe ok in
		// our case where kernel is trusted as is. XXX Use different
		// image for user procs.
		Binds: []string{
			"/var/run/docker.sock:/var/run/docker.sock",
		},
	}, nil, nil, "")
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return nil, err
	}
	json, err1 := cli.ContainerInspect(ctx, resp.ID)
	if err1 != nil {
		return nil, err
	}
	ip := json.NetworkSettings.IPAddress
	db.DPrintf(db.CONTAINER, "Booting %s %s at %s...\n", SIGMAKIMAGE, resp.ID[:10], ip)
	return &Container{ctx, cli, resp.ID, ip}, nil
}
