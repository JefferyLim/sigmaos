package container

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"

	db "sigmaos/debug"
	"sigmaos/proc"
	sp "sigmaos/sigmap"
)

func StartPContainer(p *proc.Proc, kernelId, realm string) (*Container, error) {
	db.DPrintf(db.CONTAINER, "dockerContainer %v\n", realm)
	image := "sigmauser"
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	cmd := append([]string{p.Program}, p.Args...)
	db.DPrintf(db.CONTAINER, "ContainerCreate %v %v %v\n", cmd, p.GetEnv(), container.NetworkMode(sp.Conf.Network.MODE))

	pset := nat.PortSet{} // Ports to expose
	pmap := nat.PortMap{} // NAT mappings for exposed ports
	for i := FPORT; i < LPORT; i++ {
		p, err := nat.NewPort("tcp", i.String())
		if err != nil {
			return nil, err
		}
		pset[p] = struct{}{}
		pmap[p] = []nat.PortBinding{{}}
	}

	endpoints := make(map[string]*network.EndpointSettings, 1)
	endpoints["sigmanet"] = &network.EndpointSettings{}
	resp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image:        image,
			Cmd:          cmd,
			Tty:          false,
			Env:          p.GetEnv(),
			ExposedPorts: pset,
		}, &container.HostConfig{
			NetworkMode: container.NetworkMode(sp.Conf.Network.MODE),
			Mounts: []mount.Mount{
				mount.Mount{
					Type:     mount.TypeBind,
					Source:   PERF_MOUNT,
					Target:   PERF_MOUNT,
					ReadOnly: false,
				},
			},
			PortBindings: pmap,
		}, &network.NetworkingConfig{
			EndpointsConfig: endpoints,
		}, nil, kernelId+"-uprocd-"+realm)
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		db.DPrintf(db.CONTAINER, "ContainerStart err %v\n", err)
		return nil, err
	}
	json, err1 := cli.ContainerInspect(ctx, resp.ID)
	if err1 != nil {
		db.DPrintf(db.CONTAINER, "ContainerInspect err %v\n", err)
		return nil, err
	}
	ip := json.NetworkSettings.IPAddress

	pm := makePortMap(json.NetworkSettings.NetworkSettingsBase.Ports)

	db.DPrintf(db.CONTAINER, "network setting: ip %v portmap %v\n", ip, pm)
	return &Container{ctx, cli, resp.ID, ip, pm, nil}, nil
}
