// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ovs

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	log "github.com/coreos/flannel/Godeps/_workspace/src/github.com/golang/glog"
	"github.com/coreos/flannel/Godeps/_workspace/src/golang.org/x/net/context"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
)

const (
	defaultVNI = 0
)

var (
	onceNew	   sync.Once
	onceRun    sync.Once
	ovsBackend *OVSBackend
)

type OVSNetwork struct {
	Name          string
	VNI           int
	lease         *subnet.Lease
	config        *subnet.Config
	mut           sync.Mutex
}

type OVSBackend struct {
	sm       subnet.Manager
	mtu      int
	networks []*OVSNetwork
	dev      *ovsDevice
	extIAddr net.IP
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mut      sync.Mutex
	watches  chan(*OVSNetwork)
}

func New(sm subnet.Manager, extIface *net.Interface, extIaddr net.IP, extEaddr net.IP) (backend.Backend, error) {
	var err error
	onceFunc := func() {
		ovsBackend = &OVSBackend{
			sm:              sm,
			mtu:             extIface.MTU,
			networks:        make([]*OVSNetwork,0),
			extIAddr:        extIaddr,
			watches:         make(chan *OVSNetwork, 5),
		}
		dev, err := newOVSDevice(extIaddr)
		if err != nil {
			return
		}
		ovsBackend.dev = dev
		return
	}
	onceNew.Do(onceFunc)
	if err != nil {
		return nil, err
	}
	return ovsBackend, nil
}

func parseVNI(config *subnet.Config) (int) {
	var bt struct {
		VNI int
	}

	if len(config.Backend) == 0 {
		bt.VNI = defaultVNI
	} else {
		if err := json.Unmarshal(config.Backend, &bt); err != nil {
			log.Warningf("Error decoding Backend property of config: %v, no VNI found. Defaulting to %d", err, defaultVNI)
			bt.VNI = defaultVNI
		}
	}
	return bt.VNI
}

func newSubnetAttrs(extIaddr net.IP) (*subnet.LeaseAttrs, error) {
	return &subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(extIaddr),
		BackendType: "ovs",
		BackendData: json.RawMessage(""),
	}, nil
}


func (ovsb *OVSBackend) AddNetwork(network string, config *subnet.Config) (*OVSNetwork) {
	if len(network) == 0 || config == nil {
		return nil
	}
	n := &OVSNetwork{
		Name: network,
		config: config,
		VNI: parseVNI(config),
	}
	ovsb.networks = append(ovsBackend.networks, n)
	return n
}

func (ovsb *OVSBackend) RegisterNetwork(ctx context.Context, network string, config *subnet.Config) (*backend.SubnetDef, error) {
	ovsb.mut.Lock()
	defer ovsb.mut.Unlock()

	net := ovsBackend.AddNetwork(network, config)

	// Acquire a lease for this node within the given network
	sa, err := newSubnetAttrs(ovsb.extIAddr)
	if err != nil {
		return nil, err
	}

	l, err := ovsb.sm.AcquireLease(ctx, net.Name, sa)
	switch err {
	case nil:
		net.lease = l

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// Configure the device for the newly acquired lease
	ovsb.dev.ConfigureDeviceForNetwork(net, l)
	if err != nil {
		return nil, err
	}

	ovsb.watches <- net

	return &backend.SubnetDef{
		Lease: l,
		MTU:   ovsb.mtu,
	}, nil
}


func (ovsb *OVSBackend) watchNetworkLeases(network *OVSNetwork, ctx context.Context) {
	evts := make(chan []subnet.Event)
	ovsb.wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, ovsb.sm, network.Name, nil, evts)
		log.Infof("WatchLeases(%s) exited", network.Name)
		ovsb.wg.Done()
	}()

	log.Errorf("rcrcrc - watching %v\n", network)
	initialEvtsBatch := <-evts
	ovsb.handleSubnetEvents(network, initialEvtsBatch)

SubnetEvents:
	for {
		select {
		case evtBatch := <-evts:
			ovsb.handleSubnetEvents(network, evtBatch)

		case <-ctx.Done():
			break SubnetEvents
		}
	}
}

// Only called the first time we see an OVS network
func (ovsb *OVSBackend) start(ctx context.Context) {
	for {
		select {
		case net := <-ovsb.watches:
			ovsb.wg.Add(1)
			go func() {
				ovsb.watchNetworkLeases(net, ctx)
				ovsb.wg.Done()
			}()

		case <-ctx.Done():
			return
		}
	}
}

func (ovsb *OVSBackend) Run(ctx context.Context) {
	onceRun.Do(func() { ovsb.start(ctx) })
}

func (ovsb *OVSBackend) handleSubnetEvents(network *OVSNetwork, batch []subnet.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case subnet.EventAdded:
			log.Infof("Subnet added: %s => %s", evt.Lease.Attrs.PublicIP, evt.Lease.Subnet)

			if evt.Lease.Attrs.BackendType != "ovs" {
				log.Warningf("Ignoring non-ovs subnet: type=%v", evt.Lease.Attrs.BackendType)
				continue
			}

			fmt.Printf("rcrc - network: %v\n", network)
			if ovsb.extIAddr.String() == evt.Lease.Attrs.PublicIP.String() {
				ovsb.dev.AddLocalSubnet(network, evt.Lease.Subnet.ToIPNet())
			} else {
				ovsb.dev.AddRemoteSubnet(network, evt.Lease.Subnet.ToIPNet(), evt.Lease.Attrs.PublicIP.ToIP())
			}

		case subnet.EventRemoved:
			log.Infof("Subnet removed: %s => %s", evt.Lease.Attrs.PublicIP, evt.Lease.Subnet)

			if evt.Lease.Attrs.BackendType != "ovs" {
				log.Warningf("Ignoring non-ovs subnet: type=%v", evt.Lease.Attrs.BackendType)
				continue
			}

			if ovsb.extIAddr.String() == evt.Lease.Attrs.PublicIP.String() {
				ovsb.dev.RemoveLocalSubnet(network, evt.Lease.Subnet.ToIPNet())
			} else {
				ovsb.dev.RemoveRemoteSubnet(network, evt.Lease.Subnet.ToIPNet(), evt.Lease.Attrs.PublicIP.ToIP())
			}

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}

func (ovsb *OVSBackend) Stop() {
	// OVSBackend is a singleton and uses the master context
}

func (ovsb *OVSBackend) Name() string {
	return "OVS"
}

