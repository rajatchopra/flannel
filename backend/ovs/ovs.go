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
	once	sync.Once
	ovsBackend *OVSBackend
)

type OVSNetwork struct {
	Name string
	VNI  int
	leases  []*subnet.Lease
	config  *subnet.Config
}

type OVSBackend struct {
	sm      subnet.Manager
	networks []*OVSNetwork
	dev    *ovsDevice
	ctx    context.Context
	extIAddr net.IP
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(sm subnet.Manager, network string, config *subnet.Config) backend.Backend {
	onceFunc := func() {
		ctx, cancel := context.WithCancel(context.Background())
		ovsBackend = &OVSBackend{
			sm:      sm,
			networks: make([]*OVSNetwork,0),
			ctx:     ctx,
			cancel:  cancel,
		}
	}
	once.Do(onceFunc)
	ovsBackend.AddNetwork(network, config)
	return ovsBackend
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

func newSubnetAttrs(extEaddr net.IP) (*subnet.LeaseAttrs, error) {
	return &subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(extEaddr),
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
		leases: make([]*subnet.Lease, 0),
	}
	ovsb.networks = append(ovsBackend.networks, n)
	return n
}

func (ovsb *OVSBackend) AddLeaseToNetwork(network *OVSNetwork) error {
	// Acquire a lease for this node within the given network
	sa, err := newSubnetAttrs(ovsb.extIAddr)
	if err != nil {
		return err
	}
	l, err := ovsb.sm.AcquireLease(ovsb.ctx, network.Name, sa)
	switch err {
	case nil:
		network.leases = append(network.leases, l)
	case context.Canceled, context.DeadlineExceeded:
		return err
	default:
		return fmt.Errorf("failed to acquire lease: %v", err)
	}

	return nil
}

func (ovsb *OVSBackend) Init(extIface *net.Interface, extIaddr net.IP, extEaddr net.IP) (*backend.SubnetDef, error) {
	// store the ext addresses
	ovsb.extIAddr = extIaddr

	if ovsb.dev == nil {
		dev, err := newOVSDevice(extIaddr)
		if err != nil {
			return nil, err
		}
		ovsb.dev = dev
	}

	for _, network := range ovsb.networks {
		if len(network.leases) == 0 {
			err := ovsb.AddLeaseToNetwork(network)
			// Configure the device for the newly acquired lease
			ovsb.dev.ConfigureDeviceForNetwork(network)
			if err != nil {
				return nil, err
			}
		}
	}
	
	return &backend.SubnetDef{}, nil
}

func (ovsb *OVSBackend) Run() {
	for _, network := range(ovsb.networks) {
		for _, lease := range(network.leases) {
			ovsb.wg.Add(1)
			go func() {
				subnet.LeaseRenewer(ovsb.ctx, ovsb.sm, network.Name, lease)
				log.Info("LeaseRenewer exited")
				ovsb.wg.Done()
			}()
		} // end for: each lease in a network
	} // end for: each network being watched in this backend instance
	defer ovsb.wg.Wait()

	log.Info("Watching for new subnet leases")
	for _, network := range(ovsb.networks) {
		ovsb.wg.Add(1)
		go ovsb.watchNetworkLeases(network)
	}
}

func (ovsb *OVSBackend) watchNetworkLeases(network *OVSNetwork) {
	evts := make(chan []subnet.Event)
	ovsb.wg.Add(1)
	go func() {
		subnet.WatchLeases(ovsb.ctx, ovsb.sm, network.Name, network.leases[0], evts)
		log.Info("WatchLeases exited")
		ovsb.wg.Done()
	}()

	for {
		select {
		case evtBatch := <-evts:
			ovsb.handleSubnetEvents(network, evtBatch)

		case <-ovsb.ctx.Done():
			ovsb.wg.Done()
			return
		}
	}
}

func (ovsb *OVSBackend) Stop() {
	ovsb.cancel()
}

func (ovsb *OVSBackend) Name() string {
	return "OVS"
}

func (ovsb *OVSBackend) handleSubnetEvents(network *OVSNetwork, batch []subnet.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case subnet.EventAdded:
			log.Info("Subnet added: ", evt.Lease.Subnet)

			if evt.Lease.Attrs.BackendType != "ovs" {
				log.Warningf("Ignoring non-ovs subnet: type=%v", evt.Lease.Attrs.BackendType)
				continue
			}

			fmt.Printf("rcrc - network: %v\n", network)
			ovsb.dev.AddRemoteSubnet(network, evt.Lease.Subnet.ToIPNet(), evt.Lease.Attrs.PublicIP.ToIP())

		case subnet.EventRemoved:
			log.Info("Subnet removed: ", evt.Lease.Subnet)

			if evt.Lease.Attrs.BackendType != "ovs" {
				log.Warningf("Ignoring non-ovs subnet: type=%v", evt.Lease.Attrs.BackendType)
				continue
			}

			ovsb.dev.RemoveRemoteSubnet(network, evt.Lease.Subnet.ToIPNet(), evt.Lease.Attrs.PublicIP.ToIP())

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}
