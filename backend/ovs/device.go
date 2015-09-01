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
	"fmt"
	"net"
	"os/exec"
	"encoding/hex"

	"github.com/coreos/flannel/subnet"
	log "github.com/coreos/flannel/Godeps/_workspace/src/github.com/golang/glog"
)

type ovsDeviceAttrs struct {
	vni       uint32
	name      string
	vtepIndex int
	vtepAddr  net.IP
	vtepPort  int
}

type ovsDevice struct {
	bridgeName	string
	oflowProto	string
	encapType	string
	encapPort	int
	vtepAddr	net.IP
	tunnelPortMap	map[string]*ovsTunnelDevice
}

type ovsTunnelDevice struct {
	name	string
	portId	int
	subnet	*net.IPNet
}

func newOVSDevice(ipn net.IP) (*ovsDevice, error) {
	bridge := &ovsDevice{
		bridgeName: "br0",
		oflowProto: "OpenFlow13",
		encapType: "vxlan",
		encapPort: 4789,
		vtepAddr: ipn,
		tunnelPortMap: make(map[string]*ovsTunnelDevice),
	}
	err := bridge.Configure()
	return bridge, err
}

func (dev *ovsDevice) Configure() error {
	exec.Command("ovs-vsctl", "del-br", dev.bridgeName).CombinedOutput()
	exec.Command("ovs-vsctl", "add-br", dev.bridgeName, "--", "set", "Bridge", dev.bridgeName, "fail-mode=secure").CombinedOutput()
	exec.Command("ovs-vsctl", "set", "bridge", dev.bridgeName, "protocols=OpenFlow13").CombinedOutput()
	exec.Command("ovs-vsctl", "del-port", dev.bridgeName, "vxlan0").CombinedOutput()
	exec.Command("ovs-vsctl", "add-port", dev.bridgeName, "vxlan0", "--", "set", "Interface", "vxlan0", "type=vxlan", "options:remote_ip=\"flow\"", "options:key=\"flow\"", "ofport_request=1").CombinedOutput()
	return nil
}

func (dev *ovsDevice) Destroy() {
	exec.Command("ovs-vsctl", "del-br", dev.bridgeName)
}

func generateCookie(ip string) string {
	return hex.EncodeToString(net.ParseIP(ip).To4())
}

// Generate the default gateway IP Address for a subnet
func generateDefaultGateway(sna *net.IPNet) net.IP {
	ip := sna.IP.To4()
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]|0x1)
}

func (dev *ovsDevice) ConfigureDeviceForNetwork(network *OVSNetwork, l *subnet.Lease) {
	tunDevName := fmt.Sprintf("tun%s", network.Name)
	subnet := l.Subnet.ToIPNet()
	tunGateway := generateDefaultGateway(subnet)

	// add a tunnel device for this network
	exec.Command("ovs-vsctl", "add-port", dev.bridgeName, tunDevName, "--", "set", "Interface", tunDevName, "type=internal").CombinedOutput()

        // setup tun address
	exec.Command("ip", "addr", "add", tunGateway.String(), "dev", tunDevName).CombinedOutput()
	exec.Command("ip", "link", "set", tunDevName, "up").CombinedOutput()

	newTunPort := &ovsTunnelDevice{name: tunDevName, portId: 2, subnet: subnet}
	dev.tunnelPortMap[network.Name] = newTunPort

	dev.AddRoutes(network, subnet)
	
}

func (dev *ovsDevice) AddRemoteSubnet(network *OVSNetwork, lease *net.IPNet, vtep net.IP) error {
	cookie := generateCookie(vtep.String())
	iprule := fmt.Sprintf("table=6,cookie=0x%s,priority=100,ip,nw_dst=%s,actions=move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31],set_field:%s->tun_dst,output:1", cookie, lease.String(), vtep.String())
	arprule := fmt.Sprintf("table=7,cookie=0x%s,priority=100,arp,nw_dst=%s,actions=move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31],set_field:%s->tun_dst,output:1", cookie, lease.String(), vtep.String())
	out, err := exec.Command("ovs-ofctl", "-O", dev.oflowProto, "add-flow", dev.bridgeName, iprule).CombinedOutput()
	log.Infof("Output of adding %s: %s (%v)", iprule, out, err)
	if err != nil {
		return err
	}
	out, err = exec.Command("ovs-ofctl", "-O", dev.oflowProto, "add-flow", dev.bridgeName, arprule).CombinedOutput()
	log.Infof("Output of adding %s: %s (%v)", iprule, out, err)
	if err != nil {
		return err
	}
	return dev.AddRoutes(network, lease)
}

func (dev *ovsDevice) RemoveRemoteSubnet(network *OVSNetwork, lease *net.IPNet, vtep net.IP) error {
	cookie := generateCookie(vtep.String())
	iprule := fmt.Sprintf("table=6,cookie=0x%s/0xffffffff", cookie)
	arprule := fmt.Sprintf("table=7,cookie=0x%s/0xffffffff", cookie)
	o, e := exec.Command("ovs-ofctl", "-O", dev.oflowProto, "del-flows", dev.bridgeName, iprule).CombinedOutput()
	log.Infof("Output of deleting local ip rules %s (%v)", o, e)
	o, e = exec.Command("ovs-ofctl", "-O", dev.oflowProto, "del-flows", dev.bridgeName, arprule).CombinedOutput()
	log.Infof("Output of deleting local arp rules %s (%v)", o, e)
	if e != nil {
		return e
	}
	return dev.RemoveRoutes(network, lease)
}

func (dev *ovsDevice) RemoveRoutes(network *OVSNetwork, lease *net.IPNet) error {
	tunPort := dev.tunnelPortMap[network.Name]
	_, err := exec.Command("ip", "route", "del", lease.String(), "dev", tunPort.name, "proto", "kernel", "scope", "link").CombinedOutput()
	return err
}

func (dev *ovsDevice) AddRoutes(network *OVSNetwork, lease *net.IPNet) error {
	tunPort := dev.tunnelPortMap[network.Name]
	_, err := exec.Command("ip", "route", "add", lease.String(), "dev", tunPort.name, "proto", "kernel", "scope", "link").CombinedOutput()
	return err
}
