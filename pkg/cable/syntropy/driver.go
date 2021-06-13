/*
© 2021 Red Hat, Inc. and others

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package syntropy

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/klog"

	"github.com/submariner-io/admiral/pkg/log"

	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/types"
)

const (
	// DefaultDeviceName specifies name of WireGuard network device
	DefaultDeviceName = "SYNTROPY_PUBLIC"

	// PublicKey is name (key) of publicKey entry in back-end map
	PublicKey = "publicKey"

	// KeepAliveInterval to use for wg peers
	KeepAliveInterval = 10 * time.Second

	// handshakeTimeout is maximal time from handshake a connections is still considered connected
	handshakeTimeout = 2*time.Minute + 10*time.Second

	cableDriverName = "syntropy"
	receiveBytes    = "ReceiveBytes"  // for peer connection status
	transmitBytes   = "TransmitBytes" // for peer connection status
	lastChecked     = "LastChecked"   // for connection peer status

	// TODO use submariner prefix
	specEnvPrefix = "ce_ipsec"
)

func init() {
	cable.AddDriver(cableDriverName, NewDriver)
}

type specification struct {
	PSK      string `default:"default psk"`
	NATTPort int    `default:"4500"`
}

type wireguard struct {
	localEndpoint types.SubmarinerEndpoint
	connections   map[string]*v1.Connection // clusterID -> remote ep connection
	mutex         sync.Mutex
	client        *wgctrl.Client
	link          netlink.Link
	spec          *specification
}

// NewDriver creates a new WireGuard driver
func NewDriver(localEndpoint types.SubmarinerEndpoint, localCluster types.SubmarinerCluster) (cable.Driver, error) {
	var err error

	w := wireguard{
		connections:   make(map[string]*v1.Connection),
		localEndpoint: localEndpoint,
		spec:          new(specification),
	}

	if err := envconfig.Process(specEnvPrefix, w.spec); err != nil {
		return nil, fmt.Errorf("error processing environment config for wireguard: %v", err)
	}

	// create controller
	if w.client, err = wgctrl.New(); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("wgctrl is not available on this system")
		}

		return nil, fmt.Errorf("failed to open wgctl client: %v", err)
	}

	defer func() {
		if err != nil {
			if e := w.client.Close(); e != nil {
				klog.Errorf("Failed to close client %v", e)
			}

			w.client = nil
		}
	}()

	d, err := w.client.Device(DefaultDeviceName)
	if err != nil {
		return nil, fmt.Errorf("wgctrl cannot find WireGuard device: %v", err)
	}

	w.localEndpoint.Spec.BackendConfig[PublicKey] = d.PublicKey.String()

	klog.V(log.DEBUG).Infof("Created WireGuard %s with publicKey %s", DefaultDeviceName, w.localEndpoint.Spec.BackendConfig[PublicKey])

	return &w, nil
}

func (w *wireguard) Init() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	klog.V(log.DEBUG).Infof("Initializing WireGuard device for cluster %s", w.localEndpoint.Spec.ClusterID)

	if len(w.connections) != 0 {
		return fmt.Errorf("cannot initialize with existing connections: %+v", w.connections)
	}

	l, err := net.InterfaceByName(DefaultDeviceName)
	if err != nil {
		return fmt.Errorf("cannot get wireguard link by name %s: %v", DefaultDeviceName, err)
	}

	d, err := w.client.Device(DefaultDeviceName)
	if err != nil {
		return fmt.Errorf("wgctrl cannot find WireGuard device: %v", err)
	}

	if l, err := netlink.LinkList(); err != nil {
		return fmt.Errorf("failed to show WireGuard device: %v", err)
	} else {
		for _, link := range l {
			if link.Attrs().Name == d.Name {
				if !strings.Contains(link.Attrs().Flags.String(), net.FlagUp.String()) {
					return fmt.Errorf("failed to check if WireGuard device is up: %v", err)
				} else {
					w.link = link
				}
			}
		}
	}

	// ip link set $DefaultDeviceName up

	klog.V(log.DEBUG).Infof("WireGuard device %s, is up on i/f number %d, listening on port :%d, with key %s",
		w.link.Attrs().Name, l.Index, d.ListenPort, d.PublicKey)

	return nil
}

func (w *wireguard) GetName() string {
	return cableDriverName
}

func (w *wireguard) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	remoteEndpoint := &endpointInfo.Endpoint
	ip := endpointInfo.UseIP

	if w.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not connect to self")
		return "", nil
	}

	// parse remote addresses and allowed IPs
	remoteIP := net.ParseIP(ip)
	if remoteIP == nil {
		return "", fmt.Errorf("failed to parse remote IP %s", ip)
	}

	// parse remote public key
	remoteKey, err := keyFromSpec(&remoteEndpoint.Spec)
	if err != nil {
		return "", fmt.Errorf("failed to parse peer public key: %v", err)
	}

	klog.V(log.DEBUG).Infof("Connecting cluster %s endpoint %s with publicKey %s",
		remoteEndpoint.Spec.ClusterID, remoteIP, remoteKey)
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// delete or update old peers for ClusterID
	oldCon, found := w.connections[remoteEndpoint.Spec.ClusterID]
	if found {
		if oldKey, err := keyFromSpec(&oldCon.Endpoint); err == nil {
			if oldKey.String() == remoteKey.String() {
				// existing connection, update status and skip
				w.updatePeerStatus(oldCon, oldKey)
				klog.V(log.DEBUG).Infof("Skipping connect for existing peer key %s", oldKey)

				return ip, nil
			}

		}

		delete(w.connections, remoteEndpoint.Spec.ClusterID)
	}

	// create connection, overwrite existing connection
	connection := v1.NewConnection(remoteEndpoint.Spec, ip, endpointInfo.UseNAT)
	connection.SetStatus(v1.Connecting, "Connection has been created but not yet started")
	klog.V(log.DEBUG).Infof("Adding connection for cluster %s, %v", remoteEndpoint.Spec.ClusterID, connection)
	w.connections[remoteEndpoint.Spec.ClusterID] = connection

	// verify peer was added
	if p, err := w.peerByKey(remoteKey); err != nil {
		klog.Errorf("Failed to verify peer configuration: %v", err)
	} else {
		// TODO verify configuration
		klog.V(log.DEBUG).Infof("Peer configured, PubKey:%s, EndPoint:%s, AllowedIPs:%v", p.PublicKey, p.Endpoint, p.AllowedIPs)
	}

	klog.V(log.DEBUG).Infof("Done connecting endpoint peer %s@%s", *remoteKey, remoteIP)

	cable.RecordConnection(cableDriverName, &w.localEndpoint.Spec, &connection.Endpoint, string(v1.Connected), true)

	return ip, nil
}

func keyFromSpec(ep *v1.EndpointSpec) (*wgtypes.Key, error) {
	s, found := ep.BackendConfig[PublicKey]
	if !found {
		return nil, fmt.Errorf("endpoint is missing public key")
	}

	key, err := wgtypes.ParseKey(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key %s: %v", s, err)
	}

	return &key, nil
}

func (w *wireguard) DisconnectFromEndpoint(remoteEndpoint types.SubmarinerEndpoint) error {
	klog.V(log.DEBUG).Infof("Removing endpoint %v+", remoteEndpoint)

	if w.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not disconnect self")
		return nil
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	delete(w.connections, remoteEndpoint.Spec.ClusterID)

	klog.V(log.DEBUG).Infof("Done removing endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)
	cable.RecordDisconnected(cableDriverName, &w.localEndpoint.Spec, &remoteEndpoint.Spec)

	return nil
}

func (w *wireguard) GetActiveConnections() ([]v1.Connection, error) {
	// force caller to skip duplicate handling
	return make([]v1.Connection, 0), nil
}

func (w *wireguard) peerByKey(key *wgtypes.Key) (*wgtypes.Peer, error) {
	d, err := w.client.Device(DefaultDeviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find device %s: %v", DefaultDeviceName, err)
	}
	for _, p := range d.Peers {
		if p.PublicKey.String() == key.String() {
			return &p, nil
		}
	}

	return nil, fmt.Errorf("peer not found for key %s", key)
}
