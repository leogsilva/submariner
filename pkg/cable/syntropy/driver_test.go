package syntropy

import (
	"testing"

	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/submariner-io/submariner/pkg/types"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func TestInit(t *testing.T) {
	client, err := wgctrl.New()
	if err != nil {
		t.Errorf("Error creating wg client %v", err)
	}

	w := &wireguard{
		client: client,
	}
	err = w.Init()
	if err != nil {
		t.Errorf("Init failed %v", err)
	}
}

func TestNew(t *testing.T) {
	le := types.SubmarinerEndpoint{
		Spec: v1.EndpointSpec{
			BackendConfig: make(map[string]string),
		},
	}
	c := types.SubmarinerCluster{}
	_, err := NewDriver(le, c)
	if err != nil {
		t.Errorf("NewDriver failed %v", err)
	}
}

func TestConnect(t *testing.T) {
	client, err := wgctrl.New()
	if err != nil {
		t.Errorf("Error creating wg client %v", err)
	}

	w := &wireguard{
		client:      client,
		connections: make(map[string]*v1.Connection),
		localEndpoint: types.SubmarinerEndpoint{
			Spec: v1.EndpointSpec{
				ClusterID: "peerA",
			},
		},
	}
	ei := &natdiscovery.NATEndpointInfo{
		UseIP: "192.168.0.16",
		Endpoint: v1.Endpoint{
			Spec: v1.EndpointSpec{
				ClusterID: "peerB",
			},
		},
	}
	ip, err := w.ConnectToEndpoint(ei)
	if err != nil {
		t.Errorf("Error connecting to endpoint %v", err)
	}
	t.Logf("ip %s", ip)
	conns := w.connections
	if len(conns) != 1 {
		t.Errorf("expected only 1 connection but got %d", len(conns))
	}
}

func TestDisconnect(t *testing.T) {
	client, err := wgctrl.New()
	if err != nil {
		t.Errorf("Error creating wg client %v", err)
	}

	w := &wireguard{
		client:      client,
		connections: make(map[string]*v1.Connection),
		localEndpoint: types.SubmarinerEndpoint{
			Spec: v1.EndpointSpec{
				ClusterID: "peerA",
			},
		},
	}
	endpoint := types.SubmarinerEndpoint{}
	err = w.DisconnectFromEndpoint(endpoint)
	if err != nil {
		t.Errorf("Error connecting to endpoint %v", err)
	}
	conns := w.connections
	if len(conns) != 0 {
		t.Errorf("expected only 0 connection but got %d", len(conns))
	}
}
