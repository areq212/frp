// Copyright 2026 The frp Authors
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

package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
)

func TestNewXUDPConfigurerByType(t *testing.T) {
	require := require.New(t)

	pc := NewProxyConfigurerByType(ProxyTypeXUDP)
	require.IsType(&XUDPProxyConfig{}, pc)
	require.Equal("xudp", pc.GetBaseConfig().Type)

	vc := NewVisitorConfigurerByType(VisitorTypeXUDP)
	require.IsType(&XUDPVisitorConfig{}, vc)
	require.Equal("xudp", vc.GetBaseConfig().Type)
}

func TestUnmarshalTypedXUDPConfig(t *testing.T) {
	require := require.New(t)

	proxyConfigs := struct {
		Proxies []TypedProxyConfig `json:"proxies,omitempty"`
	}{}
	proxyStr := `{
		"proxies": [
			{
				"name": "p2p-udp",
				"type": "xudp",
				"secretKey": "abc",
				"localPort": 53
			}
		]
	}`
	require.NoError(json.Unmarshal([]byte(proxyStr), &proxyConfigs))
	require.IsType(&XUDPProxyConfig{}, proxyConfigs.Proxies[0].ProxyConfigurer)
	require.Equal("abc", proxyConfigs.Proxies[0].ProxyConfigurer.(*XUDPProxyConfig).Secretkey)

	visitorConfigs := struct {
		Visitors []TypedVisitorConfig `json:"visitors,omitempty"`
	}{}
	visitorStr := `{
		"visitors": [
			{
				"name": "p2p-udp-visitor",
				"type": "xudp",
				"serverName": "p2p-udp",
				"secretKey": "abc",
				"bindPort": 9002
			}
		]
	}`
	require.NoError(json.Unmarshal([]byte(visitorStr), &visitorConfigs))
	require.IsType(&XUDPVisitorConfig{}, visitorConfigs.Visitors[0].VisitorConfigurer)
}

func TestXUDPProxyConfigMarshalRoundtrip(t *testing.T) {
	require := require.New(t)

	cfg := &XUDPProxyConfig{
		ProxyBaseConfig: ProxyBaseConfig{
			Name: "p2p-udp",
			Type: "xudp",
		},
		Secretkey:  "abc",
		AllowUsers: []string{"user1", "user2"},
	}

	m := &msg.NewProxy{}
	cfg.MarshalToMsg(m)
	require.Equal("abc", m.Sk)
	require.Equal([]string{"user1", "user2"}, m.AllowUsers)

	out := &XUDPProxyConfig{}
	out.UnmarshalFromMsg(m)
	require.Equal(cfg.Secretkey, out.Secretkey)
	require.Equal(cfg.AllowUsers, out.AllowUsers)
}

func TestXUDPVisitorConfigComplete(t *testing.T) {
	require := require.New(t)

	cfg := &XUDPVisitorConfig{}
	cfg.Complete()
	require.Equal("quic", cfg.Protocol)
	require.Equal(8, cfg.MaxRetriesAnHour)
	require.Equal(90, cfg.MinRetryInterval)
	require.Equal("127.0.0.1", cfg.BindAddr)
}

func TestXUDPCloneDeepCopy(t *testing.T) {
	require := require.New(t)

	cfg := &XUDPProxyConfig{
		ProxyBaseConfig: ProxyBaseConfig{
			Name: "p2p-udp",
			Type: "xudp",
		},
		Secretkey:  "abc",
		AllowUsers: []string{"user1"},
		NatTraversal: &NatTraversalConfig{
			DisableAssistedAddrs: true,
		},
	}

	cloned := cfg.Clone().(*XUDPProxyConfig)
	cloned.AllowUsers[0] = "changed"
	cloned.NatTraversal.DisableAssistedAddrs = false

	require.Equal("user1", cfg.AllowUsers[0])
	require.True(cfg.NatTraversal.DisableAssistedAddrs)
}
