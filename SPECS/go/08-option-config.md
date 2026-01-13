# 配置选项 (option/)

## 1. 目录概述

`option/` 目录包含 47 个配置选项文件，定义了 sing-box 的所有配置结构。

```
option/
├── anytls.go              # AnyTLS 选项
├── certificate.go         # 证书选项
├── debug.go               # 调试选项
├── direct.go              # Direct 选项
├── dns_record.go          # DNS 记录选项
├── dns.go                 # DNS 选项
├── endpoint.go            # 端点选项
├── experimental.go        # 实验性选项
├── group.go               # 出站组选项
├── hysteria.go            # Hysteria 选项
├── hysteria2.go           # Hysteria2 选项
├── inbound.go             # 入站选项
├── multiplex.go           # 多路复用选项
├── naive.go               # NaiveProxy 选项
├── ntp.go                 # NTP 选项
├── options.go             # 主配置选项
├── outbound.go            # 出站选项
├── platform.go            # 平台选项
├── redir.go               # 重定向选项
├── resolved.go            # 已解析选项
├── route.go               # 路由选项
├── rule_action.go         # 规则动作选项
├── rule_dns.go            # DNS 规则选项
├── rule_set.go            # 规则集选项
├── rule.go                # 规则选项
├── service.go             # 服务选项
├── shadowsocks.go         # Shadowsocks 选项
├── shadowsocksr.go        # ShadowsocksR 选项
├── shadowtls.go           # ShadowTLS 选项
├── simple.go              # 简单协议选项
├── ssh.go                 # SSH 选项
├── ssmapi.go              # SSM API 选项
├── tailscale.go           # Tailscale 选项
├── tls_acme.go            # ACME TLS 选项
├── tls.go                 # TLS 选项
├── tor.go                 # Tor 选项
├── trojan.go              # Trojan 选项
├── tuic.go                # TUIC 选项
├── tun_platform.go        # TUN 平台选项
├── tun.go                 # TUN 选项
├── types.go               # 通用类型
├── udp_over_tcp.go        # UDP over TCP 选项
├── v2ray_transport.go     # V2Ray 传输选项
├── v2ray.go               # V2Ray 选项
├── vless.go               # VLESS 选项
├── vmess.go               # VMess 选项
└── wireguard.go           # WireGuard 选项
```

---

## 2. 主配置结构

### 2.1 Options - 顶层配置

```go
// option/options.go

type Options struct {
    $schema      string                 `json:"$schema,omitempty"`
    Log          *LogOptions            `json:"log,omitempty"`
    DNS          *DNSOptions            `json:"dns,omitempty"`
    NTP          *NTPOptions            `json:"ntp,omitempty"`
    Certificate  *CertificateOptions    `json:"certificate,omitempty"`
    Endpoints    []EndpointOptions      `json:"endpoints,omitempty"`
    Inbounds     []Inbound              `json:"inbounds,omitempty"`
    Outbounds    []Outbound             `json:"outbounds,omitempty"`
    Services     []Service              `json:"services,omitempty"`
    Route        *RouteOptions          `json:"route,omitempty"`
    Experimental *ExperimentalOptions   `json:"experimental,omitempty"`
}
```

---

## 3. 入站选项

### 3.1 通用入站选项

```go
// option/inbound.go

type InboundOptions struct {
    Tag           string     `json:"tag,omitempty"`
    SniffEnabled  bool       `json:"sniff,omitempty"`
    SniffOverrideDestination bool `json:"sniff_override_destination,omitempty"`
    SniffTimeout  Duration   `json:"sniff_timeout,omitempty"`
    DomainStrategy DomainStrategy `json:"domain_strategy,omitempty"`
}

type ListenOptions struct {
    Listen            ListenAddress  `json:"listen,omitempty"`
    ListenPort        uint16         `json:"listen_port,omitempty"`
    TCPFastOpen       bool           `json:"tcp_fast_open,omitempty"`
    TCPMultiPath      bool           `json:"tcp_multi_path,omitempty"`
    UDPFragment       *bool          `json:"udp_fragment,omitempty"`
    UDPFragmentDefault bool
    UDPTimeout        UDPTimeoutCompat `json:"udp_timeout,omitempty"`
    ProxyProtocol     bool             `json:"proxy_protocol,omitempty"`
    ProxyProtocolAcceptNoHeader bool   `json:"proxy_protocol_accept_no_header,omitempty"`
    Detour            string           `json:"detour,omitempty"`
    InboundOptions
}
```

### 3.2 TUN 入站

```go
// option/tun.go

type TunInboundOptions struct {
    InterfaceName       string           `json:"interface_name,omitempty"`
    MTU                 uint32           `json:"mtu,omitempty"`
    Address             badoption.Listable[netip.Prefix] `json:"address,omitempty"`
    AutoRoute           bool             `json:"auto_route,omitempty"`
    StrictRoute         bool             `json:"strict_route,omitempty"`
    RouteAddress        badoption.Listable[netip.Prefix] `json:"route_address,omitempty"`
    RouteExcludeAddress badoption.Listable[netip.Prefix] `json:"route_exclude_address,omitempty"`
    RouteAddressSet     badoption.Listable[string] `json:"route_address_set,omitempty"`
    RouteExcludeAddressSet badoption.Listable[string] `json:"route_exclude_address_set,omitempty"`
    IncludeInterface    badoption.Listable[string] `json:"include_interface,omitempty"`
    ExcludeInterface    badoption.Listable[string] `json:"exclude_interface,omitempty"`
    IncludeUID          badoption.Listable[uint32] `json:"include_uid,omitempty"`
    IncludeUIDRange     badoption.Listable[string] `json:"include_uid_range,omitempty"`
    ExcludeUID          badoption.Listable[uint32] `json:"exclude_uid,omitempty"`
    ExcludeUIDRange     badoption.Listable[string] `json:"exclude_uid_range,omitempty"`
    IncludeAndroidUser  badoption.Listable[int]    `json:"include_android_user,omitempty"`
    IncludePackage      badoption.Listable[string] `json:"include_package,omitempty"`
    ExcludePackage      badoption.Listable[string] `json:"exclude_package,omitempty"`
    EndpointIndependentNat bool `json:"endpoint_independent_nat,omitempty"`
    UDPTimeout             UDPTimeoutCompat `json:"udp_timeout,omitempty"`
    Stack                  string   `json:"stack,omitempty"`  // system / gvisor / lwip
    Platform               *TunPlatformOptions `json:"platform,omitempty"`
    InboundOptions
}
```

### 3.3 Shadowsocks 入站

```go
// option/shadowsocks.go

type ShadowsocksInboundOptions struct {
    ListenOptions
    Method              string                    `json:"method"`
    Password            string                    `json:"password,omitempty"`
    Users               []ShadowsocksUser         `json:"users,omitempty"`
    Destinations        []ShadowsocksDestination  `json:"destinations,omitempty"` // Relay
    Multiplex           *InboundMultiplexOptions  `json:"multiplex,omitempty"`
}

type ShadowsocksUser struct {
    Name     string `json:"name,omitempty"`
    Password string `json:"password"`
}
```

---

## 4. 出站选项

### 4.1 通用出站选项

```go
// option/outbound.go

type DialerOptions struct {
    Detour              string            `json:"detour,omitempty"`
    BindInterface       string            `json:"bind_interface,omitempty"`
    Inet4BindAddress    *ListenAddress    `json:"inet4_bind_address,omitempty"`
    Inet6BindAddress    *ListenAddress    `json:"inet6_bind_address,omitempty"`
    ProtectPath         string            `json:"protect_path,omitempty"`
    RoutingMark         FwMark            `json:"routing_mark,omitempty"`
    ReuseAddr           bool              `json:"reuse_addr,omitempty"`
    ConnectTimeout      Duration          `json:"connect_timeout,omitempty"`
    TCPFastOpen         bool              `json:"tcp_fast_open,omitempty"`
    TCPMultiPath        bool              `json:"tcp_multi_path,omitempty"`
    UDPFragment         *bool             `json:"udp_fragment,omitempty"`
    DomainStrategy      DomainStrategy    `json:"domain_strategy,omitempty"`
    FallbackDelay       Duration          `json:"fallback_delay,omitempty"`
    NetworkStrategy     *NetworkStrategy  `json:"network_strategy,omitempty"`
    NetworkType         badoption.Listable[InterfaceType] `json:"network_type,omitempty"`
    FallbackNetworkType badoption.Listable[InterfaceType] `json:"fallback_network_type,omitempty"`
    IsWireGuardListener bool
}

type ServerOptions struct {
    Server     string `json:"server"`
    ServerPort uint16 `json:"server_port"`
}
```

### 4.2 Shadowsocks 出站

```go
// option/shadowsocks.go

type ShadowsocksOutboundOptions struct {
    DialerOptions
    ServerOptions
    Method      string                    `json:"method"`
    Password    string                    `json:"password"`
    Plugin      string                    `json:"plugin,omitempty"`
    PluginOptions string                  `json:"plugin_opts,omitempty"`
    Network     NetworkList               `json:"network,omitempty"`
    UDPOverTCP  *UDPOverTCPOptions        `json:"udp_over_tcp,omitempty"`
    Multiplex   *OutboundMultiplexOptions `json:"multiplex,omitempty"`
}
```

### 4.3 VMess/VLESS 出站

```go
// option/vmess.go

type VMessOutboundOptions struct {
    DialerOptions
    ServerOptions
    UUID                string                     `json:"uuid"`
    Security            string                     `json:"security,omitempty"`
    AlterId             int                        `json:"alter_id,omitempty"`
    GlobalPadding       bool                       `json:"global_padding,omitempty"`
    AuthenticatedLength bool                       `json:"authenticated_length,omitempty"`
    Network             NetworkList                `json:"network,omitempty"`
    TLS                 *OutboundTLSOptions        `json:"tls,omitempty"`
    PacketEncoding      string                     `json:"packet_encoding,omitempty"`
    Multiplex           *OutboundMultiplexOptions  `json:"multiplex,omitempty"`
    Transport           *V2RayTransportOptions     `json:"transport,omitempty"`
}

// option/vless.go

type VLESSOutboundOptions struct {
    DialerOptions
    ServerOptions
    UUID       string                     `json:"uuid"`
    Flow       string                     `json:"flow,omitempty"`
    Network    NetworkList                `json:"network,omitempty"`
    TLS        *OutboundTLSOptions        `json:"tls,omitempty"`
    Multiplex  *OutboundMultiplexOptions  `json:"multiplex,omitempty"`
    Transport  *V2RayTransportOptions     `json:"transport,omitempty"`
}
```

---

## 5. DNS 选项

```go
// option/dns.go

type DNSOptions struct {
    Servers            []DNSServerOptions   `json:"servers,omitempty"`
    Rules              []DNSRule            `json:"rules,omitempty"`
    Final              string               `json:"final,omitempty"`
    ReverseMapping     bool                 `json:"reverse_mapping,omitempty"`
    FakeIP             *DNSFakeIPOptions    `json:"fakeip,omitempty"`
    Strategy           DomainStrategy       `json:"strategy,omitempty"`
    DisableCache       bool                 `json:"disable_cache,omitempty"`
    DisableExpire      bool                 `json:"disable_expire,omitempty"`
    IndependentCache   bool                 `json:"independent_cache,omitempty"`
    CacheCapacity      uint32               `json:"cache_capacity,omitempty"`
    ClientSubnet       *AddrPrefix          `json:"client_subnet,omitempty"`
}

type DNSServerOptions struct {
    Tag                 string          `json:"tag,omitempty"`
    Address             string          `json:"address"`
    AddressResolver     string          `json:"address_resolver,omitempty"`
    AddressStrategy     DomainStrategy  `json:"address_strategy,omitempty"`
    AddressFallbackDelay Duration       `json:"address_fallback_delay,omitempty"`
    Detour              string          `json:"detour,omitempty"`
    ClientSubnet        *AddrPrefix     `json:"client_subnet,omitempty"`
}

type DNSFakeIPOptions struct {
    Enabled    bool        `json:"enabled,omitempty"`
    Inet4Range *AddrPrefix `json:"inet4_range,omitempty"`
    Inet6Range *AddrPrefix `json:"inet6_range,omitempty"`
}
```

---

## 6. 路由选项

```go
// option/route.go

type RouteOptions struct {
    GeoIP                *GeoIPOptions            `json:"geoip,omitempty"`
    Geosite              *GeositeOptions          `json:"geosite,omitempty"`
    Rules                []Rule                   `json:"rules,omitempty"`
    RuleSet              []RuleSet                `json:"rule_set,omitempty"`
    Final                string                   `json:"final,omitempty"`
    FindProcess          bool                     `json:"find_process,omitempty"`
    AutoDetectInterface  bool                     `json:"auto_detect_interface,omitempty"`
    OverrideAndroidVPN   bool                     `json:"override_android_vpn,omitempty"`
    DefaultInterface     string                   `json:"default_interface,omitempty"`
    DefaultMark          FwMark                   `json:"default_mark,omitempty"`
}
```

---

## 7. 规则选项

```go
// option/rule.go

type Rule struct {
    Type           string           `json:"type,omitempty"`
    DefaultOptions DefaultRule      `json:"-"`
    LogicalOptions LogicalRule      `json:"-"`
}

type DefaultRule struct {
    // 匹配条件
    Inbound            badoption.Listable[string] `json:"inbound,omitempty"`
    IPVersion          int                        `json:"ip_version,omitempty"`
    Network            badoption.Listable[string] `json:"network,omitempty"`
    AuthUser           badoption.Listable[string] `json:"auth_user,omitempty"`
    Protocol           badoption.Listable[string] `json:"protocol,omitempty"`
    Client             badoption.Listable[string] `json:"client,omitempty"`
    Domain             badoption.Listable[string] `json:"domain,omitempty"`
    DomainSuffix       badoption.Listable[string] `json:"domain_suffix,omitempty"`
    DomainKeyword      badoption.Listable[string] `json:"domain_keyword,omitempty"`
    DomainRegex        badoption.Listable[string] `json:"domain_regex,omitempty"`
    Geosite            badoption.Listable[string] `json:"geosite,omitempty"`
    SourceGeoIP        badoption.Listable[string] `json:"source_geoip,omitempty"`
    GeoIP              badoption.Listable[string] `json:"geoip,omitempty"`
    SourceIPCIDR       badoption.Listable[string] `json:"source_ip_cidr,omitempty"`
    SourceIPIsPrivate  bool                       `json:"source_ip_is_private,omitempty"`
    IPCIDR             badoption.Listable[string] `json:"ip_cidr,omitempty"`
    IPIsPrivate        bool                       `json:"ip_is_private,omitempty"`
    SourcePort         badoption.Listable[uint16] `json:"source_port,omitempty"`
    SourcePortRange    badoption.Listable[string] `json:"source_port_range,omitempty"`
    Port               badoption.Listable[uint16] `json:"port,omitempty"`
    PortRange          badoption.Listable[string] `json:"port_range,omitempty"`
    ProcessName        badoption.Listable[string] `json:"process_name,omitempty"`
    ProcessPath        badoption.Listable[string] `json:"process_path,omitempty"`
    ProcessPathRegex   badoption.Listable[string] `json:"process_path_regex,omitempty"`
    PackageName        badoption.Listable[string] `json:"package_name,omitempty"`
    User               badoption.Listable[string] `json:"user,omitempty"`
    UserID             badoption.Listable[int32]  `json:"user_id,omitempty"`
    ClashMode          string                     `json:"clash_mode,omitempty"`
    WIFISSID           badoption.Listable[string] `json:"wifi_ssid,omitempty"`
    WIFIBSSID          badoption.Listable[string] `json:"wifi_bssid,omitempty"`
    RuleSet            badoption.Listable[string] `json:"rule_set,omitempty"`
    Invert             bool                       `json:"invert,omitempty"`
    
    // 动作
    RuleAction
}

type LogicalRule struct {
    Mode  string `json:"mode"`        // and / or 
    Rules []DefaultRule `json:"rules"`
    Invert bool `json:"invert,omitempty"`
    RuleAction
}
```

---

## 8. TLS 选项

```go
// option/tls.go

type OutboundTLSOptions struct {
    Enabled         bool                      `json:"enabled,omitempty"`
    DisableSNI      bool                      `json:"disable_sni,omitempty"`
    ServerName      string                    `json:"server_name,omitempty"`
    Insecure        bool                      `json:"insecure,omitempty"`
    ALPN            badoption.Listable[string] `json:"alpn,omitempty"`
    MinVersion      string                    `json:"min_version,omitempty"`
    MaxVersion      string                    `json:"max_version,omitempty"`
    CipherSuites    badoption.Listable[string] `json:"cipher_suites,omitempty"`
    Certificate     badoption.Listable[string] `json:"certificate,omitempty"`
    CertificatePath string                    `json:"certificate_path,omitempty"`
    ECH             *OutboundECHOptions       `json:"ech,omitempty"`
    UTLS            *OutboundUTLSOptions      `json:"utls,omitempty"`
    Reality         *OutboundRealityOptions   `json:"reality,omitempty"`
}

type OutboundUTLSOptions struct {
    Enabled     bool   `json:"enabled,omitempty"`
    Fingerprint string `json:"fingerprint,omitempty"`
}

type OutboundRealityOptions struct {
    Enabled   bool   `json:"enabled,omitempty"`
    PublicKey string `json:"public_key"`
    ShortID   string `json:"short_id,omitempty"`
}
```

---

## 9. 实验性选项

```go
// option/experimental.go

type ExperimentalOptions struct {
    CacheFile *CacheFileOptions `json:"cache_file,omitempty"`
    ClashAPI  *ClashAPIOptions  `json:"clash_api,omitempty"`
    V2RayAPI  *V2RayAPIOptions  `json:"v2ray_api,omitempty"`
    Debug     *DebugOptions     `json:"debug,omitempty"`
}

type ClashAPIOptions struct {
    ExternalController       string `json:"external_controller,omitempty"`
    ExternalUI               string `json:"external_ui,omitempty"`
    ExternalUIDownloadURL    string `json:"external_ui_download_url,omitempty"`
    ExternalUIDownloadDetour string `json:"external_ui_download_detour,omitempty"`
    Secret                   string `json:"secret,omitempty"`
    DefaultMode              string `json:"default_mode,omitempty"`
    StoreMode                bool   `json:"store_mode,omitempty"`
    StoreSelected            bool   `json:"store_selected,omitempty"`
    StoreFakeIP              bool   `json:"store_fakeip,omitempty"`
    CacheFile                string `json:"cache_file,omitempty"`  // Deprecated
    CacheID                  string `json:"cache_id,omitempty"`
}
```

---

## 10. 类型辅助

```go
// option/types.go

type Duration time.Duration           // JSON: "30s", "1m30s"
type DomainStrategy C.DomainStrategy  // prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only
type NetworkList []string             // ["tcp", "udp"]
type ListenAddress netip.Addr

// JSON 序列化/反序列化实现
func (d *Duration) UnmarshalJSON(bytes []byte) error
func (d Duration) MarshalJSON() ([]byte, error)
```
