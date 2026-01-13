# 命令行工具 (cmd/)

## 1. 目录结构

```
cmd/
├── internal/              # 内部工具
└── sing-box/              # 主命令
    ├── main.go            # 入口
    ├── cmd.go             # 根命令
    ├── cmd_check.go       # 配置检查
    ├── cmd_format.go      # 配置格式化
    ├── cmd_generate.go    # 生成命令
    ├── cmd_generate_ech.go        # ECH 密钥生成
    ├── cmd_generate_tls.go        # TLS 证书生成
    ├── cmd_generate_vapid.go      # VAPID 密钥生成
    ├── cmd_generate_wireguard.go  # WireGuard 密钥生成
    ├── cmd_geoip.go       # GeoIP 命令
    ├── cmd_geoip_export.go
    ├── cmd_geoip_list.go
    ├── cmd_geoip_lookup.go
    ├── cmd_geosite.go     # GeoSite 命令
    ├── cmd_geosite_export.go
    ├── cmd_geosite_list.go
    ├── cmd_geosite_lookup.go
    ├── cmd_geosite_matcher.go
    ├── cmd_merge.go       # 配置合并
    ├── cmd_rule_set.go    # 规则集命令
    ├── cmd_rule_set_compile.go
    ├── cmd_rule_set_convert.go
    ├── cmd_rule_set_decompile.go
    ├── cmd_rule_set_format.go
    ├── cmd_rule_set_match.go
    ├── cmd_rule_set_merge.go
    ├── cmd_rule_set_upgrade.go
    ├── cmd_run.go         # 运行命令
    ├── cmd_tools.go       # 工具命令
    ├── cmd_tools_connect.go
    ├── cmd_tools_fetch.go
    ├── cmd_tools_fetch_http3.go
    ├── cmd_tools_synctime.go
    ├── cmd_version.go     # 版本命令
    └── generate_completions.go
```

---

## 2. 命令概览

```
sing-box [command]

Available Commands:
  check       Check configuration
  format      Format configuration
  generate    Generate resources
  geoip       GeoIP tools
  geosite     GeoSite tools
  help        Help about any command
  merge       Merge configurations
  rule-set    Rule set tools
  run         Run service
  tools       Experimental tools
  version     Print current version

Flags:
  -c, --config stringArray   set configuration file path
  -C, --config-directory string   set configuration directory path
  -D, --directory string     set working directory
  -h, --help                 help for sing-box
      --disable-color        disable color output
```

---

## 3. 核心命令

### 3.1 run - 运行服务

```go
// cmd/sing-box/cmd_run.go

var commandRun = &cobra.Command{
    Use:   "run",
    Short: "Run service",
    Run:   run,
}

func init() {
    commandRun.Flags().StringP("config", "c", "", "set configuration file path")
    commandRun.Flags().StringP("config-directory", "C", "", "set configuration directory path")
    commandRun.Flags().StringP("directory", "D", "", "set working directory")
}

func run(cmd *cobra.Command, args []string) {
    // 1. 读取配置
    options, err := readConfig()
    
    // 2. 创建 Box 实例
    ctx := box.Context(context.Background(), 
                       include.InboundRegistry(), 
                       include.OutboundRegistry(),
                       include.EndpointRegistry(),
                       include.DNSTransportRegistry(),
                       include.ServiceRegistry())
    
    instance, err := box.New(box.Options{
        Context: ctx,
        Options: options,
    })
    
    // 3. 启动服务
    err = instance.Start()
    
    // 4. 等待信号
    osSignals := make(chan os.Signal, 1)
    signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
    
    for {
        select {
        case signal := <-osSignals:
            switch signal {
            case syscall.SIGHUP:
                // 重载配置
                instance.Close()
                instance, _ = box.New(...)
                instance.Start()
            default:
                // 关闭
                instance.Close()
                return
            }
        }
    }
}
```

### 3.2 check - 配置检查

```go
// cmd/sing-box/cmd_check.go

var commandCheck = &cobra.Command{
    Use:   "check",
    Short: "Check configuration",
    Run:   checkConfiguration,
}

func checkConfiguration(cmd *cobra.Command, args []string) {
    options, err := readConfig()
    if err != nil {
        log.Fatal("read config: ", err)
    }
    
    ctx := box.Context(context.Background(), ...)
    instance, err := box.New(box.Options{
        Context: ctx,
        Options: options,
    })
    if err != nil {
        log.Fatal("create instance: ", err)
    }
    
    instance.Close()
    log.Info("configuration is valid")
}
```

### 3.3 format - 配置格式化

```go
// cmd/sing-box/cmd_format.go

var commandFormat = &cobra.Command{
    Use:   "format",
    Short: "Format configuration",
    Run:   formatConfiguration,
}

func init() {
    commandFormat.Flags().BoolP("write", "w", false, "write result to source file")
}

func formatConfiguration(cmd *cobra.Command, args []string) {
    // 读取并重新格式化 JSON 配置
    configPath := args[0]
    content, _ := os.ReadFile(configPath)
    
    var options option.Options
    json.Unmarshal(content, &options)
    
    formatted, _ := json.MarshalIndent(options, "", "  ")
    
    if write {
        os.WriteFile(configPath, formatted, 0644)
    } else {
        fmt.Println(string(formatted))
    }
}
```

### 3.4 merge - 配置合并

```go
// cmd/sing-box/cmd_merge.go

var commandMerge = &cobra.Command{
    Use:   "merge [output]",
    Short: "Merge configurations",
    Run:   mergeConfigurations,
}

func mergeConfigurations(cmd *cobra.Command, args []string) {
    // 合并多个配置文件
    // - 支持 include 指令
    // - 支持目录扫描
    // - 合并 inbounds, outbounds, rules 等数组
}
```

---

## 4. 生成命令

### 4.1 generate tls - TLS 证书

```bash
sing-box generate tls-keypair [flags]

Flags:
      --ca                generate CA certificate
      --duration string   certificate duration (default "8760h")
      --ecdsa-curve string   ECDSA curve (P224, P256, P384, P521)
      --ed25519           use Ed25519
      --host string       certificate host
      --rsa-bits int      RSA key size (default 4096)
```

### 4.2 generate wireguard - WireGuard 密钥

```bash
sing-box generate wireguard-keypair

# 输出
{
  "private_key": "...",
  "public_key": "..."
}
```

### 4.3 generate ech - ECH 密钥

```bash
sing-box generate ech-keypair [flags]

Flags:
      --pq               use post-quantum
      --plain-text       output as plain text
```

---

## 5. GeoIP 工具

```bash
sing-box geoip [command]

Commands:
  export    Export GeoIP as rule-set
  list      List GeoIP categories
  lookup    Lookup IP in GeoIP

# 示例
sing-box geoip lookup 8.8.8.8
# US

sing-box geoip list geoip.db
# CN, US, JP, ...

sing-box geoip export -o cn.srs geoip.db cn
```

---

## 6. GeoSite 工具

```bash
sing-box geosite [command]

Commands:
  export    Export GeoSite as rule-set
  list      List GeoSite categories
  lookup    Lookup domain in GeoSite
  match     Check if domain matches

# 示例
sing-box geosite lookup google.com
# google

sing-box geosite list geosite.db
# google, facebook, twitter, ...

sing-box geosite export -o google.srs geosite.db google
```

---

## 7. 规则集工具

### 7.1 compile - 编译规则集

```bash
sing-box rule-set compile [flags] source.json

# 将 JSON 规则集编译为二进制 .srs 格式
```

### 7.2 decompile - 反编译规则集

```bash
sing-box rule-set decompile [flags] source.srs

# 将二进制规则集反编译为 JSON
```

### 7.3 convert - 转换规则集

```bash
sing-box rule-set convert [flags] source

Flags:
      --type string     source type (clash-rules, adguard)
      --output string   output file
```

### 7.4 match - 测试规则集

```bash
sing-box rule-set match [flags] source domain

# 检查域名是否匹配规则集
```

### 7.5 merge - 合并规则集

```bash
sing-box rule-set merge [flags] output source1 source2 ...

# 合并多个规则集
```

### 7.6 upgrade - 升级规则集

```bash
sing-box rule-set upgrade old.srs

# 将旧版规则集升级到新版本
```

---

## 8. 调试工具

### 8.1 tools connect - 连接测试

```bash
sing-box tools connect [flags] address

# 测试 TCP 连接
```

### 8.2 tools fetch - HTTP 请求

```bash
sing-box tools fetch [flags] url

Flags:
      --http3            use HTTP/3
      --method string    HTTP method (default "GET")
      --header strings   HTTP headers
```

### 8.3 tools synctime - 时间同步

```bash
sing-box tools synctime [flags]

# 通过 NTP 同步系统时间
```

---

## 9. 版本信息

```bash
sing-box version

# 输出
sing-box version 1.12.14

Environment: go1.23.1 darwin/arm64
Tags: with_gvisor,with_quic,with_wireguard,with_utls,with_reality_server,with_clash_api,with_v2ray_api,with_tailscale
Revision: ...
CGO: enabled
```

---

## 10. 配置读取

```go
// cmd/sing-box/cmd.go

func readConfig() (*option.Options, error) {
    var options option.Options
    
    // 1. 从配置文件读取
    for _, path := range configPaths {
        content, err := os.ReadFile(path)
        // 合并配置
    }
    
    // 2. 从目录读取
    if configDirectory != "" {
        entries, _ := os.ReadDir(configDirectory)
        for _, entry := range entries {
            if strings.HasSuffix(entry.Name(), ".json") {
                // 读取并合并
            }
        }
    }
    
    return &options, nil
}
```

---

## 11. 信号处理

| 信号 | 行为 |
|------|------|
| `SIGINT` / `SIGTERM` | 优雅关闭 |
| `SIGHUP` | 重载配置 |

```go
// cmd/sing-box/cmd_run.go

for {
    select {
    case signal := <-osSignals:
        switch signal {
        case syscall.SIGHUP:
            log.Info("reloading...")
            instance.Close()
            options, _ := readConfig()
            instance, _ = box.New(options)
            instance.Start()
        default:
            log.Info("shutting down...")
            instance.Close()
            return
        }
    }
}
```
