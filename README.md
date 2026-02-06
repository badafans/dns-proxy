# DNS 拦截与代理管理

一个单文件 Go 程序，提供 DNS 拦截、TCP 代理转发、Web 管理界面、规则管理与统计日志。

## 功能概览

- DNS 拦截：按规则返回指定 IP
- TCP 代理：支持 HTTP/HTTPS 转发
- Web 管理：规则管理、配置管理、实时统计
- 规则导入：从 URL 导入 gfwlist，自动去重并合并

## 快速开始

1. 运行程序

```bash
go run dns-proxy.go
```

或编译后运行：

```bash
go build -o dns-proxy.exe dns-proxy.go
./dns-proxy.exe
```

2. 打开控制台输出的 Web 管理地址  
默认端口为 10000，可用参数 `-port` 修改：

```bash
go run dns-proxy.go -port 10000
```

3. 在“配置管理”中保存配置后启动服务

## 配置说明

配置文件为 `config.json`，首次运行会自动生成。

| 字段 | 说明 |
| --- | --- |
| dns_listen | DNS 监听地址 |
| upstream_dns | 上游 DNS |
| redirect_ip | 拦截返回 IP |
| proxy_listen | 代理监听地址列表 |
| socks5_proxy | 前置代理地址（支持 socks5/http/https） |
| auto_start | 启动时自动启动服务 |

默认配置会使用本机局域网 IP 作为 DNS 监听与拦截返回 IP。

## 规则管理

- 规则文件：`gfwlist.txt`（每行一个域名）
- 导入规则：在“规则管理”中输入 URL 并导入
- 合并去重：导入会与现有规则合并，自动去重与排序
- 规则匹配：支持精确匹配与后缀匹配（如 `example.com` 匹配 `www.example.com`）

导入 gfwlist 时，需要先在“配置管理”中配置前置代理。

## 文件说明

- `dns-proxy.go` 主程序
- `config.json` 配置文件
- `gfwlist.txt` 规则文件

## 运行提示

- 程序启动后会输出可访问的 Web 管理地址
- 如需变更端口，使用 `-port` 参数
