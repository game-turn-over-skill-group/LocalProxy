



#### HTTP 代理
```cmd
curl -4 -x http://127.0.0.1:1080 https://www.baidu.com -v --tlsv1.2 --insecure
curl -x http://[::1]:1080 https://ipv6.baidu.com -v --tlsv1.2 --insecure
```

#### SOCKS5 代理
```cmd
curl -4 --socks5 127.0.0.1:1080 https://www.baidu.com -v --tlsv1.2 --insecure
curl --socks5 [::1]:1080 https://ipv6.baidu.com -v --tlsv1.2 --insecure
```


启动方式
```bash
node proxy-server.js
```
默认：HTTP+SOCKS5 合并监听 127.0.0.1:1080


命令行参数自定义
```bash
# 监听所有 IPv4 接口
node proxy-server.js --http-host=0.0.0.0 --http-port=1080 --socks5-host=0.0.0.0 --socks5-port=1081

# 监听所有 IPv6 接口
node proxy-server.js --socks5-host=:: --http-host=::

# 仅 IPv6 本机
node proxy-server.js --socks5-host=::1 --http-host=::1

# 自定义 UDP 端口范围和轮换阈值
node proxy-server.js --udp-min=6811 --udp-max=6922 --udp-rotate=5
```

| 核心设计     |
| 功能      | 实现 |
|    :----:     |    :----:   |
|  IPv4/IPv6双栈 | 监听地址支持 127.0.0.1 / 0.0.0.0 / :: / ::1，自动适配 |
|  HTTP 代理	  | 支持普通 HTTP（PIPE 转发）和 HTTPS（CONNECT 隧道），出口连接系统随机分配端口 |
|  SOCKS5 TCP	  | 完整握手，支持 IPv4/IPv6/域名三种地址类型，自动 DNS 解析 |
|  SOCKS5 UDP	  | 创建中继 socket 接收客户端 UDP 包，每发送 5 个包后重新绑定新端口（在 6811-6922 范围内随机选取），旧 socket 立即关闭 |
|  TCP 控制	    | 绑定UDP ASSOCIATE 的 TCP 控制连接断开时，自动清理所有 UDP socket |





##### 项目发起人：rer
##### 项目协作者：豆包、claude











