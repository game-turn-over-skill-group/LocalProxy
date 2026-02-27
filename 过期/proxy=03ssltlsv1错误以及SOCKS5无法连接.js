const net = require('net');
const dgram = require('dgram');
const { URL } = require('url'); // 新版 URL API
const { EventEmitter } = require('events');

// ===================== 核心配置（可自定义） =====================
const CONFIG = {
  // 同时监听的多个地址（支持 IPv4+IPv6 组合）
  listenHosts: ['0.0.0.0', '::'],
  // 🔥 改用非特权端口（1080 是代理常用端口，避免 22/80 等系统端口）
  listenPort: 22,
  // UDP 端口范围（SOCKS5 UDP ASSOCIATE 使用）
  udpPortRange: {
    min: 6811,
    max: 6922
  },
  // SOCKS5 UDP 包计数阈值（达到该数量后更换端口）
  udpPacketThreshold: 5
};

// ===================== 工具函数 =====================
/**
 * 解析监听地址（处理 IPv6 方括号，如 [::1] → ::1）
 * @param {string} host - 原始地址
 * @returns {string} 解析后的地址
 */
function parseListenHost(host) {
  return host.replace(/^\[(.*)\]$/, '$1');
}

/**
 * 判断地址类型（IPv4/IPv6）
 * @param {string} host - 解析后的地址
 * @returns {'ipv4'|'ipv6'} 地址类型
 */
function getAddressType(host) {
  return host.includes(':') ? 'ipv6' : 'ipv4';
}

/**
 * 在指定范围内生成随机端口
 * @returns {number} 随机端口
 */
function getRandomUdpPort() {
  const { min, max } = CONFIG.udpPortRange;
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * 检查端口是否在合法范围
 * @param {number} port - 端口号
 * @returns {boolean} 是否合法
 */
function isValidPort(port) {
  return port >= 1 && port <= 65535;
}

// ===================== UDP 连接管理器（核心逻辑） =====================
class UdpConnectionManager extends EventEmitter {
  constructor() {
    super();
    this.udpSockets = new Map(); // key: clientId, value: { socket, packetCount, remoteInfo }
  }

  /**
   * 创建/重建 UDP Socket（自动选择端口范围）
   * @param {object} remoteInfo - 远端信息（IP/端口）
   * @param {string} clientId - 客户端唯一标识
   * @returns {dgram.Socket} UDP Socket
   */
  createUdpSocket(remoteInfo, clientId) {
    // 关闭旧的 Socket（如果存在）
    if (this.udpSockets.has(clientId)) {
      const oldSocket = this.udpSockets.get(clientId).socket;
      oldSocket.close();
      this.udpSockets.delete(clientId);
    }

    // 创建新 Socket（支持 IPv4/IPv6）
    const socketType = remoteInfo.family === 'IPv6' ? 'udp6' : 'udp4';
    const udpSocket = dgram.createSocket(socketType);
    const packetCount = 0;

    // 绑定随机端口（在指定范围）
    const bindPort = getRandomUdpPort();
    udpSocket.bind(bindPort, (err) => {
      if (err) {
        console.error(`UDP 端口 ${bindPort} 绑定失败：`, err.message);
        // 绑定失败则重新生成端口
        this.createUdpSocket(remoteInfo, clientId);
        return;
      }
      console.log(`UDP Socket 已绑定：${socketType} ${udpSocket.address().address}:${bindPort}`);
    });

    // 监听 UDP 消息
    udpSocket.on('message', (msg, rinfo) => {
      const current = this.udpSockets.get(clientId);
      if (!current) return;

      // 包计数 +1
      current.packetCount += 1;
      this.emit('udpMessage', msg, rinfo, clientId);

      // 达到阈值则重建 Socket（更换端口）
      if (current.packetCount >= CONFIG.udpPacketThreshold) {
        console.log(`客户端 ${clientId} UDP 包达到 ${CONFIG.udpPacketThreshold} 个，更换端口`);
        this.createUdpSocket(remoteInfo, clientId);
      }
    });

    // 错误处理
    udpSocket.on('error', (err) => {
      console.error(`UDP Socket 错误：`, err.message);
      udpSocket.close();
    });

    // 保存 Socket 信息
    this.udpSockets.set(clientId, {
      socket: udpSocket,
      packetCount,
      remoteInfo
    });

    return udpSocket;
  }

  /**
   * 关闭客户端的 UDP Socket
   * @param {string} clientId - 客户端唯一标识
   */
  closeClientUdp(clientId) {
    if (this.udpSockets.has(clientId)) {
      this.udpSockets.get(clientId).socket.close();
      this.udpSockets.delete(clientId);
    }
  }
}

// 初始化 UDP 管理器
const udpManager = new UdpConnectionManager();

// ===================== SOCKS5 代理实现 =====================
/**
 * 处理 SOCKS5 握手
 * @param {net.Socket} socket - 客户端连接
 */
function handleSocks5(socket) {
  const clientId = `${socket.remoteAddress}:${socket.remotePort}`;
  let stage = 'HANDSHAKE'; // 状态：HANDSHAKE → AUTH → REQUEST → CONNECT/UDP

  // 握手阶段（版本 + 认证方法）
  socket.on('data', (data) => {
    try {
      switch (stage) {
        case 'HANDSHAKE':
          // SOCKS5 握手格式：VER(1) + NMETHODS(1) + METHODS(N)
          if (data[0] !== 0x05) {
            socket.end(Buffer.from([0x05, 0xFF])); // 不支持的版本
            return;
          }
          // 无需认证（0x00）
          socket.write(Buffer.from([0x05, 0x00]));
          stage = 'REQUEST';
          break;

        case 'REQUEST':
          // SOCKS5 请求格式：VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR + DST.PORT
          const ver = data[0];
          const cmd = data[1];
          const atyp = data[3];

          if (ver !== 0x05) {
            socket.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
            return;
          }

          // 解析目标地址
          let dstHost, dstPort, offset = 4;
          switch (atyp) {
            case 0x01: // IPv4
              dstHost = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
              offset += 4;
              break;
            case 0x03: // 域名
              const domainLen = data[4];
              dstHost = data.toString('utf8', 5, 5 + domainLen);
              offset += 1 + domainLen;
              break;
            case 0x04: // IPv6
              dstHost = data.slice(4, 20).toString('hex').match(/.{1,4}/g).join(':');
              offset += 16;
              break;
            default:
              socket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
              return;
          }
          dstPort = data.readUInt16BE(offset);

          // 处理不同命令
          switch (cmd) {
            case 0x01: // CONNECT（TCP）
              stage = 'CONNECT';
              handleSocks5Connect(socket, dstHost, dstPort);
              break;
            case 0x03: // UDP ASSOCIATE（UDP）
              stage = 'UDP';
              handleSocks5Udp(socket, clientId);
              break;
            default:
              socket.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
              return;
          }
          break;
      }
    } catch (err) {
      console.error(`SOCKS5 处理错误：`, err.message);
      socket.destroy();
    }
  });

  // 连接关闭时清理 UDP Socket
  socket.on('close', () => {
    udpManager.closeClientUdp(clientId);
  });

  // 错误处理
  socket.on('error', (err) => {
    console.error(`客户端 ${clientId} 错误：`, err.message);
    socket.destroy();
  });
}

/**
 * 处理 SOCKS5 CONNECT 命令（TCP 代理）
 * @param {net.Socket} socket - 客户端连接
 * @param {string} host - 目标主机
 * @param {number} port - 目标端口
 */
function handleSocks5Connect(socket, host, port) {
  // 创建到目标的连接（支持 IPv4/IPv6）
  const targetSocket = net.connect({
    host,
    port,
    family: host.includes(':') ? 6 : 4 // IPv6 地址包含 :
  });

  // 连接成功响应
  targetSocket.on('connect', () => {
    // 响应格式：VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR + BND.PORT
    const resp = Buffer.alloc(10);
    resp[0] = 0x05; // VER
    resp[1] = 0x00; // REP（成功）
    resp[2] = 0x00; // RSV
    resp[3] = 0x01; // ATYP（IPv4）
    // BND.ADDR（监听地址）
    const localAddr = socket.localAddress;
    const ipParts = localAddr.includes(':') ? [] : localAddr.split('.').map(Number);
    resp.writeUInt8(ipParts[0] || 0, 4);
    resp.writeUInt8(ipParts[1] || 0, 5);
    resp.writeUInt8(ipParts[2] || 0, 6);
    resp.writeUInt8(ipParts[3] || 0, 7);
    // BND.PORT（随机端口）
    resp.writeUInt16BE(targetSocket.localPort, 8);
    socket.write(resp);

    // 双向数据转发
    socket.pipe(targetSocket);
    targetSocket.pipe(socket);
  });

  // 连接失败响应
  targetSocket.on('error', (err) => {
    console.error(`TCP 连接 ${host}:${port} 失败：`, err.message);
    const resp = Buffer.from([0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    socket.end(resp);
  });

  // 关闭时清理
  socket.on('close', () => targetSocket.destroy());
  targetSocket.on('close', () => socket.destroy());
}

/**
 * 处理 SOCKS5 UDP ASSOCIATE 命令（UDP 代理）
 * @param {net.Socket} socket - 客户端连接
 * @param {string} clientId - 客户端唯一标识
 */
function handleSocks5Udp(socket, clientId) {
  // 创建 UDP Socket
  const udpSocket = udpManager.createUdpSocket({
    family: socket.remoteFamily === 'IPv6' ? 'IPv6' : 'IPv4'
  }, clientId);

  // 获取 UDP 绑定的端口和地址
  const udpAddr = udpSocket.address();
  const resp = Buffer.alloc(10);
  resp[0] = 0x05; // VER
  resp[1] = 0x00; // REP（成功）
  resp[2] = 0x00; // RSV
  resp[3] = udpAddr.family === 'IPv6' ? 0x04 : 0x01; // ATYP

  // 填充绑定地址
  if (udpAddr.family === 'IPv4') {
    const ipParts = udpAddr.address.split('.').map(Number);
    resp.writeUInt8(ipParts[0], 4);
    resp.writeUInt8(ipParts[1], 5);
    resp.writeUInt8(ipParts[2], 6);
    resp.writeUInt8(ipParts[3], 7);
  } else {
    // IPv6 地址转 16 字节 Buffer
    const ipBuffer = Buffer.from(udpAddr.address.split(':').map(part => parseInt(part || '0', 16)), 'hex');
    ipBuffer.copy(resp, 4, 0, 16);
  }

  // 填充绑定端口
  resp.writeUInt16BE(udpAddr.port, 8);
  socket.write(resp);

  // 监听 UDP 消息并转发给客户端
  udpManager.on('udpMessage', (msg, rinfo, id) => {
    if (id !== clientId) return;
    // SOCKS5 UDP 包格式：RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
    const atyp = rinfo.family === 'IPv6' ? 0x04 : 0x01;
    let addrBuffer;
    if (atyp === 0x01) {
      addrBuffer = Buffer.from(rinfo.address.split('.').map(Number));
    } else {
      addrBuffer = Buffer.from(rinfo.address.split(':').map(part => parseInt(part || '0', 16)), 'hex');
    }
    const portBuffer = Buffer.alloc(2);
    portBuffer.writeUInt16BE(rinfo.port, 0);

    // 组装 UDP 响应包
    const udpPacket = Buffer.concat([
      Buffer.from([0x00, 0x00, 0x00]), // RSV + FRAG
      Buffer.from([atyp]), // ATYP
      addrBuffer, // DST.ADDR
      portBuffer, // DST.PORT
      msg // DATA
    ]);
    socket.write(udpPacket);
  });
}

// ===================== HTTP 代理实现（修复核心问题） =====================
/**
 * 处理 HTTP 代理
 * @param {net.Socket} socket - 客户端连接
 */
function handleHttp(socket) {
  const clientId = `${socket.remoteAddress}:${socket.remotePort}`;
  
  // 🔥 增加数据分片处理，避免只读取部分请求
  let requestBuffer = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    try {
      requestBuffer = Buffer.concat([requestBuffer, chunk]);
      
      // 确保读取完整的请求头（以 \r\n\r\n 为结束符）
      const headerEnd = requestBuffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return; // 未读取到完整请求头，等待后续数据

      const requestData = requestBuffer.toString('utf8');
      const firstLine = requestData.split('\r\n')[0].trim();
      
      // 🔥 校验请求首行格式
      if (!firstLine) {
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        socket.destroy();
        return;
      }

      const [method, targetUrl, version] = firstLine.split(' ');
      
      // 🔥 校验核心参数
      if (!method || !targetUrl || !version) {
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        socket.destroy();
        return;
      }

      if (method === 'CONNECT') {
        // HTTPS CONNECT 方法（隧道代理）
        const [host, port] = targetUrl.split(':');
        const targetPort = port || 443;

        // 🔥 校验目标主机
        if (!host) {
          socket.write(`${version} 400 Bad Request\r\n\r\n`);
          socket.destroy();
          return;
        }

        // 创建到目标的 TCP 连接
        const targetSocket = net.connect({
          host,
          port: targetPort,
          family: host.includes(':') ? 6 : 4
        });

        // 连接成功响应
        targetSocket.on('connect', () => {
          socket.write(`${version} 200 Connection Established\r\n\r\n`);
          socket.pipe(targetSocket);
          targetSocket.pipe(socket);
        });

        // 连接失败响应
        targetSocket.on('error', (err) => {
          console.error(`HTTPS 连接 ${host}:${targetPort} 失败：`, err.message);
          socket.write(`${version} 503 Service Unavailable\r\n\r\n`);
          socket.destroy();
        });

        // 关闭时清理
        socket.on('close', () => targetSocket.destroy());
        targetSocket.on('close', () => socket.destroy());
      } else {
        // 普通 HTTP 代理（🔥 替换为新版 URL API）
        let parsedUrl;
        try {
          // 兼容相对路径（补充协议头）
          parsedUrl = new URL(targetUrl.startsWith('http') ? targetUrl : `http://${targetUrl}`);
        } catch (err) {
          console.error(`URL 解析失败：`, err.message);
          socket.write(`${version} 400 Bad Request\r\n\r\n`);
          socket.destroy();
          return;
        }

        const host = parsedUrl.hostname;
        const port = parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80);

        // 重写请求头（去掉代理相关）
        const reqData = requestData.replace(firstLine, `${method} ${parsedUrl.pathname + parsedUrl.search} ${version}`);
        const targetSocket = net.connect({ host, port, family: host.includes(':') ? 6 : 4 });

        // 转发请求
        targetSocket.write(reqData);
        targetSocket.pipe(socket);

        // 错误处理
        targetSocket.on('error', (err) => {
          console.error(`HTTP 连接 ${host}:${port} 失败：`, err.message);
          socket.write(`${version} 503 Service Unavailable\r\n\r\n`);
          socket.destroy();
        });

        // 关闭时清理
        socket.on('close', () => targetSocket.destroy());
        targetSocket.on('close', () => socket.destroy());
      }
    } catch (err) {
      console.error(`HTTP 代理处理错误：`, err.message);
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      socket.destroy();
    }
  });

  // 错误处理
  socket.on('error', (err) => {
    console.error(`HTTP 客户端 ${clientId} 错误：`, err.message);
    socket.destroy();
  });
}

// ===================== 多地址监听核心实现 =====================
/**
 * 创建单个代理服务器实例（IPv4/IPv6）
 * @param {string} host - 监听地址（解析后的）
 * @param {number} port - 监听端口
 * @returns {net.Server} 服务器实例
 */
function createProxyServer(host, port) {
  const addressType = getAddressType(host);
  const server = net.createServer((socket) => {
    // 🔥 优化协议识别延迟，减少错误
    setTimeout(() => {
      const firstByte = socket.read(1);
      if (!firstByte) {
        socket.destroy();
        return;
      }

      // 还原读取的字节
      socket.unshift(firstByte);

      // SOCKS5 第一个字节是 0x05，否则是 HTTP
      if (firstByte[0] === 0x05) {
        handleSocks5(socket);
      } else {
        handleHttp(socket);
      }
    }, 50); // 缩短延迟到 50ms
  });

  // 监听配置（关键：IPv6 实例需设置 ipv6Only: false）
  const listenOptions = {
    port,
    host,
    ipv6Only: addressType === 'ipv6' ? false : undefined // 允许 IPv6 实例兼容 IPv4
  };

  // 启动监听
  server.listen(listenOptions, () => {
    const addr = server.address();
    const displayHost = addr.family === 'IPv6' ? `[${addr.address}]` : addr.address;
    console.log(`✅ 代理服务器实例启动：${displayHost}:${addr.port} (${addressType.toUpperCase()})`);
  });

  // 服务器错误处理
  server.on('error', (err) => {
    const displayHost = host.includes(':') ? `[${host}]` : host;
    if (err.code === 'EADDRINUSE') {
      console.error(`❌ 地址 ${displayHost}:${port} 已被占用，无法监听`);
    } else {
      console.error(`❌ 服务器实例 ${displayHost}:${port} 启动失败：`, err.message);
    }
  });

  return server;
}

/**
 * 启动多地址代理服务器（同时监听 IPv4+IPv6）
 */
function startMultiAddressProxyServer() {
  console.log(`🚀 启动多地址代理服务器，端口：${CONFIG.listenPort}`);
  console.log(`📌 监听地址列表：${CONFIG.listenHosts.map(h => h.includes(':') ? `[${h}]` : h).join(', ')}`);
  
  // 为每个地址创建独立的服务器实例
  CONFIG.listenHosts.forEach((rawHost) => {
    const host = parseListenHost(rawHost);
    createProxyServer(host, CONFIG.listenPort);
  });
}

// 启动多地址服务器
startMultiAddressProxyServer();