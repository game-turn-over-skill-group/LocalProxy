const net = require('net');
const dgram = require('dgram');
const { URL } = require('url');
const { EventEmitter } = require('events');

// ===================== 核心配置（Windows 适配） =====================
const CONFIG = {
  listenHost: '::', 
  listenPort: 1080,
  udpPortRange: {
    min: 6811,
    max: 6922
  },
  udpPacketThreshold: 5,
  connectTimeout: 15000, // 延长超时到15秒，适配SSL握手
  socketTimeout: 30000,
  debug: true // 开启调试日志
};

// ===================== 工具函数 =====================
function parseListenHost(host) {
  return host.replace(/^\[(.*)\]$/, '$1');
}

function getRandomUdpPort() {
  const { min, max } = CONFIG.udpPortRange;
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// 新增：调试日志函数
function debugLog(type, msg, clientId = 'unknown') {
  if (CONFIG.debug) {
    console.log(`[${new Date().toISOString()}] [${type}] [${clientId}] ${msg}`);
  }
}

// 新增：标准化IPv6地址（修复curl兼容问题）
function normalizeIPv6Address(addr) {
  // 处理Windows下的IPv4映射地址 ::ffff:127.0.0.1 → 127.0.0.1
  if (addr.startsWith('::ffff:')) {
    return addr.replace('::ffff:', '');
  }
  // 补全IPv6零压缩地址
  const parts = addr.split(':');
  const emptyCount = 8 - parts.filter(p => p !== '').length;
  const fullParts = [];
  let zeroInserted = false;
  for (const part of parts) {
    if (part === '' && !zeroInserted) {
      for (let i = 0; i < emptyCount; i++) {
        fullParts.push('0000');
      }
      zeroInserted = true;
    } else if (part !== '') {
      fullParts.push(part.padStart(4, '0'));
    }
  }
  return fullParts.join(':');
}

// ===================== UDP 连接管理器 =====================
class UdpConnectionManager extends EventEmitter {
  constructor() {
    super();
    this.udpSockets = new Map();
  }

  createUdpSocket(remoteInfo, clientId) {
    debugLog('UDP', `创建UDP Socket，客户端：${clientId}，地址族：${remoteInfo.family}`);
    if (this.udpSockets.has(clientId)) {
      debugLog('UDP', `关闭旧UDP Socket，客户端：${clientId}`);
      this.udpSockets.get(clientId).socket.close();
      this.udpSockets.delete(clientId);
    }

    const socketType = remoteInfo.family === 'IPv6' ? 'udp6' : 'udp4';
    const udpSocket = dgram.createSocket(socketType);
    const packetCount = 0;

    const bindPort = getRandomUdpPort();
    udpSocket.bind(bindPort, (err) => {
      if (err) {
        console.error(`[UDP] 端口 ${bindPort} 绑定失败：`, err.message);
        this.createUdpSocket(remoteInfo, clientId);
        return;
      }
      debugLog('UDP', `UDP Socket绑定成功：${socketType} ${udpSocket.address().address}:${bindPort}`, clientId);
    });

    udpSocket.on('message', (msg, rinfo) => {
      const current = this.udpSockets.get(clientId);
      if (!current) return;

      current.packetCount += 1;
      debugLog('UDP', `收到UDP消息，长度：${msg.length}，来源：${rinfo.address}:${rinfo.port}`, clientId);
      this.emit('udpMessage', msg, rinfo, clientId);

      if (current.packetCount >= CONFIG.udpPacketThreshold) {
        debugLog('UDP', `UDP包达到阈值(${CONFIG.udpPacketThreshold})，更换端口`, clientId);
        this.createUdpSocket(remoteInfo, clientId);
      }
    });

    udpSocket.on('error', (err) => {
      console.error(`[UDP] Socket错误：`, err.message);
      udpSocket.close();
    });

    this.udpSockets.set(clientId, {
      socket: udpSocket,
      packetCount,
      remoteInfo
    });

    return udpSocket;
  }

  closeClientUdp(clientId) {
    if (this.udpSockets.has(clientId)) {
      debugLog('UDP', `关闭客户端UDP Socket`, clientId);
      this.udpSockets.get(clientId).socket.close();
      this.udpSockets.delete(clientId);
    }
  }
}

const udpManager = new UdpConnectionManager();

// ===================== SOCKS5 代理实现（全日志 + IPv6修复） =====================
function handleSocks5(socket) {
  const clientId = `${socket.remoteAddress}:${socket.remotePort}`;
  const clientFamily = socket.remoteFamily === 'IPv6' ? 'IPv6' : 'IPv4';
  debugLog('SOCKS5', `新客户端连接，地址族：${clientFamily}`, clientId);
  let stage = 'HANDSHAKE';

  socket.setTimeout(CONFIG.socketTimeout);
  socket.setNoDelay(true); // 禁用Nagle，加速SSL握手
  socket.on('timeout', () => {
    debugLog('SOCKS5', `连接超时`, clientId);
    socket.destroy();
  });

  socket.on('data', (data) => {
    try {
      debugLog('SOCKS5', `收到数据，长度：${data.length}，阶段：${stage}`, clientId);
      switch (stage) {
        case 'HANDSHAKE':
          // SOCKS5 握手格式：VER(1) + NMETHODS(1) + METHODS(N)
          if (data[0] !== 0x05) {
            debugLog('SOCKS5', `不支持的版本：${data[0]}`, clientId);
            socket.end(Buffer.from([0x05, 0xFF]));
            return;
          }
          // 无需认证（0x00）
          debugLog('SOCKS5', `握手成功，返回无需认证`, clientId);
          socket.write(Buffer.from([0x05, 0x00]));
          stage = 'REQUEST';
          break;

        case 'REQUEST':
          // SOCKS5 请求格式：VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR + DST.PORT
          const ver = data[0];
          const cmd = data[1];
          const atyp = data[3];

          if (ver !== 0x05) {
            debugLog('SOCKS5', `请求版本错误：${ver}`, clientId);
            socket.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
            return;
          }

          // 解析目标地址（修复IPv6解析）
          let dstHost, dstPort, offset = 4;
          switch (atyp) {
            case 0x01: // IPv4
              dstHost = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
              offset += 4;
              debugLog('SOCKS5', `解析IPv4目标：${dstHost}`, clientId);
              break;
            case 0x03: // 域名
              const domainLen = data[4];
              dstHost = data.toString('utf8', 5, 5 + domainLen);
              offset += 1 + domainLen;
              debugLog('SOCKS5', `解析域名目标：${dstHost}`, clientId);
              break;
            case 0x04: // IPv6（修复解析逻辑）
              const ipv6Buffer = data.slice(4, 20);
              dstHost = [];
              for (let i = 0; i < 16; i += 2) {
                dstHost.push(ipv6Buffer.readUInt16BE(i).toString(16));
              }
              dstHost = dstHost.join(':');
              offset += 16;
              debugLog('SOCKS5', `解析IPv6目标：${dstHost}`, clientId);
              break;
            default:
              debugLog('SOCKS5', `不支持的地址类型：${atyp}`, clientId);
              socket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
              return;
          }
          dstPort = data.readUInt16BE(offset);
          debugLog('SOCKS5', `目标端口：${dstPort}`, clientId);

          // 处理不同命令
          switch (cmd) {
            case 0x01: // CONNECT（TCP）
              debugLog('SOCKS5', `处理CONNECT命令`, clientId);
              stage = 'CONNECT';
              handleSocks5Connect(socket, dstHost, dstPort, clientId);
              break;
            case 0x03: // UDP ASSOCIATE（UDP）
              debugLog('SOCKS5', `处理UDP ASSOCIATE命令`, clientId);
              stage = 'UDP';
              handleSocks5Udp(socket, clientId);
              break;
            default:
              debugLog('SOCKS5', `不支持的命令：${cmd}`, clientId);
              socket.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
              return;
          }
          break;
      }
    } catch (err) {
      console.error(`[SOCKS5] 处理错误：`, err.message);
      debugLog('SOCKS5', `处理异常：${err.message}`, clientId);
      socket.destroy();
    }
  });

  socket.on('close', () => {
    debugLog('SOCKS5', `客户端连接关闭`, clientId);
    udpManager.closeClientUdp(clientId);
  });

  socket.on('error', (err) => {
    if (err.code !== 'ECONNRESET') {
      console.error(`[SOCKS5] 客户端 ${clientId} 错误：`, err.message);
    }
    debugLog('SOCKS5', `连接错误：${err.message}`, clientId);
    socket.destroy();
  });
}

function handleSocks5Connect(socket, host, port, clientId) {
  debugLog('SOCKS5-CONNECT', `尝试连接目标：${host}:${port}`, clientId);
  // 修复：强制指定地址族，避免解析错误
  const family = host.includes(':') ? 6 : (net.isIP(host) === 6 ? 6 : 4);
  const targetSocket = net.connect({
    host,
    port,
    family,
    timeout: CONFIG.connectTimeout,
    allowHalfOpen: false // 修复SSL半开连接问题
  });

  targetSocket.setTimeout(CONFIG.socketTimeout);
  targetSocket.setNoDelay(true); // 禁用Nagle，加速SSL握手
  targetSocket.on('timeout', () => {
    debugLog('SOCKS5-CONNECT', `目标连接超时`, clientId);
    socket.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    targetSocket.destroy();
  });

  targetSocket.on('connect', () => {
    debugLog('SOCKS5-CONNECT', `目标连接成功：${host}:${port}`, clientId);
    // 构建响应（修复IPv6响应格式）
    const resp = Buffer.alloc(22); // 足够容纳IPv6地址
    resp[0] = 0x05; // VER
    resp[1] = 0x00; // REP（成功）
    resp[2] = 0x00; // RSV
    // 获取本地绑定地址
    const localAddr = socket.localAddress;
    const localFamily = socket.localFamily === 'IPv6' ? 6 : 4;
    
    if (localFamily === 4) {
      resp[3] = 0x01; // ATYP IPv4
      const ipParts = localAddr.replace('::ffff:', '').split('.').map(Number);
      resp.writeUInt8(ipParts[0] || 0, 4);
      resp.writeUInt8(ipParts[1] || 0, 5);
      resp.writeUInt8(ipParts[2] || 0, 6);
      resp.writeUInt8(ipParts[3] || 0, 7);
      resp.writeUInt16BE(targetSocket.localPort, 8);
    } else {
      resp[3] = 0x04; // ATYP IPv6
      // 修复：正确写入IPv6地址到响应
      const normalizedAddr = normalizeIPv6Address(localAddr);
      const ipv6Parts = normalizedAddr.split(':').map(part => parseInt(part, 16));
      let offset = 4;
      for (const part of ipv6Parts) {
        resp.writeUInt16BE(part, offset);
        offset += 2;
      }
      resp.writeUInt16BE(targetSocket.localPort, 20);
    }

    // 发送响应（确保写入完成）
    socket.write(resp, (err) => {
      if (err) {
        debugLog('SOCKS5-CONNECT', `响应发送失败：${err.message}`, clientId);
        socket.destroy();
        targetSocket.destroy();
        return;
      }
      debugLog('SOCKS5-CONNECT', `响应发送成功，开始双向转发`, clientId);
      
      // 双向转发（添加错误日志）
      socket.pipe(targetSocket)
        .on('error', (err) => {
          if (err.code !== 'ECONNRESET') {
            debugLog('SOCKS5-CONNECT', `客户端→目标转发错误：${err.message}`, clientId);
          }
        })
        .on('end', () => debugLog('SOCKS5-CONNECT', `客户端→目标转发结束`, clientId));
      
      targetSocket.pipe(socket)
        .on('error', (err) => {
          if (err.code !== 'ECONNRESET') {
            debugLog('SOCKS5-CONNECT', `目标→客户端转发错误：${err.message}`, clientId);
          }
        })
        .on('end', () => debugLog('SOCKS5-CONNECT', `目标→客户端转发结束`, clientId));
    });
  });

  targetSocket.on('error', (err) => {
    console.error(`[SOCKS5-CONNECT] 连接 ${host}:${port} 失败：`, err.message);
    debugLog('SOCKS5-CONNECT', `目标连接失败：${err.message}`, clientId);
    const resp = Buffer.from([0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    socket.end(resp);
  });

  socket.on('close', () => {
    debugLog('SOCKS5-CONNECT', `客户端关闭，销毁目标连接`, clientId);
    targetSocket.destroy();
  });
  targetSocket.on('close', () => {
    debugLog('SOCKS5-CONNECT', `目标关闭，销毁客户端连接`, clientId);
    socket.destroy();
  });
}

function handleSocks5Udp(socket, clientId) {
  const remoteFamily = socket.remoteFamily === 'IPv6' ? 'IPv6' : 'IPv4';
  debugLog('SOCKS5-UDP', `创建UDP关联，地址族：${remoteFamily}`, clientId);
  const udpSocket = udpManager.createUdpSocket({
    family: remoteFamily
  }, clientId);

  const udpAddr = udpSocket.address();
  debugLog('SOCKS5-UDP', `UDP绑定地址：${udpAddr.address}:${udpAddr.port}`, clientId);
  const resp = Buffer.alloc(22);
  resp[0] = 0x05;
  resp[1] = 0x00;
  resp[2] = 0x00;
  resp[3] = udpAddr.family === 'IPv6' ? 0x04 : 0x01;

  if (udpAddr.family === 'IPv4') {
    const ipParts = udpAddr.address.split('.').map(Number);
    resp.writeUInt8(ipParts[0], 4);
    resp.writeUInt8(ipParts[1], 5);
    resp.writeUInt8(ipParts[2], 6);
    resp.writeUInt8(ipParts[3], 7);
    resp.writeUInt16BE(udpAddr.port, 8);
  } else {
    // 修复：正确写入IPv6 UDP地址
    const normalizedAddr = normalizeIPv6Address(udpAddr.address);
    const ipv6Parts = normalizedAddr.split(':').map(part => parseInt(part, 16));
    let offset = 4;
    for (const part of ipv6Parts) {
      resp.writeUInt16BE(part, offset);
      offset += 2;
    }
    resp.writeUInt16BE(udpAddr.port, 20);
  }

  socket.write(resp, (err) => {
    if (err) {
      debugLog('SOCKS5-UDP', `响应发送失败：${err.message}`, clientId);
      socket.destroy();
      return;
    }
    debugLog('SOCKS5-UDP', `UDP关联响应发送成功`, clientId);
  });

  // 监听UDP消息并转发
  udpManager.on('udpMessage', (msg, rinfo, id) => {
    if (id !== clientId) return;
    debugLog('SOCKS5-UDP', `收到UDP消息，转发给客户端，长度：${msg.length}`, clientId);
    const atyp = rinfo.family === 'IPv6' ? 0x04 : 0x01;
    let addrBuffer;
    if (atyp === 0x01) {
      addrBuffer = Buffer.from(rinfo.address.split('.').map(Number));
    } else {
      // 修复：IPv6地址转Buffer
      const normalizedAddr = normalizeIPv6Address(rinfo.address);
      const ipv6Parts = normalizedAddr.split(':').map(part => parseInt(part, 16));
      addrBuffer = Buffer.alloc(16);
      let offset = 0;
      for (const part of ipv6Parts) {
        addrBuffer.writeUInt16BE(part, offset);
        offset += 2;
      }
    }
    const portBuffer = Buffer.alloc(2);
    portBuffer.writeUInt16BE(rinfo.port, 0);

    const udpPacket = Buffer.concat([
      Buffer.from([0x00, 0x00, 0x00]), // RSV + FRAG
      Buffer.from([atyp]), // ATYP
      addrBuffer, // DST.ADDR
      portBuffer, // DST.PORT
      msg // DATA
    ]);
    socket.write(udpPacket, (err) => {
      if (err) {
        debugLog('SOCKS5-UDP', `UDP消息转发失败：${err.message}`, clientId);
      }
    });
  });
}

// ===================== HTTP 代理实现（SSL修复 + 全日志） =====================
function handleHttp(socket) {
  const clientId = `${socket.remoteAddress}:${socket.remotePort}`;
  const clientFamily = socket.remoteFamily === 'IPv6' ? 'IPv6' : 'IPv4';
  debugLog('HTTP', `新客户端连接，地址族：${clientFamily}`, clientId);
  let requestBuffer = Buffer.alloc(0);

  socket.setTimeout(CONFIG.socketTimeout);
  socket.setNoDelay(true); // 禁用Nagle，加速SSL握手
  socket.on('timeout', () => {
    debugLog('HTTP', `连接超时`, clientId);
    socket.write('HTTP/1.1 408 Request Timeout\r\n\r\n');
    socket.destroy();
  });

  socket.on('data', (chunk) => {
    try {
      requestBuffer = Buffer.concat([requestBuffer, chunk]);
      debugLog('HTTP', `收到数据，累计长度：${requestBuffer.length}`, clientId);
      
      // 确保读取完整的请求头
      const headerEnd = requestBuffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        debugLog('HTTP', `请求头未完整，等待更多数据`, clientId);
        return;
      }

      const requestData = requestBuffer.toString('utf8');
      const firstLine = requestData.split('\r\n')[0].trim();
      if (!firstLine) {
        debugLog('HTTP', `空请求行`, clientId);
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        socket.destroy();
        return;
      }

      const [method, targetUrl, version] = firstLine.split(' ');
      if (!method || !targetUrl || !version) {
        debugLog('HTTP', `请求行解析失败：${firstLine}`, clientId);
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        socket.destroy();
        return;
      }

      debugLog('HTTP', `解析请求：${method} ${targetUrl} ${version}`, clientId);
      if (method === 'CONNECT') {
        // HTTPS CONNECT 隧道（修复SSL握手）
        const [host, port] = targetUrl.split(':');
        const targetPort = port || 443;
        if (!host) {
          debugLog('HTTP', `CONNECT主机为空`, clientId);
          socket.write(`${version} 400 Bad Request\r\n\r\n`);
          socket.destroy();
          return;
        }
        debugLog('HTTP-CONNECT', `尝试连接HTTPS目标：${host}:${targetPort}`, clientId);

        // 修复：强制指定地址族
        const family = host.includes(':') ? 6 : (net.isIP(host) === 6 ? 6 : 4);
        const targetSocket = net.connect({
          host,
          port: targetPort,
          family,
          timeout: CONFIG.connectTimeout,
          allowHalfOpen: false
        });

        targetSocket.setNoDelay(true);
        targetSocket.setTimeout(CONFIG.socketTimeout);

        targetSocket.on('connect', () => {
          debugLog('HTTP-CONNECT', `HTTPS目标连接成功：${host}:${targetPort}`, clientId);
          // 发送200响应（确保写入完成后再转发）
          const response = `${version} 200 Connection Established\r\nConnection: close\r\n\r\n`;
          socket.write(response, 'utf8', (err) => {
            if (err) {
              debugLog('HTTP-CONNECT', `响应发送失败：${err.message}`, clientId);
              socket.destroy();
              targetSocket.destroy();
              return;
            }
            debugLog('HTTP-CONNECT', `200响应发送成功，开始SSL转发`, clientId);
            
            // 双向转发（修复SSL数据丢失）
            socket.pipe(targetSocket, { end: true })
              .on('error', (err) => {
                if (err.code !== 'ECONNRESET') {
                  debugLog('HTTP-CONNECT', `客户端→目标转发错误：${err.message}`, clientId);
                }
              });
            
            targetSocket.pipe(socket, { end: true })
              .on('error', (err) => {
                if (err.code !== 'ECONNRESET') {
                  debugLog('HTTP-CONNECT', `目标→客户端转发错误：${err.message}`, clientId);
                }
              });
          });
        });

        targetSocket.on('timeout', () => {
          debugLog('HTTP-CONNECT', `HTTPS目标连接超时`, clientId);
          socket.write(`${version} 504 Gateway Timeout\r\n\r\n`);
          targetSocket.destroy();
          socket.destroy();
        });

        targetSocket.on('error', (err) => {
          console.error(`[HTTP-CONNECT] 连接 ${host}:${targetPort} 失败：`, err.message);
          debugLog('HTTP-CONNECT', `HTTPS目标连接失败：${err.message}`, clientId);
          socket.write(`${version} 503 Service Unavailable\r\n\r\n`);
          socket.destroy();
        });

        socket.on('close', () => {
          debugLog('HTTP-CONNECT', `客户端关闭，销毁HTTPS目标连接`, clientId);
          targetSocket.destroy();
        });
        targetSocket.on('close', () => {
          debugLog('HTTP-CONNECT', `HTTPS目标关闭，销毁客户端连接`, clientId);
          socket.destroy();
        });
      } else {
        // 普通HTTP代理
        let parsedUrl;
        try {
          // 修复：兼容相对路径和HTTPS URL
          if (!targetUrl.startsWith('http')) {
            // 补全协议头
            parsedUrl = new URL(`http://${targetUrl}`);
          } else {
            parsedUrl = new URL(targetUrl);
          }
          debugLog('HTTP', `解析URL成功：${parsedUrl.hostname}:${parsedUrl.port || 80}`, clientId);
        } catch (err) {
          console.error(`[HTTP] URL解析失败：`, err.message);
          debugLog('HTTP', `URL解析失败：${err.message}`, clientId);
          socket.write(`${version} 400 Bad Request\r\n\r\n`);
          socket.destroy();
          return;
        }

        const host = parsedUrl.hostname;
        const port = parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80);
        // 重写请求行（修复路径）
        const reqPath = parsedUrl.pathname + (parsedUrl.search || '');
        const newFirstLine = `${method} ${reqPath} ${version}`;
        const reqData = requestData.replace(firstLine, newFirstLine);
        debugLog('HTTP', `重写请求行：${newFirstLine}`, clientId);

        const family = host.includes(':') ? 6 : (net.isIP(host) === 6 ? 6 : 4);
        const targetSocket = net.connect({ host, port, family });
        targetSocket.setNoDelay(true);

        // 转发请求
        targetSocket.write(reqData, (err) => {
          if (err) {
            debugLog('HTTP', `请求转发失败：${err.message}`, clientId);
            socket.write(`${version} 503 Service Unavailable\r\n\r\n`);
            socket.destroy();
            targetSocket.destroy();
          } else {
            debugLog('HTTP', `请求转发成功，等待响应`, clientId);
          }
        });

        // 转发响应
        targetSocket.pipe(socket)
          .on('error', (err) => {
            debugLog('HTTP', `响应转发错误：${err.message}`, clientId);
          });

        targetSocket.on('error', (err) => {
          console.error(`[HTTP] 连接 ${host}:${port} 失败：`, err.message);
          debugLog('HTTP', `目标连接失败：${err.message}`, clientId);
          socket.write(`${version} 503 Service Unavailable\r\n\r\n`);
          socket.destroy();
        });

        socket.on('close', () => {
          debugLog('HTTP', `客户端关闭，销毁目标连接`, clientId);
          targetSocket.destroy();
        });
        targetSocket.on('close', () => {
          debugLog('HTTP', `目标关闭，销毁客户端连接`, clientId);
          socket.destroy();
        });
      }
    } catch (err) {
      console.error(`[HTTP] 处理错误：`, err.message);
      debugLog('HTTP', `处理异常：${err.message}`, clientId);
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      socket.destroy();
    }
  });

  socket.on('error', (err) => {
    if (err.code !== 'ECONNRESET') {
      console.error(`[HTTP] 客户端 ${clientId} 错误：`, err.message);
    }
    debugLog('HTTP', `连接错误：${err.message}`, clientId);
    socket.destroy();
  });
}

// ===================== Windows 适配的监听逻辑 =====================
function startProxyServer() {
  console.log(`🚀 启动 Windows 兼容版代理服务器（带全链路日志）`);
  console.log(`📌 监听地址：[${CONFIG.listenHost}] (自动兼容 IPv4+IPv6)`);
  console.log(`📌 监听端口：${CONFIG.listenPort}`);
  console.log(`📌 UDP 端口范围：${CONFIG.udpPortRange.min}-${CONFIG.udpPortRange.max}`);
  console.log(`📌 调试模式：${CONFIG.debug ? '开启' : '关闭'}`);

  // 单实例监听 :: 地址，自动兼容 IPv4
  const server = net.createServer((socket) => {
    debugLog('SERVER', `新连接到达，地址：${socket.remoteAddress}:${socket.remotePort}`, 'server');
    // 优化协议识别延迟
    setTimeout(() => {
      const firstByte = socket.read(1);
      if (!firstByte) {
        debugLog('SERVER', `无数据，销毁连接`, 'server');
        socket.destroy();
        return;
      }

      // 还原读取的字节
      socket.unshift(firstByte);
      debugLog('SERVER', `第一个字节：0x${firstByte[0].toString(16)}`, 'server');
      
      // SOCKS5 第一个字节是 0x05，否则是 HTTP
      if (firstByte[0] === 0x05) {
        debugLog('SERVER', `识别为SOCKS5协议`, 'server');
        handleSocks5(socket);
      } else {
        debugLog('SERVER', `识别为HTTP协议`, 'server');
        handleHttp(socket);
      }
    }, 10); // 缩短识别延迟到10ms，减少SSL握手超时
  });

  // Windows 核心配置：ipv6Only: false 兼容 IPv4
  server.listen({
    port: CONFIG.listenPort,
    host: parseListenHost(CONFIG.listenHost),
    ipv6Only: false,
    pauseOnConnect: false // 禁用连接暂停，加速处理
  }, () => {
    const addr = server.address();
    const displayHost = addr.family === 'IPv6' ? `[${addr.address}]` : addr.address;
    console.log(`✅ 代理服务器启动成功：${displayHost}:${addr.port}`);
    console.log(`✅ 支持：HTTP/HTTPS 代理、SOCKS5(TCP/UDP) 代理、IPv4+IPv6 连接`);
    console.log(`✅ 日志会输出所有关键步骤，方便定位问题`);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`❌ 端口 ${CONFIG.listenPort} 已被占用！请关闭占用程序或更换端口`);
    } else if (err.code === 'EACCES') {
      console.error(`❌ 无权限监听端口 ${CONFIG.listenPort}！请以管理员身份运行CMD`);
    } else {
      console.error(`❌ 服务器启动失败：`, err.message);
    }
    process.exit(1);
  });

  // 服务器级别的错误捕获
  server.on('connection', (socket) => {
    socket.on('error', (err) => {
      if (err.code !== 'ECONNRESET') {
        debugLog('SERVER', `连接错误：${err.message}`, 'server');
      }
    });
  });
}

// 启动服务器
startProxyServer();

// 全局未捕获异常处理
process.on('uncaughtException', (err) => {
  console.error(`[全局异常] ${err.message}`, err.stack);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error(`[未处理Promise] ${reason}`, promise);
});