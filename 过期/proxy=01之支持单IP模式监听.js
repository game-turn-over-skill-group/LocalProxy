const net = require('net');
const dgram = require('dgram');
const url = require('url');
const { EventEmitter } = require('events');

// ===================== 配置项（可自定义） =====================
const CONFIG = {
  // 监听地址（支持 127.0.0.1/0.0.0.0/::/::1，IPv6 地址无需方括号）
  listenHost: '0.0.0.0',
  // 代理服务监听端口
  listenPort: 1080,
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
    udpSocket.bind(bindPort, parseListenHost(CONFIG.listenHost), (err) => {
      if (err) {
        console.error(`UDP 端口 ${bindPort} 绑定失败：`, err.message);
        // 绑定失败则重新生成端口
        this.createUdpSocket(remoteInfo, clientId);
        return;
      }
      console.log(`UDP Socket 已绑定：${socketType} ${CONFIG.listenHost}:${bindPort}`);
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
    const ipParts = parseListenHost(CONFIG.listenHost).split('.').map(Number);
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

// ===================== HTTP 代理实现 =====================
/**
 * 处理 HTTP 代理
 * @param {net.Socket} socket - 客户端连接
 */
function handleHttp(socket) {
  const clientId = `${socket.remoteAddress}:${socket.remotePort}`;
  socket.on('data', (data) => {
    try {
      const firstLine = data.toString('utf8').split('\r\n')[0];
      const [method, targetUrl, version] = firstLine.split(' ');

      if (method === 'CONNECT') {
        // HTTPS CONNECT 方法（隧道代理）
        const [host, port] = targetUrl.split(':');
        const targetPort = port || 443;

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
        // 普通 HTTP 代理
        const parsedUrl = url.parse(targetUrl);
        const host = parsedUrl.hostname;
        const port = parsedUrl.port || 80;

        // 重写请求头（去掉代理相关）
        const reqData = data.toString('utf8').replace(firstLine, `${method} ${parsedUrl.path} ${version}`);
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

// ===================== 主服务器启动 =====================
/**
 * 启动代理服务器（自动识别 HTTP/SOCKS5）
 */
function startProxyServer() {
  const server = net.createServer((socket) => {
    // 延迟 100ms 识别协议（根据第一个字节）
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
    }, 100);
  });

  // 监听指定地址和端口（支持 IPv4/IPv6）
  server.listen({
    port: CONFIG.listenPort,
    host: parseListenHost(CONFIG.listenHost),
    ipv6Only: false // 同时支持 IPv4 和 IPv6
  }, () => {
    const addr = server.address();
    console.log(`代理服务器已启动：`);
    console.log(`- 监听地址：${addr.family === 'IPv6' ? `[${addr.address}]` : addr.address}`);
    console.log(`- 监听端口：${addr.port}`);
    console.log(`- 支持协议：HTTP/HTTPS、SOCKS5（TCP/UDP）`);
    console.log(`- UDP 端口范围：${CONFIG.udpPortRange.min}-${CONFIG.udpPortRange.max}`);
    console.log(`- UDP 包阈值：${CONFIG.udpPacketThreshold} 个`);
  });

  // 服务器错误处理
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`端口 ${CONFIG.listenPort} 已被占用，请更换端口后重试`);
    } else {
      console.error(`服务器启动失败：`, err.message);
    }
    process.exit(1);
  });
}

// 启动服务器
startProxyServer();