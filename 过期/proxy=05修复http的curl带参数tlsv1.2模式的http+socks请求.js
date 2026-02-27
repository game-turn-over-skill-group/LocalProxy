const net = require('net');
const dns = require('dns');

// ===================== 核心配置（强制IPv4） =====================
const CONFIG = {
  listenPort: 1080,
  listenHost: '0.0.0.0',
  connectTimeout: 15000,
  socketTimeout: 30000,
  debug: true
};

// ===================== 工具函数 =====================
function debugLog(type, msg, clientId = 'unknown') {
  if (CONFIG.debug) {
    console.log(`[${new Date().toISOString()}] [${type}] [${clientId}] ${msg}`);
  }
}

// 🔥 核心修复：强制解析为IPv4地址（彻底解决SSL兼容问题）
function resolveIPv4Only(host, callback) {
  // 已是IPv4地址，直接返回
  if (net.isIP(host) === 4) {
    callback(null, host);
    return;
  }
  // 已是IPv6地址，拒绝（避免SSL兼容问题）
  if (net.isIP(host) === 6) {
    callback(new Error('禁止IPv6连接'), null);
    return;
  }
  // 强制解析IPv4（指定family:4）
  dns.lookup(host, { family: 4 }, (err, address) => {
    if (err || !address) {
      debugLog('DNS', `IPv4解析失败，降级到通用解析：${host}`, 'dns');
      callback(null, host);
    } else {
      debugLog('DNS', `强制IPv4解析成功：${host} → ${address}`, 'dns');
      callback(null, address);
    }
  });
}

// ===================== SOCKS5 处理（修复write after end） =====================
function handleSocks5(socket) {
  const clientId = `${socket.remoteAddress.replace('::ffff:', '')}:${socket.remotePort}`;
  let buffer = Buffer.alloc(0);
  let handshakeDone = false;
  let socketClosed = false; // 🔥 新增：标记socket是否已关闭

  socket.setNoDelay(true);
  socket.setTimeout(CONFIG.socketTimeout);
  socket.setKeepAlive(false);

  // 标记socket关闭状态
  socket.on('close', () => {
    socketClosed = true;
    debugLog('SOCKS5', '连接关闭', clientId);
  });

  socket.on('timeout', () => {
    if (!socketClosed) {
      socket.destroy();
      socketClosed = true;
    }
  });

  socket.on('data', (data) => {
    if (socketClosed) return; // 🔥 避免关闭后写数据

    try {
      buffer = Buffer.concat([buffer, data]);

      // 1. 握手处理
      if (!handshakeDone) {
        if (buffer.length < 3) return;
        const ver = buffer[0];
        const nmethods = buffer[1];

        if (buffer.length < 2 + nmethods) return;
        if (ver !== 0x05) {
          if (!socketClosed) socket.end(Buffer.from([0x05, 0xFF]));
          socketClosed = true;
          return;
        }

        socket.write(Buffer.from([0x05, 0x00]));
        handshakeDone = true;
        buffer = buffer.slice(2 + nmethods);
        return;
      }

      // 2. 请求处理
      if (buffer.length < 10) return;
      const ver = buffer[0];
      const cmd = buffer[1];
      const atyp = buffer[3];

      if (ver !== 0x05) {
        if (!socketClosed) socket.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0,0,0,0,0,0]));
        socketClosed = true;
        return;
      }

      // 解析目标
      let host, port, offset = 4;
      switch (atyp) {
        case 0x01: // IPv4
          host = `${buffer[4]}.${buffer[5]}.${buffer[6]}.${buffer[7]}`;
          offset += 4;
          break;
        case 0x03: // 域名
          const len = buffer[4];
          host = buffer.toString('utf8', 5, 5 + len);
          offset += 1 + len;
          break;
        default: // 拒绝IPv6
          if (!socketClosed) socket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0,0,0,0,0,0]));
          socketClosed = true;
          return;
      }
      port = buffer.readUInt16BE(offset);
      buffer = Buffer.alloc(0);

      // 仅处理CONNECT
      if (cmd === 0x01) {
        resolveIPv4Only(host, (err, ip) => {
          if (socketClosed || err) {
            if (!socketClosed) socket.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0,0,0,0,0,0]));
            socketClosed = true;
            return;
          }

          const target = net.connect({ host: ip, port, timeout: CONFIG.connectTimeout });
          target.setNoDelay(true);

          target.on('connect', () => {
            if (socketClosed) { target.destroy(); return; }
            // 发送成功响应
            const resp = Buffer.from([0x05, 0x00, 0x00, 0x01, 127,0,0,1, 0,0]);
            resp.writeUInt16BE(target.localPort, 8);
            socket.write(resp);
            // 双向转发
            socket.pipe(target);
            target.pipe(socket);
          });

          target.on('error', () => {
            if (!socketClosed) socket.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0,0,0,0,0,0]));
            socketClosed = true;
            target.destroy();
          });

          socket.on('close', () => target.destroy());
          target.on('close', () => { if (!socketClosed) socket.destroy(); });
        });
      } else {
        if (!socketClosed) socket.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0,0,0,0,0,0]));
        socketClosed = true;
      }
    } catch (err) {
      if (!socketClosed) socket.destroy();
      socketClosed = true;
    }
  });

  socket.on('error', (err) => {
    if (err.code !== 'ECONNRESET') debugLog('SOCKS5', `错误：${err.message}`, clientId);
    if (!socketClosed) socket.destroy();
    socketClosed = true;
  });
}

// ===================== HTTP 处理（强制IPv4） =====================
function handleHttp(socket) {
  const clientId = `${socket.remoteAddress.replace('::ffff:', '')}:${socket.remotePort}`;
  let buffer = Buffer.alloc(0);
  let requestHandled = false;
  let socketClosed = false; // 🔥 标记关闭状态

  socket.setNoDelay(true);
  socket.setTimeout(CONFIG.socketTimeout);
  socket.setKeepAlive(false);

  socket.on('close', () => {
    socketClosed = true;
    debugLog('HTTP', '连接关闭', clientId);
  });

  socket.on('timeout', () => {
    if (!socketClosed) {
      socket.write('HTTP/1.1 408 Timeout\r\nConnection: close\r\n\r\n');
      socket.destroy();
      socketClosed = true;
    }
  });

  socket.on('data', (data) => {
    if (socketClosed || requestHandled) {
      if (!socketClosed) socket._targetSocket?.write(data);
      return;
    }

    try {
      buffer = Buffer.concat([buffer, data]);
      const headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return;

      const req = buffer.toString('utf8', 0, headerEnd);
      const firstLine = req.split('\r\n')[0].trim();
      const [method, target, version] = firstLine.split(' ');

      // 处理CONNECT
      if (method === 'CONNECT') {
        requestHandled = true;
        const [host, port] = target.split(':');
        resolveIPv4Only(host, (err, ip) => {
          if (socketClosed || err) {
            if (!socketClosed) socket.write(`${version} 503 Error\r\nConnection: close\r\n\r\n`);
            socketClosed = true;
            return;
          }

          const targetSocket = net.connect({ host: ip, port: port || 443, timeout: CONFIG.connectTimeout });
          socket._targetSocket = targetSocket;

          targetSocket.on('connect', () => {
            if (socketClosed) { targetSocket.destroy(); return; }
            socket.write(`${version} 200 Connection Established\r\nConnection: close\r\n\r\n`);
            socket.pipe(targetSocket);
            targetSocket.pipe(socket);
          });

          targetSocket.on('error', () => {
            if (!socketClosed) socket.write(`${version} 503 Error\r\nConnection: close\r\n\r\n`);
            socketClosed = true;
            targetSocket.destroy();
          });

          socket.on('close', () => targetSocket.destroy());
          targetSocket.on('close', () => { if (!socketClosed) socket.destroy(); });
        });
      }
      buffer = Buffer.alloc(0);
    } catch (err) {
      if (!socketClosed) socket.write('HTTP/1.1 500 Error\r\nConnection: close\r\n\r\n');
      socketClosed = true;
    }
  });

  socket.on('error', (err) => {
    if (err.code !== 'ECONNRESET') debugLog('HTTP', `错误：${err.message}`, clientId);
    if (!socketClosed) socket.destroy();
    socketClosed = true;
  });
}

// ===================== 启动服务器 =====================
function startServer() {
  console.log('====================================');
  console.log('🚀 终极版代理服务器（强制IPv4）');
  console.log('📌 监听：0.0.0.0:1080 | 仅IPv4 | 无SSL兼容问题');
  console.log('====================================');

  const server = net.createServer((socket) => {
    setTimeout(() => {
      const firstByte = socket.read(1);
      if (!firstByte) { socket.destroy(); return; }
      socket.unshift(firstByte);
      firstByte[0] === 0x05 ? handleSocks5(socket) : handleHttp(socket);
    }, 10);
  });

  server.listen({ port: CONFIG.listenPort, host: CONFIG.listenHost, ipv6Only: false }, () => {
    console.log(`✅ 服务器启动成功：0.0.0.0:${CONFIG.listenPort}`);
    console.log(`✅ 已强制IPv4解析，解决SSL兼容问题`);
  });

  server.on('error', (err) => {
    console.error(`❌ 启动失败：${err.message}`);
    process.exit(1);
  });
}

// 全局异常捕获
process.on('uncaughtException', (err) => console.error(`[全局异常] ${err.message}`));
process.on('unhandledRejection', (reason) => console.error(`[Promise异常] ${reason}`));

// 启动！
startServer();