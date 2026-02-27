const net = require('net');
const dgram = require('dgram');
const dns = require('dns');

// ===================== 配置 =====================
const CONFIG = {
  port: 1080,
  host: '0.0.0.0',
  timeout: 30000,
  udpPortRange: { min: 6811, max: 6922 },
  udpPingTimeout: 2000
};

// ===================== 全局变量 =====================
const udpAssociations = new Map(); // clientId -> { socket, port, targetIp, targetPort }
const udpPingTimers = new Map();

// ===================== 工具函数 =====================
function resolveIPv4(host, cb) {
  dns.lookup(host, { family: 4, hints: dns.ADDRCONFIG }, (err, ip) => {
    console.log(`[DNS] ${host} → ${ip || host}`);
    cb(err, ip || host);
  });
}

function getRandomUdpPort() {
  return CONFIG.udpPortRange.min + Math.floor(Math.random() * (CONFIG.udpPortRange.max - CONFIG.udpPortRange.min + 1));
}

// 严格RFC1928封装SOCKS5 UDP包
function wrapSocks5UdpPacket(ip, port, data) {
  const ipBytes = Buffer.from(ip.split('.').map(Number));
  const portBytes = Buffer.alloc(2);
  portBytes.writeUInt16BE(port, 0);
  return Buffer.concat([
    Buffer.from([0x00, 0x00]), // RSV
    Buffer.from([0x00]),       // FRAG
    Buffer.from([0x01]),       // ATYP=IPv4
    ipBytes,                   // DST.ADDR
    portBytes,                 // DST.PORT
    data                       // DATA
  ]);
}

// ===================== HTTP代理（保留） =====================
function handleHttp(socket) {
  const clientId = `${socket.remoteAddress.replace('::ffff:', '')}:${socket.remotePort}`;
  let buffer = Buffer.alloc(0);
  let isClosed = false;

  const safeClose = (reason = '未知原因') => {
    if (isClosed) return;
    isClosed = true;
    console.log(`[HTTP] ${clientId} 关闭：${reason}`);
    socket.destroy();
  };

  socket.setNoDelay(true);
  socket.setTimeout(CONFIG.timeout);
  socket.on('timeout', () => safeClose('超时'));
  socket.on('error', (err) => {
    if (err.code !== 'ECONNRESET') safeClose(`错误：${err.message}`);
  });
  socket.on('close', () => isClosed = true);

  socket.on('data', (chunk) => {
    if (isClosed) return;
    buffer = Buffer.concat([buffer, chunk]);

    const headerEnd = buffer.indexOf('\r\n\r\n');
    if (headerEnd === -1) return;

    const req = buffer.toString('utf8', 0, headerEnd);
    const firstLine = req.split('\r\n')[0].trim();
    const [method, target] = firstLine.split(' ');

    if (method !== 'CONNECT') {
      safeClose('仅支持CONNECT命令');
      return;
    }

    const [host, port] = target.split(':');
    resolveIPv4(host, (err, ipv4Host) => {
      if (isClosed || err) {
        socket.write(`HTTP/1.1 503 Error\r\nConnection: close\r\n\r\n`);
        safeClose('解析地址失败');
        return;
      }

      const targetSocket = net.connect({
        host: ipv4Host,
        port: port || 443,
        family: 4,
        timeout: CONFIG.timeout
      });

      targetSocket.on('connect', () => {
        if (isClosed) { targetSocket.destroy(); return; }
        socket.write(`HTTP/1.1 200 Connection Established\r\nConnection: keep-alive\r\n\r\n`);
        socket.pipe(targetSocket).on('error', () => {});
        targetSocket.pipe(socket).on('error', () => {});
        console.log(`[HTTP] ${clientId} 连接成功：${ipv4Host}:${port || 443}`);
      });

      targetSocket.on('error', (err) => {
        socket.write(`HTTP/1.1 503 Error\r\nConnection: close\r\n\r\n`);
        safeClose(`目标连接失败：${err.message}`);
        targetSocket.destroy();
      });

      socket.on('close', () => targetSocket.destroy());
      targetSocket.on('close', () => !isClosed && socket.destroy());
    });

    buffer = Buffer.alloc(0);
  });
}

// ===================== SOCKS5（复刻v2 UDP逻辑） =====================
function handleSocks5(socket) {
  const clientId = `${socket.remoteAddress.replace('::ffff:', '')}:${socket.remotePort}`;
  let buffer = Buffer.alloc(0);
  let handshakeDone = false;
  let connectionEstablished = false;
  let isClosed = false;

  const cleanUdpResources = () => {
    if (udpAssociations.has(clientId)) {
      const udpObj = udpAssociations.get(clientId);
      udpObj.socket.close();
      udpAssociations.delete(clientId);
    }
    if (udpPingTimers.has(clientId)) {
      clearTimeout(udpPingTimers.get(clientId));
      udpPingTimers.delete(clientId);
    }
  };

  const safeClose = (reason = '未知原因') => {
    if (isClosed) return;
    isClosed = true;
    cleanUdpResources();
    if (reason !== '错误：read ECONNRESET') {
      console.log(`[SOCKS5] ${clientId} 关闭：${reason}`);
    }
    socket.destroy();
  };

  // 配置socket，禁用Nagle，开启保活
  socket.setNoDelay(true);
  socket.setKeepAlive(true, 1000);
  socket.setTimeout(CONFIG.timeout);
  socket.on('timeout', () => safeClose('超时'));
  socket.on('error', (err) => {
    if (err.code === 'ECONNRESET') {
      safeClose(`错误：read ECONNRESET`);
    } else {
      safeClose(`错误：${err.message}`);
    }
  });
  socket.on('close', () => {
    isClosed = true;
    cleanUdpResources();
  });

  const processData = () => {
    if (isClosed || buffer.length === 0 || connectionEstablished) return;

    // 1. SOCKS5握手（严格RFC1928）
    if (!handshakeDone) {
      if (buffer.length < 3) return;
      const ver = buffer[0];
      const nmethods = buffer[1];
      if (buffer.length < 2 + nmethods) return;

      if (ver !== 0x05) {
        socket.write(Buffer.from([0x05, 0xFF]));
        safeClose('仅支持SOCKS5');
        return;
      }

      // 响应无需认证
      socket.write(Buffer.from([0x05, 0x00]));
      handshakeDone = true;
      buffer = buffer.slice(2 + nmethods);
      console.log(`[SOCKS5] ${clientId} 握手完成（SOCKS5 RFC1928）`);
      processData();
      return;
    }

    // 2. SOCKS5请求处理
    if (handshakeDone && !connectionEstablished) {
      if (buffer.length < 7) return;

      const [ver, cmd, rsv, atyp] = buffer;
      // 严格校验RFC1928
      if (ver !== 0x05 || rsv !== 0x00) {
        socket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0,0,0,0,0,0]));
        safeClose('请求不符合RFC1928标准');
        return;
      }

      // 2.1 TCP CONNECT（已稳定）
      if (cmd === 0x01) {
        let targetHost, targetPort, offset = 4;
        try {
          switch (atyp) {
            case 0x01: // IPv4
              targetHost = `${buffer[4]}.${buffer[5]}.${buffer[6]}.${buffer[7]}`;
              offset += 4;
              break;
            case 0x03: // 域名
              const domainLen = buffer[4];
              targetHost = buffer.toString('utf8', 5, 5 + domainLen);
              offset += 1 + domainLen;
              break;
            default:
              socket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0,0,0,0,0,0]));
              safeClose('仅支持IPv4/域名地址');
              return;
          }
          targetPort = buffer.readUInt16BE(offset);
          buffer = Buffer.alloc(0);

          resolveIPv4(targetHost, (err, targetIp) => {
            if (isClosed || err) {
              socket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0,0,0,0,0,0]));
              safeClose(`DNS解析失败：${err?.message}`);
              return;
            }

            console.log(`[SOCKS5] ${clientId} TCP转发 → ${targetIp}:${targetPort}`);
            const targetSocket = net.connect({
              host: targetIp,
              port: targetPort,
              family: 4,
              timeout: CONFIG.timeout
            });

            targetSocket.on('connect', () => {
              if (isClosed) { targetSocket.destroy(); return; }
              // 响应TCP连接成功
              const resp = Buffer.from([0x05, 0x00, 0x00, 0x01, 127,0,0,1, 0,0]);
              resp.writeUInt16BE(targetSocket.localPort, 8);
              socket.write(resp);

              connectionEstablished = true;
              console.log(`[SOCKS5] ${clientId} TCP连接成功 → ${targetIp}:${targetPort}`);

              // 双向转发
              socket.pipe(targetSocket, { end: true }).on('error', () => {});
              targetSocket.pipe(socket, { end: true }).on('error', () => {});
            });

            targetSocket.on('error', (err) => {
              socket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0,0,0,0,0,0]));
              safeClose(`TCP连接失败：${err.message}`);
              targetSocket.destroy();
            });

            socket.on('close', () => targetSocket.destroy());
            targetSocket.on('close', () => !isClosed && socket.destroy());
          });
        } catch (err) {
          socket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0,0,0,0,0,0]));
          safeClose(`TCP请求解析失败：${err.message}`);
        }
      }

      // 2.2 UDP ASSOCIATE（复刻v2逻辑，核心修复）
      else if (cmd === 0x03) {
        try {
          // 步骤1：生成随机UDP端口，绑定0.0.0.0（关键！不是127.0.0.1）
          const udpPort = getRandomUdpPort();
          const udpSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
          
          // 关键配置：禁用回环，允许对外发送/接收
          udpSocket.setBroadcast(true);
          udpSocket.setMulticastLoopback(false);

          // 步骤2：绑定UDP端口到0.0.0.0，确保能接收公网响应
          udpSocket.bind(udpPort, CONFIG.host, () => {
            if (isClosed) { udpSocket.close(); return; }
            console.log(`[SOCKS5] ${clientId} UDP关联成功 → 0.0.0.0:${udpPort}`);
            udpAssociations.set(clientId, {
              socket: udpSocket,
              port: udpPort,
              targetIp: '',
              targetPort: 0
            });

            // 步骤3：响应UDP ASSOCIATE成功（RFC1928标准）
            const resp = Buffer.from([0x05, 0x00, 0x00, 0x01, 0,0,0,0, udpPort >> 8, udpPort & 0xFF]);
            socket.write(resp);

            // 步骤4：处理UDP响应（核心：接收公网目标的响应）
            udpSocket.on('message', (data, rinfo) => {
              if (isClosed) return;
              // 只处理来自目标服务器的响应，过滤本地回环
              if (rinfo.address === '127.0.0.1' && rinfo.port !== 6969) {
                console.log(`[UDP] ${clientId} 过滤本地回环响应 → ${rinfo.address}:${rinfo.port}`);
                return;
              }

              console.log(`[UDP] ${clientId} 收到真实响应 → ${rinfo.address}:${rinfo.port} (数据长度：${data.length})`);
              // 严格封装SOCKS5 UDP包转发给客户端
              const socks5UdpPacket = wrapSocks5UdpPacket(rinfo.address, rinfo.port, data);
              socket.write(socks5UdpPacket, (err) => {
                if (err) {
                  console.log(`[UDP] ${clientId} 转发响应失败 → ${err.message}`);
                } else {
                  console.log(`[UDP] ${clientId} 响应转发成功 → 客户端（包长度：${socks5UdpPacket.length}）`);
                }
              });
            });

            // 步骤5：处理客户端UDP请求（解析并转发到公网目标）
            socket.on('data', (clientPacket) => {
              if (isClosed || clientPacket.length < 8) return;
              try {
                // 解析SOCKS5 UDP包（严格RFC1928）
                const rsv = clientPacket.readUInt16BE(0);
                const frag = clientPacket[2];
                const atyp = clientPacket[3];

                if (rsv !== 0x0000 || frag !== 0x00) {
                  console.log(`[UDP] ${clientId} 无效UDP包 → RSV:${rsv}, FRAG:${frag}`);
                  return;
                }

                let targetHost, targetPort, offset = 4;
                // 解析目标地址和端口
                switch (atyp) {
                  case 0x01: // IPv4
                    targetHost = `${clientPacket[4]}.${clientPacket[5]}.${clientPacket[6]}.${clientPacket[7]}`;
                    offset += 4;
                    break;
                  case 0x03: // 域名
                    const domainLen = clientPacket[4];
                    targetHost = clientPacket.toString('utf8', 5, 5 + domainLen);
                    offset += 1 + domainLen;
                    break;
                  default:
                    console.log(`[UDP] ${clientId} 不支持的地址类型 → ${atyp}`);
                    return;
                }
                targetPort = clientPacket.readUInt16BE(offset);
                offset += 2;
                const udpData = clientPacket.slice(offset);

                // 解析目标IP并转发到公网（核心修复：确保发到真实目标）
                resolveIPv4(targetHost, (err, targetIp) => {
                  if (isClosed || err || !targetIp) {
                    console.log(`[UDP] ${clientId} DNS解析失败 → ${targetHost}`);
                    return;
                  }

                  // 更新关联的目标信息
                  const udpObj = udpAssociations.get(clientId);
                  if (udpObj) {
                    udpObj.targetIp = targetIp;
                    udpObj.targetPort = targetPort;
                  }

                  // 关键：转发UDP包到公网目标（指定0.0.0.0出口）
                  console.log(`[UDP] ${clientId} 转发UDP包 → ${targetIp}:${targetPort} (数据长度：${udpData.length})`);
                  udpSocket.send(udpData, targetPort, targetIp, { port: udpPort, address: '0.0.0.0' }, (err) => {
                    if (err) {
                      console.log(`[UDP] ${clientId} 发送失败 → ${err.message}`);
                    } else {
                      console.log(`[UDP] ${clientId} 发送成功 → ${targetIp}:${targetPort} (出口：0.0.0.0:${udpPort})`);
                    }
                  });

                  // 适配udping超时
                  if (!udpPingTimers.has(clientId)) {
                    udpPingTimers.set(clientId, setTimeout(() => {
                      console.log(`[UDP] ${clientId} udping超时 → 清理资源`);
                      safeClose('udping超时');
                    }, CONFIG.udpPingTimeout));
                  }
                });
              } catch (err) {
                console.log(`[UDP] ${clientId} 解析请求失败 → ${err.message}`);
              }
            });
          });

          // UDP Socket错误处理
          udpSocket.on('error', (err) => {
            console.log(`[UDP] ${clientId} Socket错误 → ${err.message}`);
            safeClose('UDP Socket错误');
          });

          udpSocket.on('close', () => {
            console.log(`[UDP] ${clientId} Socket关闭`);
            cleanUdpResources();
          });
        } catch (err) {
          safeClose(`UDP关联失败 → ${err.message}`);
        }
        buffer = Buffer.alloc(0);
      } else {
        socket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0,0,0,0,0,0]));
        safeClose(`不支持的SOCKS5命令 → ${cmd}`);
      }
    }
  };

  // 接收客户端数据
  socket.on('data', (chunk) => {
    if (isClosed) return;
    buffer = Buffer.concat([buffer, chunk]);
    processData();
  });
}

// ===================== 启动服务器 =====================
const server = net.createServer({ allowHalfOpen: false, pauseOnConnect: false }, (socket) => {
  const clientId = `${socket.remoteAddress.replace('::ffff:', '')}:${socket.remotePort}`;
  console.log(`[SERVER] 新连接 → ${clientId}`);

  // 快速识别协议（SOCKS5/HTTP）
  setTimeout(() => {
    const firstByte = socket.read(1);
    if (!firstByte) {
      console.log(`[SERVER] ${clientId} 无数据 → 关闭`);
      socket.destroy();
      return;
    }
    socket.unshift(firstByte);

    // SOCKS5（0x05）或HTTP
    if (firstByte[0] === 0x05) {
      handleSocks5(socket);
    } else {
      handleHttp(socket);
    }
  }, 10);
});

// 全局异常捕获，防止进程崩溃
process.on('uncaughtException', (err) => {
  console.error(`[全局异常] → ${err.message}`);
});
process.on('unhandledRejection', (reason) => {
  console.error(`[Promise异常] → ${reason}`);
});

// 启动服务器（绑定0.0.0.0）
server.listen({ port: CONFIG.port, host: CONFIG.host, exclusive: true }, () => {
  console.log('====================================');
  console.log('🚀 复刻v2 SOCKS5代理（UDP终极修复）');
  console.log(`📌 监听地址 → ${CONFIG.host}:${CONFIG.port} (仅IPv4)`);
  console.log(`📌 UDP端口范围 → ${CONFIG.udpPortRange.min}~${CONFIG.udpPortRange.max}`);
  console.log(`📌 udping超时适配 → ${CONFIG.udpPingTimeout}ms`);
  console.log('====================================');
});

server.on('error', (err) => {
  console.error(`[SERVER] 启动失败 → ${err.message}`);
  process.exit(1);
});