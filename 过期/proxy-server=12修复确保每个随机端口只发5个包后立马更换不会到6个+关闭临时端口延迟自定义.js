/**
 * 本地代理服务器 - 单端口同时支持 SOCKS4/4a/5 + HTTP 代理
 *
 * 特性：
 *  - 单端口自动识别 HTTP / SOCKS4 / SOCKS4a / SOCKS5
 *  - 支持 IPv4 / IPv6
 *  - 支持监听 127.0.0.1 / 0.0.0.0 / :: / ::1
 *  - HTTP 代理：CONNECT(HTTPS) + 普通 HTTP
 *  - SOCKS5：TCP CONNECT + UDP ASSOCIATE
 *  - SOCKS4/4a：TCP CONNECT（兼容）
 *  - UDP：每发送 N 个包后轮换本地绑定端口（范围 6811-6922），旧端口延迟关闭时间可配置
 *
 * 启动：
 *   node proxy-server.js
 *   node proxy-server.js --host=0.0.0.0 --port=1080
 *   node proxy-server.js --host=:: --port=1080
 *   node proxy-server.js --udp-min=6811 --udp-max=6922 --udp-rotate=5
 *   node proxy-server.js --udp-stale-timeout=5000   # 旧 socket 等待回包的超时（毫秒）
 *   node proxy-server.js --debug   （显示每个连接的原始首字节）
 */

'use strict';

const net   = require('net');
const dgram = require('dgram');
const dns   = require('dns');
const fs    = require('fs'); // +++ 新增：用于写入崩溃日志
const { promisify } = require('util');

// ─── 配置 ─────────────────────────────────────────────────────────────────────

const CONFIG = {
  // host 支持以下值：
  //   '127.0.0.1'  仅 IPv4 本机
  //   '::1'        仅 IPv6 本机
  //   '0.0.0.0'    所有 IPv4 接口（含局域网）
  //   '::'         所有 IPv6 接口（含局域网）
  //   'dual'       同时监听 127.0.0.1 + ::1（默认，本机 IPv4+IPv6 均可连）
  //   'dual-all'   同时监听 0.0.0.0 + ::（局域网 IPv4+IPv6 均可连）
  host:         'dual',
  port:         22,
  udpPortRange: { min: 6811, max: 6922 },
  udpRotateAfter: 5,        // 每 5 个 UDP 数据包更换一次出口端口（从第6个包开始用新端口）
  udpStaleTimeout: 5000,    // 旧出口 socket 延迟关闭时间（毫秒），默认 5 秒
  debug:        false, //true / false
};

process.argv.slice(2).forEach(arg => {
  const m = arg.match(/^--([^=]+)(?:=(.+))?$/);
  if (!m) return;
  const [, key, val] = m;
  if (key === 'host')                CONFIG.host             = val;
  if (key === 'port')                CONFIG.port             = parseInt(val);
  if (key === 'udp-min')             CONFIG.udpPortRange.min = parseInt(val);
  if (key === 'udp-max')             CONFIG.udpPortRange.max = parseInt(val);
  if (key === 'udp-rotate')           CONFIG.udpRotateAfter   = parseInt(val);
  if (key === 'udp-stale-timeout')    CONFIG.udpStaleTimeout  = parseInt(val);
  if (key === 'debug')                CONFIG.debug            = true;
  if (key === 'no-debug')             CONFIG.debug            = false;
});

// 将 host 配置展开成实际要监听的地址列表
function resolveBindAddresses(host) {
  switch (host) {
    case 'dual':     return ['127.0.0.1', '::1'];       // 本机 IPv4 + IPv6
    case 'dual-all': return ['0.0.0.0',   '::'];        // 所有接口 IPv4 + IPv6
    default:         return [normalizeHost(host)];       // 单地址
  }
}

// ─── 工具 ─────────────────────────────────────────────────────────────────────

const dnsLookup = promisify(dns.lookup);

function log(level, ...args) {
  const ts = new Date().toISOString();
  console[level === 'error' ? 'error' : 'log'](`[${ts}] [${level.toUpperCase()}]`, ...args);
}
function dbg(...args) { if (CONFIG.debug) log('debug', ...args); }

function isIPv6Addr(addr)  { return addr.includes(':'); }
function randomInRange(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function normalizeHost(h)  { return h.replace(/^\[|\]$/g, ''); }

function pipeStreams(a, b) {
  a.pipe(b); b.pipe(a);
  const end = () => { try { a.destroy(); } catch (_) {} try { b.destroy(); } catch (_) {} };
  a.on('close', end); b.on('close', end);
  a.on('error', end); b.on('error', end);
}

// ─── 协议检测 ─────────────────────────────────────────────────────────────────
//
//  首字节：
//    0x04  → SOCKS4 / SOCKS4a
//    0x05  → SOCKS5
//    그외   → HTTP  (ASCII 大写字母: G P C H D O T)

function detectProtocol(firstByte) {
  if (firstByte === 0x05) return 'socks5';
  if (firstByte === 0x04) return 'socks4';
  // HTTP 方法首字母范围 A-Z (0x41-0x5A)
  if (firstByte >= 0x41 && firstByte <= 0x5A) return 'http';
  return 'unknown';
}

// ─── SOCKS5 ───────────────────────────────────────────────────────────────────

const S5_VER        = 0x05;
const AUTH_NONE     = 0x00;
const AUTH_UNACCEPT = 0xFF;
const CMD_CONNECT   = 0x01;
const CMD_UDP_ASSOC = 0x03;
const ATYP_IPV4     = 0x01;
const ATYP_DOMAIN   = 0x03;
const ATYP_IPV6     = 0x04;
const REP_OK        = 0x00;
const REP_FAIL      = 0x01;
const REP_UNSUP     = 0x07;

/** 将任意格式的 IPv6 地址（含缩写如 ::1）正确展开为 16 字节 Buffer */
function ipv6ToBuffer(addr) {
  const buf = Buffer.alloc(16);
  // 处理 :: 缩写：拆成左右两半，中间补零
  const halves = addr.split('::');
  let left  = halves[0] ? halves[0].split(':') : [];
  let right = halves[1] ? halves[1].split(':') : [];
  // 中间需要补的零组数
  const missing = 8 - left.length - right.length;
  const mid = Array(missing).fill('0');
  const groups = [...left, ...mid, ...right];
  groups.forEach((g, i) => buf.writeUInt16BE(parseInt(g || '0', 16), i * 2));
  return buf;
}

function parseSocks5Addr(buf, offset) {
  const atyp = buf[offset++];
  let host;
  if (atyp === ATYP_IPV4) {
    host = `${buf[offset]}.${buf[offset+1]}.${buf[offset+2]}.${buf[offset+3]}`;
    offset += 4;
  } else if (atyp === ATYP_IPV6) {
    const p = [];
    for (let i = 0; i < 8; i++) { p.push(buf.readUInt16BE(offset).toString(16)); offset += 2; }
    host = p.join(':');
  } else if (atyp === ATYP_DOMAIN) {
    const len = buf[offset++];
    host = buf.slice(offset, offset + len).toString();
    offset += len;
  } else {
    throw new Error(`Unknown ATYP: 0x${atyp.toString(16)}`);
  }
  const port = buf.readUInt16BE(offset);
  return { host, port, atyp, offset: offset + 2 };
}

function buildS5Reply(rep, host, port) {
  let atyp, addrBuf;
  if (net.isIPv4(host)) {
    atyp = ATYP_IPV4;
    addrBuf = Buffer.from(host.split('.').map(Number));
  } else if (net.isIPv6(host)) {
    atyp = ATYP_IPV6;
    addrBuf = ipv6ToBuffer(host);  // 正确处理 :: 缩写
  } else {
    atyp = ATYP_IPV4;
    addrBuf = Buffer.from([0, 0, 0, 0]);
  }
  const r = Buffer.alloc(4 + addrBuf.length + 2);
  r[0] = S5_VER; r[1] = rep; r[2] = 0; r[3] = atyp;
  addrBuf.copy(r, 4);
  r.writeUInt16BE(port, 4 + addrBuf.length);
  return r;
}

function buildUdpHeader(atyp, host, port) {
  let addrBuf;
  if (atyp === ATYP_IPV4) {
    addrBuf = Buffer.from(host.split('.').map(Number));
  } else if (atyp === ATYP_IPV6) {
    addrBuf = ipv6ToBuffer(host);  // 正确处理 :: 缩写
  } else {
    const d = Buffer.from(host);
    addrBuf = Buffer.alloc(1 + d.length);
    addrBuf[0] = d.length; d.copy(addrBuf, 1);
    atyp = ATYP_DOMAIN;
  }
  const h = Buffer.alloc(4 + addrBuf.length + 2);
  h[0] = 0; h[1] = 0; h[2] = 0; h[3] = atyp;
  addrBuf.copy(h, 4);
  h.writeUInt16BE(port, 4 + addrBuf.length);
  return h;
}

function handleSocks5(socket, firstChunk) {
  let buf   = firstChunk;
  let state = 'handshake';

  const process = async () => {
    try {
      // ── 握手阶段 ──────────────────────────────────────────────
      if (state === 'handshake') {
        if (buf.length < 2) return;
        const nmethods = buf[1];
        if (buf.length < 2 + nmethods) return;
        const methods = [...buf.slice(2, 2 + nmethods)];
        buf = buf.slice(2 + nmethods);
        dbg(`SOCKS5 handshake ok, methods=[${methods.map(m => '0x'+m.toString(16))}], remaining buf=${buf.length}B`);
        if (methods.includes(AUTH_NONE)) {
          socket.write(Buffer.from([S5_VER, AUTH_NONE]));
          state = 'request';
          // 握手包和请求包可能在同一个 TCP 段里（粘包），立即继续处理
          if (buf.length > 0) {
            dbg(`SOCKS5 buf has ${buf.length}B after handshake, continuing to request phase`);
            setImmediate(process); // 异步继续，避免递归爆栈
          }
        } else {
          socket.write(Buffer.from([S5_VER, AUTH_UNACCEPT]));
          socket.destroy();
        }
        return; // 握手阶段处理完毕，等待下一次 data 或 setImmediate
      }

      // ── 请求阶段 ──────────────────────────────────────────────
      if (state === 'request') {
        dbg(`SOCKS5 request phase, buf=${buf.length}B`);
        if (buf.length < 4) { dbg('SOCKS5 waiting for more request data...'); return; }
        if (buf[0] !== S5_VER) {
          log('warn', `SOCKS5 bad version in request: 0x${buf[0].toString(16)}`);
          socket.destroy(); return;
        }
        const cmd      = buf[1];
        const atypByte = buf[3];
        let minLen = 4;
        if      (atypByte === ATYP_IPV4)   minLen += 6;
        else if (atypByte === ATYP_IPV6)   minLen += 18;
        else if (atypByte === ATYP_DOMAIN) {
          if (buf.length < 5) { dbg('SOCKS5 waiting for domain length byte...'); return; }
          minLen += 1 + buf[4] + 2;
        }
        if (buf.length < minLen) { dbg(`SOCKS5 need ${minLen}B, have ${buf.length}B`); return; }

        const { host, port, atyp, offset } = parseSocks5Addr(buf, 3);
        const rest = buf.slice(offset);
        state = 'tunneling';
        socket.pause();

        dbg(`SOCKS5 cmd=0x${cmd.toString(16)} → ${host}:${port}`);

        if (cmd === CMD_CONNECT) {
          await s5TcpConnect(socket, host, port, atyp, rest);
        } else if (cmd === CMD_UDP_ASSOC) {
          await s5UdpAssoc(socket);
        } else {
          socket.write(buildS5Reply(REP_UNSUP, '0.0.0.0', 0));
          socket.destroy();
        }
      }
    } catch (e) {
      log('error', 'SOCKS5 parse:', e.message, e.stack);
      socket.destroy();
    }
  };

  socket.on('data', chunk => {
    buf = Buffer.concat([buf, chunk]);
    dbg(`SOCKS5 data event: +${chunk.length}B, total buf=${buf.length}B, state=${state}`);
    process();
  });
  socket.on('error', err => { if (err.code !== 'ECONNRESET') log('error', 'S5 socket:', err.message); });
  // 确保 socket 处于流动状态（once data 触发后 Node 会自动 pause，需要手动恢复）
  socket.resume();
  process();
}

async function s5TcpConnect(client, host, port, atyp, pending) {
  let rHost = host, rAtyp = atyp;
  if (atyp === ATYP_DOMAIN) {
    try {
      const r = await dnsLookup(host, { all: false });
      rHost = r.address;
      rAtyp = r.family === 6 ? ATYP_IPV6 : ATYP_IPV4;
    } catch (e) {
      try { client.write(buildS5Reply(REP_FAIL, '0.0.0.0', 0)); } catch (_) {}
      client.destroy(); return;
    }
  }
  const remote = net.createConnection({ host: rHost, port }, () => {
    client.write(buildS5Reply(REP_OK, rHost, port));
    if (pending.length > 0) remote.write(pending);
    client.resume();
    pipeStreams(client, remote);
    log('info', `SOCKS5 TCP  ${client.remoteAddress} → ${host}:${port}`);
  });
  remote.on('error', err => {
    log('error', `S5 TCP [${host}:${port}]:`, err.message);
    try { client.write(buildS5Reply(REP_FAIL, '0.0.0.0', 0)); } catch (_) {}
    client.destroy();
  });
}

// 全局会话计数器，用于区分并发 UDP ASSOCIATE 会话
let _udpSessionId = 0;

async function s5UdpAssoc(clientTcp) {
  const sessionId = ++_udpSessionId;
  // 使用连接进来的本地地址（localAddress）作为 relay 绑定地址
  // 这样无论监听 127.0.0.1 还是 ::1 还是 dual，都能正确判断协议族
  const localAddr = clientTcp.localAddress || '127.0.0.1';
  const bindHost  = localAddr.startsWith('::ffff:') ? localAddr.slice(7) : localAddr;
  // relay socket 跟随监听地址的协议族（接收本机客户端的包）
  const relayV6   = net.isIPv6(bindHost) || bindHost === '::' || bindHost === '::1';
  const relayType = relayV6 ? 'udp6' : 'udp4';

  const relaySock = dgram.createSocket({ type: relayType, reuseAddr: true });
  let clientUdpAddr = null;

  // 为每个目标协议族维护独立的出口 socket（避免 udp4 socket 发 IPv6 包报 EINVAL）
  // outSocks: { 4: socket|null, 6: socket|null }
  const outSocks   = { 4: null, 6: null };
  const pktCounts  = { 4: 0,    6: 0    };

  relaySock.on('error', err => log('error', 'UDP relay:', err.message));
  relaySock.on('message', (msg, rinfo) => {
    if (!clientUdpAddr) {
      clientUdpAddr = rinfo;
      dbg(`UDP relay: client addr set to ${rinfo.address}:${rinfo.port}`);
    }
    if (msg.length < 4 || msg[2] !== 0) return;
    try {
      const { host: dstHost, port: dstPort, atyp: dstAtyp, offset } = parseSocks5Addr(msg, 3);
      const data = msg.slice(offset);
      dbg(`UDP relay: client→${dstHost}:${dstPort} (${data.length}B)`);

      // doSend 改为异步函数，以便等待新 socket 就绪
      const doSend = async (addr) => {
        const family = net.isIPv6(addr) ? 6 : 4; // 根据目标地址决定用 IPv4 还是 IPv6 出口 socket
        let sock = outSocks[family];

        // 检查是否需要轮换出口端口
        if (pktCounts[family] >= CONFIG.udpRotateAfter) {
          // 需要轮换：等待新 socket 创建完成
          await new Promise(resolve => {
            createOutSockForFamily(family, (newPort, newAddr) => {
              resolve();
            });
          });
          // 新 socket 已就绪，重新获取
          sock = outSocks[family];
          // 当前包是新 socket 的第一个包，计数器置为1
          pktCounts[family] = 1;
        } else {
          pktCounts[family]++;
        }

        // 获取本地地址和端口（try-catch 防止 socket 未绑定完成时出错）
        let localAddrStr = '';
        try {
          const local = sock.address();
          localAddrStr = net.isIPv6(local.address) ? `[${local.address}]:${local.port}` : `${local.address}:${local.port}`;
        } catch (e) {
          localAddrStr = '?.?.?.?:?'; // 极少数情况下的回退
        }

        // 每次发送都打印日志，格式：目标IP:端口 (本地监听地址:端口)
        log('info', `SOCKS5 UDP  ${clientTcp.remoteAddress} [#${sessionId}] → ${addr}:${dstPort} (${localAddrStr})`);

        //dbg(`UDP relay: sending via v${family} socket to ${addr}:${dstPort}`); // 调试信息（可选择保留）
        sock.send(data, dstPort, addr, err => {
          if (err) log('error', `UDP send(v${family}):`, err.message);
          else dbg(`UDP sent OK → ${addr}:${dstPort}`);
        });
      };

      if (dstAtyp === ATYP_DOMAIN) {
        dnsLookup(dstHost, { all: false })
          .then(r => { dbg(`UDP DNS ${dstHost} → ${r.address}`); doSend(r.address); })
          .catch(e => log('error', 'UDP DNS:', e.message));
      } else {
        doSend(dstHost);
      }
    } catch (e) { log('error', 'UDP parse:', e.message); }
  });

  // 创建出口 socket（修改版：绑定完成后再赋值给 outSocks，并调用 onReady）
  function createOutSockForFamily(family, onReady) {
    const old2 = outSocks[family];
    // 延迟关闭旧 socket（给在途回包留缓冲），使用可配置的超时
    if (old2) {
      setTimeout(() => {
        try { old2.close(); } catch (_) {}
      }, CONFIG.udpStaleTimeout);
    }

    const type = family === 6 ? 'udp6' : 'udp4';
    const bind = family === 6 ? '::'   : '0.0.0.0';
    const p    = randomInRange(CONFIG.udpPortRange.min, CONFIG.udpPortRange.max);
    const s    = dgram.createSocket({ type, reuseAddr: true });

    // 回包处理（新旧 socket 共用，旧 socket 的在途回包也能正确转发）
    const onMessage = (msg, rinfo) => {
      dbg(`UDP out(v${family}) recv ${rinfo.address}:${rinfo.port} ${msg.length}B`);
      if (!clientUdpAddr) return;
      const rAtyp = net.isIPv6(rinfo.address) ? ATYP_IPV6 : ATYP_IPV4;
      const hdr   = buildUdpHeader(rAtyp, rinfo.address, rinfo.port);
      relaySock.send(Buffer.concat([hdr, msg]), clientUdpAddr.port, clientUdpAddr.address, err => {
        if (err) log('error', `UDP back(v${family}):`, err.message);
        else dbg(`UDP back OK → ${clientUdpAddr.address}:${clientUdpAddr.port}`);
      });
    };

    s.on('error', err => { if (err.code !== 'ERR_SOCKET_DGRAM_NOT_RUNNING') log('error', `UDP out(v${family}):`, err.message); });
    s.on('message', onMessage);
    // 旧 socket 继续监听回包，直到延迟关闭
    if (old2) old2.removeAllListeners('message');
    if (old2) old2.on('message', onMessage);

    // 绑定，成功后赋值给 outSocks 并调用 onReady
    s.bind(p, bind, () => {
      const a = s.address();
      dbg(`UDP out(v${family}) → ${a.address}:${a.port}`);
      // 现在新 socket 才正式生效
      outSocks[family] = s;
      pktCounts[family] = 0; // 重置计数器（新 socket 从0开始）
      if (onReady) onReady(a.port, a.address);
    });

    // 注意：此处不立即设置 outSocks[family] = s，仍用旧 socket 直到绑定完成
  }

  // 预先创建两个出口 socket（IPv4 + IPv6）
  createOutSockForFamily(4);
  createOutSockForFamily(6);

  const relayPort = randomInRange(CONFIG.udpPortRange.min, CONFIG.udpPortRange.max);
  relaySock.bind(relayPort, bindHost, () => {
    const a = relaySock.address();
    dbg(`SOCKS5 UDP relay → ${a.address}:${a.port}`);
    const dispRelay = net.isIPv6(a.address) ? `[${a.address}]:${a.port}` : `${a.address}:${a.port}`;
    log('info', `SOCKS5 UDP  ${clientTcp.remoteAddress} [#${sessionId}] → [relay ${dispRelay}]`);
    clientTcp.write(buildS5Reply(REP_OK, a.address, a.port));
  });

  const cleanup = () => {
    try { relaySock.close(); } catch (_) {}
    try { if (outSocks[4]) outSocks[4].close(); } catch (_) {}
    try { if (outSocks[6]) outSocks[6].close(); } catch (_) {}
  };
  clientTcp.on('close', cleanup);
  clientTcp.on('error', cleanup);
}

// ─── SOCKS4 / SOCKS4a ────────────────────────────────────────────────────────
//
//  格式：VN(1) + CD(1) + DSTPORT(2) + DSTIP(4) + USERID(var,\0) [+ HOSTNAME(var,\0) if 4a]
//  响应：VN(1)=0 + CD(1) + DSTPORT(2) + DSTIP(4)

function handleSocks4(socket, firstChunk) {
  let buf = firstChunk;

  const process = async () => {
    try {
      // 至少需要：VN(1)+CD(1)+PORT(2)+IP(4) = 8 字节，再加 USERID 以 \0 结尾
      if (buf.length < 8) return;
      const cd   = buf[1];
      const port = buf.readUInt16BE(2);
      const ip   = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;

      // 查找 USERID 结尾的 \0
      let pos = 8;
      while (pos < buf.length && buf[pos] !== 0) pos++;
      if (pos >= buf.length) return; // 还没收到 \0
      pos++; // 跳过 \0

      let host = ip;
      // SOCKS4a：IP 形如 0.0.0.x（x != 0），hostname 跟在 USERID\0 后面
      if (buf[4] === 0 && buf[5] === 0 && buf[6] === 0 && buf[7] !== 0) {
        const hostnameEnd = buf.indexOf(0, pos);
        if (hostnameEnd === -1) return; // 还没收到
        host = buf.slice(pos, hostnameEnd).toString();
        pos  = hostnameEnd + 1;
      }

      const rest = buf.slice(pos);
      socket.pause();
      dbg(`SOCKS4 cd=${cd} → ${host}:${port}`);

      if (cd === 0x01) {
        // CONNECT
        let rHost = host;
        if (!net.isIPv4(host) && !net.isIPv6(host)) {
          try {
            const r = await dnsLookup(host, { all: false });
            rHost = r.address;
          } catch (e) {
            socket.write(Buffer.from([0x00, 0x5B, 0, 0, 0, 0, 0, 0])); // rejected
            socket.destroy(); return;
          }
        }
        const remote = net.createConnection({ host: rHost, port }, () => {
          // SOCKS4 成功响应：0x00 0x5A + port(2) + ip(4)
          const resp = Buffer.alloc(8);
          resp[0] = 0x00; resp[1] = 0x5A;
          resp.writeUInt16BE(port, 2);
          socket.write(resp);
          if (rest.length > 0) remote.write(rest);
          socket.resume();
          pipeStreams(socket, remote);
          log('info', `SOCKS4 TCP  ${socket.remoteAddress} → ${host}:${port}`);
        });
        remote.on('error', err => {
          log('error', `SOCKS4 TCP [${host}:${port}]:`, err.message);
          try { socket.write(Buffer.from([0x00, 0x5B, 0, 0, 0, 0, 0, 0])); socket.destroy(); } catch (_) {}
        });
      } else {
        // 不支持 BIND
        socket.write(Buffer.from([0x00, 0x5B, 0, 0, 0, 0, 0, 0]));
        socket.destroy();
      }
    } catch (e) {
      log('error', 'SOCKS4 parse:', e.message);
      socket.destroy();
    }
  };

  socket.on('data', chunk => { buf = Buffer.concat([buf, chunk]); process(); });
  socket.on('error', err => { if (err.code !== 'ECONNRESET') log('error', 'S4 socket:', err.message); });
  socket.resume(); // 确保 socket 处于流动状态
  process();
}

// ─── HTTP 代理 ────────────────────────────────────────────────────────────────

function handleHttp(socket, firstChunk) {
  let buf = firstChunk;

  function tryParse() {
    const sep = buf.indexOf('\r\n\r\n');
    if (sep === -1) {
      if (buf.length > 65536) { socket.destroy(); return; } // 防止内存炸
      socket.once('data', chunk => { buf = Buffer.concat([buf, chunk]); tryParse(); });
      return;
    }

    const headerStr = buf.slice(0, sep).toString('latin1');
    const body      = buf.slice(sep + 4);
    const lines     = headerStr.split('\r\n');
    const [method, url] = lines[0].split(' ');
    if (!method || !url) { socket.destroy(); return; }

    const headers = {};
    for (let i = 1; i < lines.length; i++) {
      const ci = lines[i].indexOf(':');
      if (ci > 0) headers[lines[i].slice(0, ci).trim().toLowerCase()] = lines[i].slice(ci + 1).trim();
    }

    if (method === 'CONNECT') {
      const lastColon = url.lastIndexOf(':');
      const host = url.slice(0, lastColon);
      const port = parseInt(url.slice(lastColon + 1)) || 443;
      log('info', `HTTP CONNECT  ${socket.remoteAddress} → ${host}:${port}`);
      const remote = net.createConnection({ host, port }, () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (body.length > 0) remote.write(body);
        socket.resume();
        pipeStreams(socket, remote);
      });
      remote.on('error', err => {
        log('error', `HTTP CONNECT [${host}:${port}]:`, err.message);
        try { socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.destroy(); } catch (_) {}
      });
    } else {
      let parsedUrl;
      try {
        parsedUrl = new URL(url.startsWith('http') ? url : `http://${headers['host'] || 'localhost'}${url}`);
      } catch (_) { socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); socket.destroy(); return; }

      const host    = parsedUrl.hostname;
      const port    = parseInt(parsedUrl.port) || (parsedUrl.protocol === 'https:' ? 443 : 80);
      const reqPath = parsedUrl.pathname + parsedUrl.search;
      const hdrsOut = Object.entries(headers)
        .filter(([k]) => !['proxy-connection', 'proxy-authorization'].includes(k))
        .map(([k, v]) => `${k}: ${v}`).join('\r\n');
      const rebuiltReq = `${method} ${reqPath} HTTP/1.1\r\n${hdrsOut}\r\n\r\n`;

      log('info', `HTTP ${method}  ${socket.remoteAddress} → ${host}:${port}`);
      const remote = net.createConnection({ host, port }, () => {
        remote.write(rebuiltReq);
        if (body.length > 0) remote.write(body);
        socket.resume();
        pipeStreams(socket, remote);
      });
      remote.on('error', err => {
        log('error', `HTTP [${host}:${port}]:`, err.message);
        try { socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.destroy(); } catch (_) {}
      });
    }
  }

  socket.pause();
  tryParse();
}

// ─── 连接入口 ─────────────────────────────────────────────────────────────────

function handleConnection(socket) {
  socket.once('data', firstChunk => {
    const fb    = firstChunk[0];
    const proto = detectProtocol(fb);
    dbg(`[${socket.remoteAddress}:${socket.remotePort}] first byte=0x${fb.toString(16).padStart(2,'0')} → ${proto}`);

    switch (proto) {
      case 'socks5': handleSocks5(socket, firstChunk); break;
      case 'socks4': handleSocks4(socket, firstChunk); break;
      case 'http':   handleHttp(socket, firstChunk);   break;
      default:
        log('warn', `Unknown protocol, first byte=0x${fb.toString(16)} from ${socket.remoteAddress} — dropping`);
        socket.destroy();
    }
  });

  socket.on('error', err => {
    if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
      log('error', 'Connection error:', err.message);
    }
  });
}

// ─── 启动 ─────────────────────────────────────────────────────────────────────

const bindAddresses = resolveBindAddresses(CONFIG.host);
const servers       = [];  // 支持同时监听多个地址

function createServer(bindHost) {
  const srv = net.createServer(handleConnection);
  srv.on('error', err => {
    if (err.code === 'EADDRNOTAVAIL') {
      // IPv6 不可用时跳过，不崩溃
      log('warn', `跳过不可用地址 ${bindHost}: ${err.message}`);
    } else {
      log('error', `Server [${bindHost}]:`, err.message);
    }
  });
  return new Promise(resolve => {
    srv.listen(CONFIG.port, bindHost, () => {
      const addr = srv.address();
      const disp = isIPv6Addr(addr.address) ? `[${addr.address}]` : addr.address;
      log('info', `  监听: ${disp}:${addr.port}`);
      servers.push(srv);
      resolve();
    });
    srv.on('error', () => resolve()); // 绑定失败时也 resolve，不阻塞其他地址
  });
}

async function startAll() {
  console.log('');
  log('info', '═'.repeat(60));
  log('info', `  代理服务器 (HTTP + SOCKS4/4a/5) 已启动`);
  log('info', '─'.repeat(60));

  for (const addr of bindAddresses) {
    await createServer(addr);
  }

  if (servers.length === 0) {
    log('error', '没有成功监听任何地址，退出');
    process.exit(1);
  }

  log('info', '─'.repeat(60));
  log('info', `  UDP 范围 : ${CONFIG.udpPortRange.min}-${CONFIG.udpPortRange.max}`);
  log('info', `  UDP 轮换 : 每 ${CONFIG.udpRotateAfter} 包换出口端口（第${CONFIG.udpRotateAfter+1}个包用新端口）`);
  log('info', `  旧端口延迟关闭 : ${CONFIG.udpStaleTimeout} ms`);
  log('info', `  调试模式 : ${CONFIG.debug ? '开启' : '关闭 (--debug 开启)'}`);
  log('info', '─'.repeat(60));
  const ex4 = '127.0.0.1', ex6 = '[::1]';
  log('info', `  HTTP  : curl -x http://${ex4}:${CONFIG.port} https://example.com`);
  log('info', `  SOCKS5: curl --socks5 ${ex4}:${CONFIG.port} https://example.com`);
  log('info', `  SOCKS5: curl --socks5 ${ex6}:${CONFIG.port} https://example.com`);
  log('info', '─'.repeat(60));
  log('info', `  --host=dual        本机 IPv4+IPv6（默认）`);
  log('info', `  --host=dual-all    所有接口 IPv4+IPv6（局域网）`);
  log('info', `  --host=127.0.0.1   仅 IPv4 本机`);
  log('info', `  --host=::1         仅 IPv6 本机`);
  log('info', `  --host=0.0.0.0     所有 IPv4 接口`);
  log('info', `  --host=::          所有 IPv6 接口`);
  log('info', `  --port=1080  --udp-min=6811  --udp-max=6922  --udp-rotate=5  --udp-stale-timeout=5000`);
  log('info', '═'.repeat(60));
  console.log('');
}

startAll();

// +++ 新增：全局未捕获异常和未处理拒绝的日志记录 +++
process.on('uncaughtException', (err) => {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] UNCAUGHT EXCEPTION: ${err.stack || err.message}\n`;
  try {
    fs.appendFileSync('crash.log', logMessage);
    console.error(logMessage);
  } catch (e) {
    console.error('Failed to write crash log:', e);
  }
  // 记录后退出，避免进程处于未知状态
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] UNHANDLED REJECTION: ${reason instanceof Error ? reason.stack : reason}\n`;
  try {
    fs.appendFileSync('crash.log', logMessage);
    console.error(logMessage);
  } catch (e) {
    console.error('Failed to write crash log:', e);
  }
  // 未处理的拒绝通常也应退出，或者可根据需要调整
  process.exit(1);
});

['SIGINT', 'SIGTERM'].forEach(sig =>
  process.on(sig, () => {
    log('info', '关闭中...');
    // 最多等 500ms 让 TCP 服务器优雅关闭，之后强制退出
    // （UDP socket 和延迟定时器会阻止 Node 自然退出，必须强制）
    const forceExit = setTimeout(() => process.exit(0), 500);
    forceExit.unref();
    Promise.all(servers.map(s => new Promise(r => s.close(r)))).then(() => process.exit(0));
  })
);