"use strict";
/**
 * Minimal Wisp v1 server (https://github.com/MercuryWorkshop/wisp-protocol)
 *
 * Packet layout (all little-endian):
 *   [1 byte type][4 bytes stream id][payload...]
 *
 * Types:
 *   0x01 CONNECT   payload: [1 byte stream type (1=TCP, 2=UDP)][2 bytes port][hostname utf8]
 *   0x02 DATA      payload: raw bytes
 *   0x03 CONTINUE  payload: [4 bytes remaining buffer, in packets]  (server -> client)
 *   0x04 CLOSE     payload: [1 byte reason]
 *
 * Run:   npm install ws && node server.js
 * Env:   PORT=8080  HOST=0.0.0.0  WISP_PATH=/wisp/
 *        TLS_CERT=/path/fullchain.pem TLS_KEY=/path/privkey.pem   (enables wss:// directly)
 *        ALLOW_PRIVATE=1   (allow connections to private/loopback IPs - local testing only)
 */

const http = require("http");
const https = require("https");
const fs = require("fs");
const net = require("net");
const dgram = require("dgram");
const dns = require("dns").promises;
const path = require("path");
const express = require("express");
const { WebSocketServer } = require("ws");

// ---------- config ----------
const PORT = parseInt(process.env.PORT || "8080", 10); // Render sets PORT
const HOST = process.env.HOST || "0.0.0.0";
const WISP_PATH = process.env.WISP_PATH || "/wisp/";
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === "1";
const BUFFER_SIZE = 128;          // packets the client may have in flight per stream
const MAX_STREAMS = 256;          // per websocket connection
const MAX_QUEUED_PACKETS = 512;   // data buffered while a stream is still connecting
const CONNECT_TIMEOUT_MS = 10_000;
const WS_BACKPRESSURE_BYTES = 4 * 1024 * 1024;

// ---------- protocol constants ----------
const T = { CONNECT: 0x01, DATA: 0x02, CONTINUE: 0x03, CLOSE: 0x04 };
const S = { TCP: 0x01, UDP: 0x02 };
const R = {
  UNSPECIFIED: 0x01,
  VOLUNTARY: 0x02,
  NETWORK_ERROR: 0x03,
  INVALID_INFO: 0x41,
  UNREACHABLE: 0x42,
  TIMEOUT: 0x43,
  REFUSED: 0x44,
  BLOCKED: 0x48,
  THROTTLED: 0x49,
};

// ---------- SSRF protection ----------
const blocklist = new net.BlockList();
[
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4],
].forEach(([a, p]) => blocklist.addSubnet(a, p, "ipv4"));
[
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
].forEach(([a, p]) => blocklist.addSubnet(a, p, "ipv6"));

function isBlocked(ip) {
  if (ALLOW_PRIVATE) return false;
  if (net.isIPv6(ip)) {
    // IPv4-mapped IPv6 (::ffff:a.b.c.d): check the embedded IPv4 address instead.
    // (Don't add a ::ffff:0:0/96 rule to the blocklist: Node treats every IPv4 address as matching it.)
    const m = ip.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (m) ip = m[1];
    else if (/^::ffff:/i.test(ip)) return true;
  }
  return blocklist.check(ip, net.isIPv6(ip) ? "ipv6" : "ipv4");
}

// ---------- packet helpers ----------
function makePacket(type, streamId, payload) {
  const len = payload ? payload.length : 0;
  const buf = Buffer.allocUnsafe(5 + len);
  buf.writeUInt8(type, 0);
  buf.writeUInt32LE(streamId, 1);
  if (len) payload.copy(buf, 5);
  return buf;
}
const continuePacket = (id, remaining) => {
  const p = Buffer.allocUnsafe(4);
  p.writeUInt32LE(remaining, 0);
  return makePacket(T.CONTINUE, id, p);
};
const closePacket = (id, reason) => makePacket(T.CLOSE, id, Buffer.from([reason]));

function errorToReason(err) {
  switch (err && err.code) {
    case "ECONNREFUSED": return R.REFUSED;
    case "ETIMEDOUT": return R.TIMEOUT;
    case "ENOTFOUND":
    case "EHOSTUNREACH":
    case "ENETUNREACH":
    case "EAI_AGAIN": return R.UNREACHABLE;
    default: return R.NETWORK_ERROR;
  }
}

// ---------- server setup ----------
const app = express();
const handler = app;

const server =
  process.env.TLS_CERT && process.env.TLS_KEY
    ? https.createServer(
        { cert: fs.readFileSync(process.env.TLS_CERT), key: fs.readFileSync(process.env.TLS_KEY) },
        handler
      )
    : http.createServer(handler);

const wss = new WebSocketServer({
  noServer: true,
  maxPayload: 1024 * 1024 + 16,
  perMessageDeflate: false,
});

server.on("upgrade", (req, socket, head) => {
  // Wisp clients connect to wss://host/wisp/ (a trailing stream path is allowed)
  const path = (req.url || "").split("?")[0];
  if (!path.startsWith(WISP_PATH)) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
});

// Drop dead connections
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
}, 30_000);
wss.on("close", () => clearInterval(heartbeat));

// ---------- per-connection logic ----------
wss.on("connection", (ws) => {
  ws.isAlive = true;
  ws.on("pong", () => (ws.isAlive = true));

  /** @type {Map<number, any>} */
  const streams = new Map();

  const send = (buf) => {
    if (ws.readyState === ws.OPEN) ws.send(buf, { binary: true });
  };

  // Initial CONTINUE on stream 0 tells the client the per-stream buffer size.
  send(continuePacket(0, BUFFER_SIZE));

  function teardown(id, reason, notifyClient) {
    const s = streams.get(id);
    if (!s) return;
    streams.delete(id);
    s.closed = true;
    try {
      if (s.type === S.TCP) s.sock && s.sock.destroy();
      else s.sock && s.sock.close();
    } catch {}
    if (notifyClient) send(closePacket(id, reason));
  }

  async function handleConnect(id, payload) {
    if (streams.size >= MAX_STREAMS) return send(closePacket(id, R.THROTTLED));
    if (streams.has(id) || id === 0 || payload.length < 4) {
      return send(closePacket(id, R.INVALID_INFO));
    }

    const type = payload.readUInt8(0);
    const port = payload.readUInt16LE(1);
    const host = payload.toString("utf8", 3);
    if ((type !== S.TCP && type !== S.UDP) || port === 0 || !host) {
      return send(closePacket(id, R.INVALID_INFO));
    }

    const stream = {
      id, type, sock: null, closed: false, ready: false,
      queue: [], pending: 0, flushed: 0,
    };
    streams.set(id, stream); // register now so early DATA packets get queued

    // Resolve + validate before connecting (prevents DNS-rebinding style SSRF)
    let ip = host;
    try {
      if (!net.isIP(host)) {
        try { ip = (await dns.lookup(host, { family: 4 })).address; }   // prefer IPv4
        catch { ip = (await dns.lookup(host)).address; }
      }
    } catch (err) {
      console.warn(`[dns error] ${host} ${err.code || ""}`);
      return teardown(id, R.UNREACHABLE, true);
    }
    if (stream.closed) return;
    if (isBlocked(ip)) { console.warn(`[blocked] ${host} -> ${ip}`); return teardown(id, R.BLOCKED, true); }

    if (type === S.TCP) openTcp(stream, ip, port);
    else openUdp(stream, ip, port);
  }

  function flushQueue(stream) {
    stream.ready = true;
    for (const chunk of stream.queue) writeToStream(stream, chunk);
    stream.queue = [];
  }

  function openTcp(stream, ip, port) {
    const sock = net.connect({ host: ip, port });
    stream.sock = sock;
    sock.setNoDelay(true);
    sock.setTimeout(CONNECT_TIMEOUT_MS);

    sock.once("connect", () => {
      sock.setTimeout(0);
      flushQueue(stream);
    });
    sock.on("timeout", () => teardown(stream.id, R.TIMEOUT, true));
    sock.on("data", (chunk) => {
      if (stream.closed) return;
      send(makePacket(T.DATA, stream.id, chunk));
      // backpressure towards the websocket
      if (ws.bufferedAmount > WS_BACKPRESSURE_BYTES) {
        sock.pause();
        const t = setInterval(() => {
          if (stream.closed || ws.bufferedAmount < WS_BACKPRESSURE_BYTES / 2) {
            clearInterval(t);
            if (!stream.closed) sock.resume();
          }
        }, 25);
      }
    });
    sock.on("error", (err) => {
      console.warn(`[tcp error] ${ip}:${port} ${err.code || ""} ${err.message}`);
      teardown(stream.id, errorToReason(err), true);
    });
    sock.on("close", () => teardown(stream.id, R.VOLUNTARY, true));
  }

  function openUdp(stream, ip, port) {
    const sock = dgram.createSocket(net.isIPv6(ip) ? "udp6" : "udp4");
    stream.sock = sock;
    sock.on("error", (err) => teardown(stream.id, errorToReason(err), true));
    sock.on("message", (msg) => !stream.closed && send(makePacket(T.DATA, stream.id, msg)));
    sock.connect(port, ip, () => flushQueue(stream));
  }

  function writeToStream(stream, data) {
    if (stream.type === S.UDP) {
      stream.sock.send(data, () => {});
      return;
    }
    stream.pending++;
    stream.sock.write(data, () => {
      stream.pending--;
      stream.flushed++;
      // Tell the client it can send more once we've drained half the buffer.
      if (!stream.closed && stream.flushed >= BUFFER_SIZE / 2) {
        stream.flushed = 0;
        send(continuePacket(stream.id, BUFFER_SIZE - stream.pending));
      }
    });
  }

  function handleData(id, payload) {
    const stream = streams.get(id);
    if (!stream) return; // unknown stream: ignore
    if (stream.ready) return writeToStream(stream, payload);
    if (stream.queue.length >= MAX_QUEUED_PACKETS) return teardown(id, R.THROTTLED, true);
    stream.queue.push(Buffer.from(payload)); // copy: ws may reuse the buffer
  }

  ws.on("message", (data, isBinary) => {
    if (!isBinary) return;
    const buf = Buffer.isBuffer(data) ? data : Buffer.concat(data);
    if (buf.length < 5) return;

    const type = buf.readUInt8(0);
    const id = buf.readUInt32LE(1);
    const payload = buf.subarray(5);

    switch (type) {
      case T.CONNECT: handleConnect(id, payload).catch(() => teardown(id, R.NETWORK_ERROR, true)); break;
      case T.DATA: handleData(id, payload); break;
      case T.CLOSE: teardown(id, 0, false); break;
      default: break; // CONTINUE is server->client only
    }
  });

  const cleanup = () => { for (const id of [...streams.keys()]) teardown(id, 0, false); };
  ws.on("close", cleanup);
  ws.on("error", cleanup);
});

(async () => {
  // These packages are ESM-only, so load them with dynamic import().
  const sjMod = await import("@mercuryworkshop/scramjet/path");
  const scramjetPath =
    sjMod.scramjetPath || sjMod.path || sjMod.default ||
    path.join(__dirname, "node_modules/@mercuryworkshop/scramjet/dist");
  const { baremuxPath } = await import("@mercuryworkshop/bare-mux/node");
  const { epoxyPath } = await import("@mercuryworkshop/epoxy-transport");

  app.get("/health", (req, res) => res.json({ status: "ok" }));
  app.use("/scram/", express.static(scramjetPath));
  app.use("/baremux/", express.static(baremuxPath));
  app.use("/epoxy/", express.static(epoxyPath));
  app.use(express.static(path.join(__dirname, "public")));

  server.listen(PORT, HOST, () => {
    const scheme = process.env.TLS_CERT ? "https" : "http";
    console.log(`Proxy site:  ${scheme}://${HOST}:${PORT}/`);
    console.log(`Wisp server: ${scheme === "https" ? "wss" : "ws"}://${HOST}:${PORT}${WISP_PATH}`);
    if (ALLOW_PRIVATE) console.warn("WARNING: ALLOW_PRIVATE=1, private IPs are reachable through this server");
  });
})();
