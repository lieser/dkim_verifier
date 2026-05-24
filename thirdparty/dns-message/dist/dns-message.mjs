let t = function(t) {
  t[t.QUERY = 0] = "QUERY";
  t[t.RESPONSE = 32768] = "RESPONSE";
  return t;
}({});

let e = function(t) {
  t[t.A = 1] = "A";
  t[t.NS = 2] = "NS";
  t[t.CNAME = 5] = "CNAME";
  t[t.SOA = 6] = "SOA";
  t[t.NULL = 10] = "NULL";
  t[t.PTR = 12] = "PTR";
  t[t.HINFO = 13] = "HINFO";
  t[t.MX = 15] = "MX";
  t[t.TXT = 16] = "TXT";
  t[t.RP = 17] = "RP";
  t[t.AFSDB = 18] = "AFSDB";
  t[t.SIG = 24] = "SIG";
  t[t.KEY = 25] = "KEY";
  t[t.AAAA = 28] = "AAAA";
  t[t.LOC = 29] = "LOC";
  t[t.SRV = 33] = "SRV";
  t[t.NAPTR = 35] = "NAPTR";
  t[t.KX = 36] = "KX";
  t[t.CERT = 37] = "CERT";
  t[t.DNAME = 39] = "DNAME";
  t[t.OPT = 41] = "OPT";
  t[t.APL = 42] = "APL";
  t[t.DS = 43] = "DS";
  t[t.SSHFP = 44] = "SSHFP";
  t[t.IPSECKEY = 45] = "IPSECKEY";
  t[t.RRSIG = 46] = "RRSIG";
  t[t.NSEC = 47] = "NSEC";
  t[t.DNSKEY = 48] = "DNSKEY";
  t[t.DHCID = 49] = "DHCID";
  t[t.NSEC3 = 50] = "NSEC3";
  t[t.NSEC3PARAM = 51] = "NSEC3PARAM";
  t[t.TLSA = 52] = "TLSA";
  t[t.HIP = 55] = "HIP";
  t[t.CDS = 59] = "CDS";
  t[t.CDNSKEY = 60] = "CDNSKEY";
  t[t.SVCB = 64] = "SVCB";
  t[t.HTTPS = 65] = "HTTPS";
  t[t.SPF = 99] = "SPF";
  t[t.TKEY = 249] = "TKEY";
  t[t.TSIG = 250] = "TSIG";
  t[t.IXFR = 251] = "IXFR";
  t[t.AXFR = 252] = "AXFR";
  t[t.ANY = 255] = "ANY";
  t[t.CAA = 257] = "CAA";
  t[t.TA = 32768] = "TA";
  t[t.DLV = 32769] = "DLV";
  return t;
}({});

let r = function(t) {
  t[t.IN = 1] = "IN";
  t[t.CS = 2] = "CS";
  t[t.CH = 3] = "CH";
  t[t.HS = 4] = "HS";
  t[t.ANY = 255] = "ANY";
  return t;
}({});

let n = function(t) {
  t[t.NOERR = 0] = "NOERR";
  t[t.FORMERR = 1] = "FORMERR";
  t[t.SERVFAIL = 2] = "SERVFAIL";
  t[t.NXDOMAIN = 3] = "NXDOMAIN";
  t[t.NOTIMP = 4] = "NOTIMP";
  t[t.REFUSED = 5] = "REFUSED";
  t[t.YXDOMAIN = 6] = "YXDOMAIN";
  t[t.YXRRSET = 7] = "YXRRSET";
  t[t.NXRRSET = 8] = "NXRRSET";
  t[t.NOTAUTH = 9] = "NOTAUTH";
  t[t.NOTZONE = 10] = "NOTZONE";
  t[t.CHECKING_DISABLED = 16] = "CHECKING_DISABLED";
  t[t.AUTHENTIC_DATA = 32] = "AUTHENTIC_DATA";
  t[t.RECURSION_AVAILABLE = 128] = "RECURSION_AVAILABLE";
  t[t.RECURSION_DESIRED = 256] = "RECURSION_DESIRED";
  t[t.TRUNCATED_RESPONSE = 512] = "TRUNCATED_RESPONSE";
  t[t.AUTHORITATIVE_ANSWER = 1024] = "AUTHORITATIVE_ANSWER";
  return t;
}({});

let s = function(t) {
  t[t.OPTION_0 = 0] = "OPTION_0";
  t[t.LLQ = 1] = "LLQ";
  t[t.UL = 2] = "UL";
  t[t.NSID = 3] = "NSID";
  t[t.OPTION_4 = 4] = "OPTION_4";
  t[t.DAU = 5] = "DAU";
  t[t.DHU = 6] = "DHU";
  t[t.N3U = 7] = "N3U";
  t[t.CLIENT_SUBNET = 8] = "CLIENT_SUBNET";
  t[t.EXPIRE = 9] = "EXPIRE";
  t[t.COOKIE = 10] = "COOKIE";
  t[t.TCP_KEEPALIVE = 11] = "TCP_KEEPALIVE";
  t[t.PADDING = 12] = "PADDING";
  t[t.CHAIN = 13] = "CHAIN";
  t[t.KEY_TAG = 14] = "KEY_TAG";
  t[t.DEVICEID = 26946] = "DEVICEID";
  t[t.OPTION_65535 = 65535] = "OPTION_65535";
  return t;
}({});

const a = new TextEncoder;

const i = new TextDecoder;

const o = "undefined" != typeof Buffer ? t => Buffer.byteLength(t) : t => {
  let e = t.length;
  for (let r = e - 1; r >= 0; r--) {
    const n = t.charCodeAt(r);
    if (n > 127 && n <= 2047) {
      e++;
    } else if (n > 2047 && n <= 65535) {
      e += 2;
    }
    if (n >= 56320 && n <= 57343) {
      r--;
    }
  }
  return e;
};

const c = {
  bytes(t) {
    let e = 2;
    switch (t) {
     case "":
     case ".":
     case "..":
      return 1;

     default:
      if ("." === t[0]) {
        e--;
      }
      if ("." === t[t.length - 1]) {
        e--;
      }
      e += t.replace(/\\\./g, ".").length;
      if (e > 255) {
        throw new RangeError(`Name "${t}" is above 255 byte limit.`);
      }
      return e;
    }
  },
  write(t, e, r) {
    const n = a.encode(r);
    for (let s = 46 === n[0] ? 1 : 0, a = 0; s < n.byteLength; s = a + 1) {
      a = n.indexOf(46, s);
      while (a > -1 && 92 === n[a - 1]) {
        a = n.indexOf(46, a + 1);
      }
      if (-1 === a) {
        a = n.byteLength;
      }
      if (a === s) {
        continue;
      } else if (a - s > 63) {
        throw new RangeError(`Label in "${r}" is above 63 byte limit.`);
      }
      let i = e + 1;
      for (let e = s; e < a; e++) {
        if (92 === n[e] && 46 === n[e + 1]) {
          e++;
        }
        t.setUint8(i++, n[e]);
      }
      t.setUint8(e, i - e - 1);
      e = i;
      s = a + 1;
    }
    return e + 1;
  },
  read(t, e) {
    const r = [];
    let n = e.offset;
    let s = e;
    while (1) {
      const e = t.getUint8(s.offset);
      if (0 === e) {
        advance(s, 1);
        break;
      } else if (!(192 & e)) {
        advance(s, 1);
        const n = sliceView(t, s, e);
        r.push(i.decode(n).replace(/\./g, "\\."));
      } else {
        const e = t.getUint16(s.offset) - 49152;
        advance(s, 2);
        if (e < n) {
          s = {
            offset: n = e,
            length: 0
          };
        } else {
          break;
        }
      }
    }
    return r.join(".") || ".";
  }
};

const f = {
  bytes: t => "string" == typeof t ? o(t) : t.byteLength,
  write(t, e, r) {
    const n = "string" == typeof r ? a.encode(r) : r;
    new Uint8Array(t.buffer, t.byteOffset + e, n.byteLength).set(n);
    return e + n.byteLength;
  },
  read: (t, e) => sliceView(t, e)
};

const d = {
  bytes: t => t.byteLength + 1,
  write(t, e, r) {
    t.setUint8(e++, r.byteLength);
    new Uint8Array(t.buffer, t.byteOffset + e, r.byteLength).set(r);
    return e + r.byteLength;
  },
  read(t, e) {
    const r = t.getUint8(e.offset);
    advance(e, 1);
    return sliceView(t, e, r);
  }
};

const u = {
  bytes: t => o(t) + 1,
  write(t, e, r) {
    const n = a.encode(r);
    t.setUint8(e++, n.byteLength);
    return f.write(t, e, n);
  },
  read(t, e) {
    const r = t.getUint8(e.offset);
    advance(e, 1);
    return i.decode(sliceView(t, e, r));
  }
};

const l = {
  bytes(t) {
    const e = [];
    for (let r = 0; r < t.length; r++) {
      e[t[r] >> 8] = Math.max(e[t[r] >> 8] || 0, 255 & t[r]);
    }
    let r = 0;
    for (let t = 0; t < e.length; t++) {
      if (null != e[t]) {
        r += 2 + Math.ceil((e[t] + 1) / 8);
      }
    }
    return r;
  },
  write(t, e, r) {
    const n = [];
    for (let t = 0; t < r.length; t++) {
      (n[r[t] >> 8] || (n[r[t] >> 8] = []))[r[t] >> 3 & 31] |= 1 << 7 - (7 & r[t]);
    }
    for (let r = 0; r < n.length; r++) {
      const s = n[r];
      if (null != s) {
        t.setUint8(e++, r);
        t.setUint8(e++, s.length);
        for (let r = 0; r < s.length; r++) {
          t.setUint8(e++, s[r]);
        }
      }
    }
    return e;
  },
  read(t, e) {
    const {offset: r, length: n} = e;
    const s = [];
    while (e.offset - r < n) {
      const r = t.getUint8(e.offset);
      const n = t.getUint8(e.offset + 1);
      for (let a = 0; a < n; a++) {
        const n = t.getUint8(e.offset + 2 + a);
        for (let t = 0; t < 8; t++) {
          if (n & 1 << 7 - t) {
            s.push(r << 8 | a << 3 | t);
          }
        }
      }
      advance(e, 2 + n);
    }
    return s;
  }
};

const g = {
  bytes: () => 4,
  write(t, e, r) {
    const n = r.split(".", 4);
    for (let r = 0; r < 4; r++) {
      t.setUint8(e++, parseInt(n[r], 10));
    }
    return e;
  },
  read(t, e) {
    const r = Math.min(e.length, 4);
    const n = new Array(4).fill(0).map((n, s) => s < r ? t.getUint8(e.offset + s) : 0).join(".");
    advance(e, r);
    return n;
  }
};

const y = {
  bytes: () => 2,
  write(t, e, r) {
    t.setUint16(e, r);
    return e + 2;
  },
  read(t, e) {
    const r = t.getUint16(e.offset);
    advance(e, 2);
    return r;
  }
};

const U = {
  bytes: () => 16,
  write(t, e, r) {
    const n = r.indexOf("::");
    const s = (n > -1 ? r.slice(0, n) : r).split(":");
    const a = n > -1 ? r.slice(n + 2).split(":") : [];
    const i = a.length > 0 && a[a.length - 1].includes(".") ? a.pop() : void 0;
    for (let r = 0; r < s.length; r++) {
      t.setUint16(e, parseInt(s[r], 16));
      e += 2;
    }
    for (let r = 8 - (s.length + a.length + (i ? 2 : 0)); r > 0; r--) {
      t.setUint16(e, 0);
      e += 2;
    }
    for (let r = 0; r < a.length; r++) {
      t.setUint16(e, parseInt(a[r], 16));
      e += 2;
    }
    if (i) {
      const r = i.split(".", 4).map(t => parseInt(t, 10));
      t.setUint16(e, r[0] << 8 | r[1]);
      t.setUint16(e + 2, r[2] << 8 | r[3]);
      e += 4;
    }
    return e;
  },
  read(t, e) {
    let r = "";
    const n = Math.min(e.length, 16);
    for (let s = 0; s < n; s += 2) {
      if (0 !== s) {
        r += ":";
      }
      r += t.getUint16(e.offset + s).toString(16);
    }
    advance(e, n);
    return r.replace(/(^|:)0(:0)*:0(:|$)/, "$1::$3").replace(/:{3,4}/, "::");
  }
};

const withRDLength = t => ({
  bytes: e => t.bytes(e) + 2,
  write(e, r, n) {
    const s = r;
    r = t.write(e, r + 2, n);
    e.setUint16(s, r - s - 2);
    return r;
  },
  read(e, r) {
    const {offset: n, length: s} = r;
    const a = r.length = e.getUint16(r.offset);
    r.offset += 2;
    const i = t.read(e, r);
    r.offset = n + 2 + a;
    r.length = s;
    return i;
  }
});

const array = t => ({
  bytes(e) {
    let r = 0;
    for (let n = 0; null != e && n < e.length; n++) {
      r += t.bytes(e[n]);
    }
    return r;
  },
  write(e, r, n) {
    for (let s = 0; null != n && s < n.length; s++) {
      r = t.write(e, r, n[s]);
    }
    return r;
  },
  read(e, r) {
    const {offset: n, length: s} = r;
    const a = [];
    while (r.offset - n < s) {
      a.push(t.read(e, r));
    }
    return a;
  }
});

const advance = (t, e) => {
  t.offset += 0 | e;
  t.length -= 0 | e;
  t.length &= ~(t.length >> 31);
};

const encodeIntoBuffer = (t, e) => {
  const r = new ArrayBuffer(t.bytes(e));
  const n = t.write(new DataView(r), 0, e);
  return new Uint8Array(r, 0, n);
};

const sliceView = (t, e, r = e.length) => {
  const n = new Uint8Array(t.buffer, t.byteOffset + e.offset, r);
  advance(e, r);
  return n;
};

const b = {
  bytes: t => c.bytes(t.name) + 4,
  write(t, e, n) {
    let s = n.class || r.IN;
    if (n.qu) {
      s |= 32768;
    }
    e = c.write(t, e, n.name);
    t.setUint16(e, n.type);
    t.setUint16(e + 2, s);
    return e + 4;
  },
  read(t, e) {
    const n = c.read(t, e);
    const s = t.getUint16(e.offset);
    let a = t.getUint16(e.offset + 2) || r.ANY;
    let i = !1;
    if (a !== r.ANY && 32768 & a) {
      a &= -32769;
      i = !0;
    }
    advance(e, 4);
    return {
      name: n,
      type: s,
      class: a,
      qu: i
    };
  }
};

const h = withRDLength({
  bytes: t => f.bytes(t.data),
  write: (t, e, r) => f.write(t, e, r.data),
  read: (t, e) => ({
    code: s.OPTION_0,
    data: f.read(t, e)
  })
});

const w = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])";

const A = new RegExp(`^(?:${w}\\.){3}${w}$`);

const E = withRDLength({
  bytes: t => Math.ceil((t.sourcePrefixLength || 0) / 8) + 4,
  write(t, e, r) {
    const n = r.sourcePrefixLength || 0;
    const s = r.scopePrefixLength || 0;
    const a = r.family || (A.test(r.ip) ? 1 : 2);
    const i = Math.ceil(n / 8);
    t.setUint16(e, a);
    t.setUint8(e + 2, n);
    t.setUint8(e + 3, s);
    e += 4;
    const o = encodeIntoBuffer(1 === a ? g : U, r.ip);
    for (let r = 0; r < i; r++) {
      t.setUint8(e++, o[r]);
    }
    return e;
  },
  read(t, e) {
    const r = t.getUint16(e.offset);
    const n = t.getUint8(e.offset + 2);
    const a = t.getUint8(e.offset + 3);
    advance(e, 4);
    return {
      code: s.CLIENT_SUBNET,
      family: r,
      sourcePrefixLength: n,
      scopePrefixLength: a,
      ip: 1 === r ? g.read(t, e) : U.read(t, e)
    };
  }
});

const S = withRDLength({
  bytes: t => t.timeout ? 2 : 0,
  write(t, e, r) {
    if (r.timeout) {
      t.setUint16(e, r.timeout);
      e += 2;
    }
    return e;
  },
  read(t, e) {
    if (e.length) {
      const r = t.getUint16(e.offset);
      advance(e, 2);
      return {
        code: s.TCP_KEEPALIVE,
        timeout: r
      };
    } else {
      return {
        code: s.TCP_KEEPALIVE,
        timeout: void 0
      };
    }
  }
});

const N = withRDLength({
  bytes: t => t.length || 0,
  write: (t, e, r) => e + (r.length || 0),
  read(t, e) {
    const {length: r} = e;
    advance(e, r);
    return {
      code: s.PADDING,
      length: r
    };
  }
});

const p = withRDLength({
  bytes: t => 2 * t.tags.length,
  write(t, e, r) {
    for (let n = 0; n < r.tags.length; n++) {
      t.setUint16(e, r.tags[n]);
      e += 2;
    }
    return e;
  },
  read(t, e) {
    const {offset: r, length: n} = e;
    const a = [];
    while (e.offset - r < n) {
      a.push(t.getUint16(e.offset));
      advance(e, 2);
    }
    return {
      code: s.KEY_TAG,
      tags: a
    };
  }
});

const isUnknownOpt = t => !!t.data;

const T = {
  bytes(t) {
    if (isUnknownOpt(t)) {
      return h.bytes(t) + 2;
    }
    switch (t.code) {
     case s.CLIENT_SUBNET:
      return E.bytes(t) + 2;

     case s.TCP_KEEPALIVE:
      return S.bytes(t) + 2;

     case s.PADDING:
      return N.bytes(t) + 2;

     case s.KEY_TAG:
      return p.bytes(t) + 2;
    }
  },
  write(t, e, r) {
    t.setUint16(e, r.code);
    e += 2;
    if (isUnknownOpt(r)) {
      return h.write(t, e, r);
    }
    switch (r.code) {
     case s.CLIENT_SUBNET:
      return E.write(t, e, r);

     case s.TCP_KEEPALIVE:
      return S.write(t, e, r);

     case s.PADDING:
      return N.write(t, e, r);

     case s.KEY_TAG:
      return p.write(t, e, r);
    }
  },
  read(t, e) {
    const r = t.getUint16(e.offset);
    advance(e, 2);
    switch (r) {
     case s.CLIENT_SUBNET:
      return E.read(t, e);

     case s.TCP_KEEPALIVE:
      return S.read(t, e);

     case s.PADDING:
      return N.read(t, e);

     case s.KEY_TAG:
      return p.read(t, e);

     default:
      const n = h.read(t, e);
      n.code = r;
      return n;
    }
  }
};

const R = withRDLength(array(y));

const I = withRDLength(array(u));

const P = withRDLength(y);

const D = withRDLength(array(g));

const C = withRDLength(array(U));

const m = withRDLength(f);

const L = {
  bytes(t) {
    let e = 0;
    if (null != t.mandatory) {
      e += R.bytes(t.mandatory) + 2;
    }
    if (null != t.alpn) {
      e += I.bytes(t.alpn) + 2;
    }
    if (t["no-default-alpn"]) {
      e += 4;
    }
    if (null != t.port) {
      e += P.bytes(t.port) + 2;
    }
    if (t.ipv4hint) {
      e += D.bytes(t.ipv4hint) + 2;
    }
    if (t.ipv6hint) {
      e += C.bytes(t.ipv6hint) + 2;
    }
    if (t.echconfig) {
      e += m.bytes(t.echconfig) + 2;
    }
    if (t.dohpath) {
      e += m.bytes(t.dohpath) + 2;
    }
    if (t.odoh) {
      e += m.bytes(t.odoh) + 2;
    }
    return e;
  },
  write(t, e, r) {
    if (null != r.mandatory) {
      t.setUint16(e, 0);
      e = R.write(t, e + 2, r.mandatory);
    }
    if (null != r.alpn) {
      t.setUint16(e, 1);
      e = I.write(t, e + 2, r.alpn);
    }
    if (r["no-default-alpn"]) {
      t.setUint16(e, 2);
      t.setUint16(e + 2, 0);
      e += 4;
    }
    if (null != r.port) {
      t.setUint16(e, 3);
      e = P.write(t, e + 2, r.port);
    }
    if (r.ipv4hint) {
      t.setUint16(e, 4);
      e = D.write(t, e + 2, r.ipv4hint);
    }
    if (r.ipv6hint) {
      t.setUint16(e, 6);
      e = C.write(t, e + 2, r.ipv6hint);
    }
    if (r.echconfig) {
      t.setUint16(e, 5);
      e = m.write(t, e + 2, r.echconfig);
    }
    if (r.dohpath) {
      t.setUint16(e, 7);
      e = m.write(t, e + 2, r.dohpath);
    }
    if (r.odoh) {
      t.setUint16(e, 32769);
      e = m.write(t, e + 2, r.odoh);
    }
    return e;
  },
  read(t, e) {
    const {length: r, offset: n} = e;
    const s = {
      mandatory: void 0,
      alpn: void 0,
      "no-default-alpn": !1,
      port: void 0,
      ipv4hint: void 0,
      ipv6hint: void 0,
      echconfig: void 0,
      dohpath: void 0,
      odoh: void 0
    };
    while (e.offset - n < r) {
      const r = t.getUint16(e.offset);
      advance(e, 2);
      switch (r) {
       case 0:
        s.mandatory = R.read(t, e);
        break;

       case 1:
        s.alpn = I.read(t, e);
        break;

       case 2:
        s["no-default-alpn"] = !0;
        advance(e, 2);
        break;

       case 3:
        s.port = P.read(t, e);
        break;

       case 4:
        s.ipv4hint = D.read(t, e);
        break;

       case 6:
        s.ipv6hint = C.read(t, e);
        break;

       case 5:
        s.echconfig = m.read(t, e);
        break;

       case 7:
        s.dohpath = i.decode(m.read(t, e));
        break;

       case 32769:
        s.odoh = m.read(t, e);
        break;

       default:
        m.read(t, e);
      }
    }
    return s;
  }
};

const O = withRDLength(f);

const k = withRDLength(c);

const x = withRDLength(g);

const H = withRDLength(U);

const V = withRDLength(array(u));

const _ = withRDLength({
  bytes: t => c.bytes(t.target) + 6,
  write(t, e, r) {
    t.setUint16(e, r.priority || 0);
    t.setUint16(e + 2, r.weight || 0);
    t.setUint16(e + 4, r.port || 0);
    return c.write(t, e + 6, r.target);
  },
  read(t, e) {
    const r = {
      priority: 0,
      weight: 0,
      port: 0,
      target: ""
    };
    r.priority = t.getUint16(e.offset);
    r.weight = t.getUint16(e.offset + 2);
    r.port = t.getUint16(e.offset + 4);
    advance(e, 6);
    r.target = c.read(t, e);
    return r;
  }
});

const M = withRDLength({
  bytes: t => u.bytes(t.cpu) + u.bytes(t.os),
  write(t, e, r) {
    e = u.write(t, e, r.cpu);
    return u.write(t, e, r.os);
  },
  read: (t, e) => ({
    cpu: u.read(t, e),
    os: u.read(t, e)
  })
});

const toCaaTag = t => {
  switch (t) {
   case "issue":
   case "issuewild":
   case "iodef":
    return t;

   default:
    return "issue";
  }
};

const Y = withRDLength({
  bytes: t => u.bytes(t.tag) + f.bytes(t.value) + 1,
  write(t, e, r) {
    let n = r.flags || 0;
    if (r.issuerCritical) {
      n |= 128;
    }
    t.setUint8(e, n);
    e = u.write(t, e + 1, r.tag);
    return f.write(t, e, r.value);
  },
  read(t, e) {
    const r = t.getUint8(e.offset);
    advance(e, 1);
    return {
      flags: r,
      tag: toCaaTag(u.read(t, e)),
      value: f.read(t, e),
      issuerCritical: !!(128 & r)
    };
  }
});

const K = withRDLength({
  bytes: t => c.bytes(t.mname) + c.bytes(t.rname) + 20,
  write(t, e, r) {
    e = c.write(t, e, r.mname);
    e = c.write(t, e, r.rname);
    t.setUint32(e, r.serial || 0);
    t.setUint32(e + 4, r.refresh || 0);
    t.setUint32(e + 8, r.retry || 0);
    t.setUint32(e + 12, r.expire || 0);
    t.setUint32(e + 16, r.minimum || 0);
    return e + 20;
  },
  read(t, e) {
    const r = {
      mname: c.read(t, e),
      rname: c.read(t, e),
      serial: t.getUint32(e.offset),
      refresh: t.getUint32(e.offset + 4),
      retry: t.getUint32(e.offset + 8),
      expire: t.getUint32(e.offset + 12),
      minimum: t.getUint32(e.offset + 16)
    };
    e.offset += 20;
    e.length -= 20;
    return r;
  }
});

const v = withRDLength({
  bytes: t => c.bytes(t.exchange) + 2,
  write(t, e, r) {
    t.setUint16(e, r.preference || 0);
    return c.write(t, e + 2, r.exchange);
  },
  read(t, e) {
    const r = {
      preference: t.getUint16(e.offset),
      exchange: ""
    };
    advance(e, 2);
    r.exchange = c.read(t, e);
    return r;
  }
});

const X = withRDLength({
  bytes: t => f.bytes(t.key) + 4,
  write(t, e, r) {
    t.setUint16(e, r.flags);
    t.setUint8(e + 2, 3);
    t.setUint8(e + 3, r.algorithm);
    return f.write(t, e + 4, r.key);
  },
  read(t, e) {
    const r = t.getUint16(e.offset);
    const n = t.getUint8(e.offset + 3);
    advance(e, 4);
    return {
      flags: r,
      algorithm: n,
      key: f.read(t, e)
    };
  }
});

const F = withRDLength({
  bytes: t => 18 + c.bytes(t.signersName) + f.bytes(t.signature),
  write(t, e, r) {
    t.setUint16(e, r.typeCovered);
    t.setUint8(e + 2, r.algorithm);
    t.setUint8(e + 3, r.labels);
    t.setUint32(e + 4, r.originalTTL);
    t.setUint32(e + 8, r.expiration);
    t.setUint32(e + 12, r.inception);
    t.setUint16(e + 16, r.keyTag);
    e = c.write(t, e + 18, r.signersName);
    return f.write(t, e, r.signature);
  },
  read(t, e) {
    const r = t.getUint16(e.offset);
    const n = t.getUint8(e.offset + 2);
    const s = t.getUint8(e.offset + 3);
    const a = t.getUint32(e.offset + 4);
    const i = t.getUint32(e.offset + 8);
    const o = t.getUint32(e.offset + 12);
    const d = t.getUint16(e.offset + 16);
    advance(e, 18);
    return {
      typeCovered: r,
      algorithm: n,
      labels: s,
      originalTTL: a,
      expiration: i,
      inception: o,
      keyTag: d,
      signersName: c.read(t, e),
      signature: f.read(t, e)
    };
  }
});

const G = withRDLength({
  bytes: t => c.bytes(t.mbox) + c.bytes(t.txt),
  write(t, e, r) {
    e = c.write(t, e, r.mbox);
    return c.write(t, e, r.txt);
  },
  read: (t, e) => ({
    mbox: c.read(t, e),
    txt: c.read(t, e)
  })
});

const B = withRDLength({
  bytes: t => c.bytes(t.nextDomain) + l.bytes(t.rrtypes),
  write(t, e, r) {
    e = c.write(t, e, r.nextDomain);
    return l.write(t, e, r.rrtypes);
  },
  read: (t, e) => ({
    nextDomain: c.read(t, e),
    rrtypes: l.read(t, e)
  })
});

const $ = withRDLength({
  bytes: t => d.bytes(t.salt) + d.bytes(t.nextDomain) + l.bytes(t.rrtypes) + 4,
  write(t, e, r) {
    t.setUint8(e, r.algorithm);
    t.setUint8(e + 1, r.flags);
    t.setUint16(e + 2, r.iterations);
    e = d.write(t, e + 4, r.salt);
    e = d.write(t, e, r.nextDomain);
    return l.write(t, e, r.rrtypes);
  },
  read(t, e) {
    const r = t.getUint8(e.offset);
    const n = t.getUint8(e.offset + 1);
    const s = t.getUint16(e.offset + 2);
    advance(e, 4);
    return {
      algorithm: r,
      flags: n,
      iterations: s,
      salt: d.read(t, e),
      nextDomain: d.read(t, e),
      rrtypes: l.read(t, e)
    };
  }
});

const q = withRDLength({
  bytes: t => f.bytes(t.fingerprint) + 2,
  write(t, e, r) {
    t.setUint8(e, r.algorithm);
    t.setUint8(e + 1, r.hash);
    return f.write(t, e + 2, r.fingerprint);
  },
  read(t, e) {
    const r = t.getUint8(e.offset);
    const n = t.getUint8(e.offset + 1);
    advance(e, 2);
    return {
      algorithm: r,
      hash: n,
      fingerprint: f.read(t, e)
    };
  }
});

const Q = withRDLength({
  bytes: t => f.bytes(t.digest) + 4,
  write(t, e, r) {
    t.setUint16(e, r.keyTag);
    t.setUint8(e + 2, r.algorithm);
    t.setUint8(e + 3, r.digestType);
    return f.write(t, e + 4, r.digest);
  },
  read(t, e) {
    const r = t.getUint16(e.offset);
    const n = t.getUint8(e.offset + 2);
    const s = t.getUint8(e.offset + 3);
    advance(e, 4);
    return {
      keyTag: r,
      algorithm: n,
      digestType: s,
      digest: f.read(t, e)
    };
  }
});

const j = withRDLength({
  bytes: t => u.bytes(t.flags) + u.bytes(t.services) + u.bytes(t.regexp) + c.bytes(t.replacement) + 4,
  write(t, e, r) {
    t.setUint16(e, r.order);
    t.setUint16(e + 2, r.preference);
    e = u.write(t, e + 4, r.flags);
    e = u.write(t, e, r.services);
    e = u.write(t, e, r.regexp);
    return c.write(t, e, r.replacement);
  },
  read(t, e) {
    const r = t.getUint16(e.offset);
    const n = t.getUint16(e.offset + 2);
    advance(e, 4);
    return {
      order: r,
      preference: n,
      flags: u.read(t, e),
      services: u.read(t, e),
      regexp: u.read(t, e),
      replacement: c.read(t, e)
    };
  }
});

const z = withRDLength({
  bytes: t => f.bytes(t.certificate) + 3,
  write(t, e, r) {
    t.setUint8(e, r.usage);
    t.setUint8(e + 1, r.selector);
    t.setUint8(e + 2, r.matchingType);
    return f.write(t, e + 3, r.certificate);
  },
  read(t, e) {
    const r = t.getUint8(e.offset);
    const n = t.getUint8(e.offset + 1);
    const s = t.getUint8(e.offset + 2);
    advance(e, 3);
    return {
      usage: r,
      selector: n,
      matchingType: s,
      certificate: f.read(t, e)
    };
  }
});

const W = withRDLength({
  bytes: t => c.bytes(t.name) + L.bytes(t.params) + 2,
  write(t, e, r) {
    t.setUint16(e, r.priority || 0);
    e = c.write(t, e + 2, r.name);
    return L.write(t, e, r.params);
  },
  read(t, e) {
    const r = t.getUint16(e.offset);
    advance(e, 2);
    return {
      name: c.read(t, e),
      priority: r,
      params: L.read(t, e)
    };
  }
});

const Z = withRDLength(array(T));

const J = {
  bytes(t) {
    const r = 8 + c.bytes(t.type === e.OPT ? "." : t.name);
    switch (t.type) {
     case e.A:
      return r + x.bytes(t.data);

     case e.NS:
      return r + k.bytes(t.data);

     case e.SOA:
      return r + K.bytes(t.data);

     case e.HINFO:
      return r + M.bytes(t.data);

     case e.MX:
      return r + v.bytes(t.data);

     case e.TXT:
      return r + V.bytes(t.data);

     case e.RP:
      return r + G.bytes(t.data);

     case e.AAAA:
      return r + H.bytes(t.data);

     case e.SRV:
      return r + _.bytes(t.data);

     case e.NAPTR:
      return r + j.bytes(t.data);

     case e.OPT:
      return r + Z.bytes(t.data);

     case e.DS:
      return r + Q.bytes(t.data);

     case e.SSHFP:
      return r + q.bytes(t.data);

     case e.RRSIG:
      return r + F.bytes(t.data);

     case e.NSEC:
      return r + B.bytes(t.data);

     case e.DNSKEY:
      return r + X.bytes(t.data);

     case e.NSEC3:
      return r + $.bytes(t.data);

     case e.TLSA:
      return r + z.bytes(t.data);

     case e.SVCB:
     case e.HTTPS:
      return r + W.bytes(t.data);

     case e.CAA:
      return r + Y.bytes(t.data);

     case e.PTR:
     case e.CNAME:
     case e.DNAME:
      return r + k.bytes(t.data);

     default:
      return r + O.bytes(t.data);
    }
  },
  write(t, r, n) {
    if (n.type === e.OPT) {
      r = c.write(t, r, ".");
      t.setUint16(r, n.type);
      t.setUint16(r + 2, n.udpPayloadSize || 4096);
      t.setUint8(r + 4, n.extendedRcode || 0);
      t.setUint8(r + 5, n.ednsVersion || 0);
      t.setUint16(r + 6, n.flags || 0);
      return Z.write(t, r += 8, n.data);
    }
    r = c.write(t, r, n.name);
    t.setUint16(r, n.type);
    t.setUint16(r + 2, (n.class || 0) | (n.flush ? 32768 : 0));
    t.setUint32(r + 4, n.ttl || 0);
    r += 8;
    switch (n.type) {
     case e.A:
      return x.write(t, r, n.data);

     case e.NS:
      return k.write(t, r, n.data);

     case e.SOA:
      return K.write(t, r, n.data);

     case e.HINFO:
      return M.write(t, r, n.data);

     case e.MX:
      return v.write(t, r, n.data);

     case e.TXT:
      return V.write(t, r, n.data);

     case e.RP:
      return G.write(t, r, n.data);

     case e.AAAA:
      return H.write(t, r, n.data);

     case e.SRV:
      return _.write(t, r, n.data);

     case e.NAPTR:
      return j.write(t, r, n.data);

     case e.DS:
      return Q.write(t, r, n.data);

     case e.SSHFP:
      return q.write(t, r, n.data);

     case e.RRSIG:
      return F.write(t, r, n.data);

     case e.NSEC:
      return B.write(t, r, n.data);

     case e.DNSKEY:
      return X.write(t, r, n.data);

     case e.NSEC3:
      return $.write(t, r, n.data);

     case e.TLSA:
      return z.write(t, r, n.data);

     case e.SVCB:
     case e.HTTPS:
      return W.write(t, r, n.data);

     case e.CAA:
      return Y.write(t, r, n.data);

     case e.PTR:
     case e.CNAME:
     case e.DNAME:
      return k.write(t, r, n.data);

     default:
      return O.write(t, r, n.data);
    }
  },
  read(t, r) {
    const n = c.read(t, r);
    const s = t.getUint16(r.offset);
    if (s === e.OPT) {
      const e = t.getUint16(r.offset + 2) || 4096;
      const n = t.getUint8(r.offset + 4);
      const a = t.getUint8(r.offset + 5);
      const i = t.getUint16(r.offset + 6);
      advance(r, 8);
      return {
        type: s,
        udpPayloadSize: e,
        extendedRcode: n,
        ednsVersion: a,
        flags: i,
        data: Z.read(t, r)
      };
    }
    const a = t.getUint16(r.offset + 2);
    const i = t.getUint32(r.offset + 4);
    advance(r, 8);
    const o = {
      name: n,
      type: s,
      class: -32769 & a,
      flush: !!(32768 & a),
      ttl: i,
      data: null
    };
    switch (o.type) {
     case e.A:
      o.data = x.read(t, r);
      return o;

     case e.NS:
      o.data = k.read(t, r);
      return o;

     case e.SOA:
      o.data = K.read(t, r);
      return o;

     case e.HINFO:
      o.data = M.read(t, r);
      return o;

     case e.MX:
      o.data = v.read(t, r);
      return o;

     case e.TXT:
      o.data = V.read(t, r);
      return o;

     case e.RP:
      o.data = G.read(t, r);
      return o;

     case e.AAAA:
      o.data = H.read(t, r);
      return o;

     case e.SRV:
      o.data = _.read(t, r);
      return o;

     case e.NAPTR:
      o.data = j.read(t, r);
      return o;

     case e.DS:
      o.data = Q.read(t, r);
      return o;

     case e.SSHFP:
      o.data = q.read(t, r);
      return o;

     case e.RRSIG:
      o.data = F.read(t, r);
      return o;

     case e.NSEC:
      o.data = B.read(t, r);
      return o;

     case e.DNSKEY:
      o.data = X.read(t, r);
      return o;

     case e.NSEC3:
      o.data = $.read(t, r);
      return o;

     case e.TLSA:
      o.data = z.read(t, r);
      return o;

     case e.SVCB:
     case e.HTTPS:
      o.data = W.read(t, r);
      return o;

     case e.CAA:
      o.data = Y.read(t, r);
      return o;

     case e.PTR:
     case e.CNAME:
     case e.DNAME:
      o.data = k.read(t, r);
      return o;

     default:
      o.data = O.read(t, r);
      return o;
    }
  }
};

const compareAnswers = (t, n) => {
  if (t.type === e.OPT || n.type === e.OPT) {
    return 0;
  }
  const s = t.class || r.IN;
  const a = n.class || r.IN;
  if (s !== a) {
    return s - a;
  } else if (t.type !== n.type) {
    return t.type - n.type;
  }
  let i;
  switch (t.type) {
   case e.A:
    i = x;
    break;

   case e.NS:
    i = k;
    break;

   case e.SOA:
    i = K;
    break;

   case e.HINFO:
    i = M;
    break;

   case e.MX:
    i = v;
    break;

   case e.TXT:
    i = V;
    break;

   case e.RP:
    i = G;
    break;

   case e.AAAA:
    i = H;
    break;

   case e.SRV:
    i = _;
    break;

   case e.NAPTR:
    i = j;
    break;

   case e.DS:
    i = Q;
    break;

   case e.SSHFP:
    i = q;
    break;

   case e.RRSIG:
    i = F;
    break;

   case e.NSEC:
    i = B;
    break;

   case e.DNSKEY:
    i = X;
    break;

   case e.NSEC3:
    i = $;
    break;

   case e.TLSA:
    i = z;
    break;

   case e.SVCB:
   case e.HTTPS:
    i = W;
    break;

   case e.CAA:
    i = Y;
    break;

   case e.PTR:
   case e.CNAME:
   case e.DNAME:
    i = k;
    break;

   default:
    i = O;
  }
  const o = encodeIntoBuffer(i, t.data);
  const c = encodeIntoBuffer(i, n.data);
  const f = o.byteLength < c.byteLength ? o.byteLength : c.byteLength;
  for (let t = 2; t < f; t++) {
    const e = o[t] - c[t];
    if (0 !== e) {
      return e < 0 ? -1 : 1;
    }
  }
  return o.byteLength !== c.byteLength ? o.byteLength < c.byteLength ? -1 : 1 : 0;
};

const readList = (t, e, r, n) => {
  if (!n) {
    return;
  }
  const {offset: s, length: a} = r;
  const i = [];
  for (let o = 0; o < n && r.offset - s < a; o++) {
    i.push(t.read(e, r));
  }
  return i;
};

const tt = {
  bytes(t) {
    const {questions: e, answers: r, authorities: n, additionals: s} = t;
    let a = 12;
    let i = 0;
    for (i = 0; e && i < e.length; i++) {
      a += b.bytes(e[i]);
    }
    for (i = 0; r && i < r.length; i++) {
      a += J.bytes(r[i]);
    }
    for (i = 0; n && i < n.length; i++) {
      a += J.bytes(n[i]);
    }
    for (i = 0; s && i < s.length; i++) {
      a += J.bytes(s[i]);
    }
    return a;
  },
  write(e, r, n) {
    const {questions: s, answers: a, authorities: i, additionals: o} = n;
    let c = 32767 & (n.flags || 0) | (n.type || t.QUERY) | (n.rtype || 0);
    e.setUint16(r, n.id || 0);
    e.setUint16(r + 2, c);
    e.setUint16(r + 4, n.questions?.length || 0);
    e.setUint16(r + 6, n.answers?.length || 0);
    e.setUint16(r + 8, n.authorities?.length || 0);
    e.setUint16(r + 10, n.additionals?.length || 0);
    r += 12;
    let f = 0;
    for (f = 0; s && f < s.length; f++) {
      r = b.write(e, r, s[f]);
    }
    for (f = 0; a && f < a.length; f++) {
      r = J.write(e, r, a[f]);
    }
    for (f = 0; i && f < i.length; f++) {
      r = J.write(e, r, i[f]);
    }
    for (f = 0; o && f < o.length; f++) {
      r = J.write(e, r, o[f]);
    }
    return r;
  },
  read(e, r) {
    const n = e.getUint16(r.offset);
    const s = e.getUint16(r.offset + 2);
    const a = e.getUint16(r.offset + 4);
    const i = e.getUint16(r.offset + 6);
    const o = e.getUint16(r.offset + 8);
    const c = e.getUint16(r.offset + 10);
    advance(r, 12);
    return {
      id: n,
      flags: s,
      rtype: 15 & s,
      type: s & t.RESPONSE ? t.RESPONSE : t.QUERY,
      questions: readList(b, e, r, a),
      answers: readList(J, e, r, i),
      authorities: readList(J, e, r, o),
      additionals: readList(J, e, r, c)
    };
  }
};

function decode(t) {
  const e = "buffer" in t ? new DataView(t.buffer, t.byteOffset, t.byteLength) : new DataView(t);
  return tt.read(e, {
    offset: 0,
    length: e.byteLength
  });
}

function streamDecode(t) {
  const e = "buffer" in t ? new DataView(t.buffer, t.byteOffset, t.byteLength) : new DataView(t);
  const r = Math.min(e.byteLength - 2, e.getUint16(0));
  return tt.read(e, {
    offset: 2,
    length: r
  });
}

function encodingLength(t) {
  return tt.bytes(t);
}

function encode(t) {
  const e = new ArrayBuffer(tt.bytes(t));
  const r = tt.write(new DataView(e), 0, t);
  return new Uint8Array(e, 0, r);
}

function streamEncode(t) {
  const e = new ArrayBuffer(tt.bytes(t) + 2);
  const r = new DataView(e);
  const n = tt.write(r, 2, t);
  r.setUint16(0, n - 2);
  return new Uint8Array(e, 0, n);
}

export { s as OptCode, n as PacketFlag, t as PacketType, r as RecordClass, e as RecordType, compareAnswers, decode, encode, encodingLength, streamDecode, streamEncode };
//# sourceMappingURL=dns-message.mjs.map
