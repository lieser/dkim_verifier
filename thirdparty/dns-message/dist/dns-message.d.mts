declare enum PacketType {
  QUERY = 0,
  RESPONSE = 32768,
}
declare enum RecordType {
  A = 1,
  NS = 2,
  CNAME = 5,
  SOA = 6,
  NULL = 10,
  PTR = 12,
  HINFO = 13,
  MX = 15,
  TXT = 16,
  RP = 17,
  AFSDB = 18,
  SIG = 24,
  KEY = 25,
  AAAA = 28,
  LOC = 29,
  SRV = 33,
  NAPTR = 35,
  KX = 36,
  CERT = 37,
  DNAME = 39,
  OPT = 41,
  APL = 42,
  DS = 43,
  SSHFP = 44,
  IPSECKEY = 45,
  RRSIG = 46,
  NSEC = 47,
  DNSKEY = 48,
  DHCID = 49,
  NSEC3 = 50,
  NSEC3PARAM = 51,
  TLSA = 52,
  HIP = 55,
  CDS = 59,
  CDNSKEY = 60,
  SVCB = 64,
  HTTPS = 65,
  SPF = 99,
  TKEY = 249,
  TSIG = 250,
  IXFR = 251,
  AXFR = 252,
  ANY = 255,
  CAA = 257,
  TA = 32768,
  DLV = 32769,
}
declare enum RecordClass {
  IN = 1,
  CS = 2,
  CH = 3,
  HS = 4,
  ANY = 255,
}
declare enum PacketFlag {
  NOERR = 0,
  FORMERR = 1,
  SERVFAIL = 2,
  NXDOMAIN = 3,
  NOTIMP = 4,
  REFUSED = 5,
  YXDOMAIN = 6,
  YXRRSET = 7,
  NXRRSET = 8,
  NOTAUTH = 9,
  NOTZONE = 10,
  CHECKING_DISABLED = 16,
  AUTHENTIC_DATA = 32,
  RECURSION_AVAILABLE = 128,
  RECURSION_DESIRED = 256,
  TRUNCATED_RESPONSE = 512,
  AUTHORITATIVE_ANSWER = 1024,
}
type PacketRType =
  | PacketFlag.NOERR
  | PacketFlag.FORMERR
  | PacketFlag.SERVFAIL
  | PacketFlag.NXDOMAIN
  | PacketFlag.NOTIMP
  | PacketFlag.REFUSED
  | PacketFlag.YXDOMAIN
  | PacketFlag.YXRRSET
  | PacketFlag.NXRRSET
  | PacketFlag.NOTAUTH
  | PacketFlag.NOTZONE;
declare enum OptCode {
  OPTION_0 = 0,
  LLQ = 1,
  UL = 2,
  NSID = 3,
  OPTION_4 = 4,
  DAU = 5,
  DHU = 6,
  N3U = 7,
  CLIENT_SUBNET = 8,
  EXPIRE = 9,
  COOKIE = 10,
  TCP_KEEPALIVE = 11,
  PADDING = 12,
  CHAIN = 13,
  KEY_TAG = 14,
  DEVICEID = 26946,
  OPTION_65535 = 65535,
}

interface Question {
  name: string;
  type: RecordType;
  class?: RecordClass;
  qu?: boolean;
}

declare const enum IPType {
  v4 = 1,
  v6 = 2,
}
interface BaseOpt {
  code: number;
}
interface ClientSubnetOpt extends BaseOpt {
  code: OptCode.CLIENT_SUBNET;
  family?: IPType | (number & {});
  sourcePrefixLength?: number;
  scopePrefixLength?: number;
  ip: string;
}
interface KeepAliveOpt extends BaseOpt {
  code: OptCode.TCP_KEEPALIVE;
  timeout?: number;
}
interface PaddingOpt extends BaseOpt {
  code: OptCode.PADDING;
  length?: number;
}
interface TagOpt extends BaseOpt {
  code: OptCode.KEY_TAG;
  tags: number[];
}
interface UnknownOpt extends BaseOpt {
  data: Uint8Array;
}
type PacketOpt = ClientSubnetOpt | KeepAliveOpt | PaddingOpt | TagOpt | UnknownOpt;

declare const enum SvcParamCode {
  Mandatory = 0,
  Alpn = 1,
  NoDefaultAlpn = 2,
  Port = 3,
  Ipv4Hint = 4,
  EchConfig = 5,
  Ipv6Hint = 6,
  DohPath = 7,
  Odoh = 32769,
}
interface SvcParams {
  mandatory?: (SvcParamCode | (number & {}))[];
  alpn?: string[];
  'no-default-alpn'?: boolean;
  port?: number;
  ipv4hint?: string[];
  ipv6hint?: string[];
  echconfig?: Uint8Array;
  dohpath?: string;
  odoh?: Uint8Array;
}

interface BaseAnswer {
  type: RecordType;
  name: string;
  ttl?: number;
  class?: RecordClass;
  flush?: boolean;
}
interface NsAnswer extends BaseAnswer {
  type: RecordType.NS;
  data: string;
}
interface AAnswer extends BaseAnswer {
  type: RecordType.A;
  data: string;
}
interface AAAAAnswer extends BaseAnswer {
  type: RecordType.AAAA;
  data: string;
}
interface TxtAnswer extends BaseAnswer {
  type: RecordType.TXT;
  data: string[];
}
interface SrvData {
  priority?: number;
  weight?: number;
  port: number;
  target: string;
}
interface SrvAnswer extends BaseAnswer {
  type: RecordType.SRV;
  data: SrvData;
}
interface HInfoData {
  cpu: string;
  os: string;
}
interface HInfoAnswer extends BaseAnswer {
  type: RecordType.HINFO;
  data: HInfoData;
}
interface CaaData {
  flags?: number;
  tag: 'issue' | 'issuewild' | 'iodef';
  value: Uint8Array;
  issuerCritical?: boolean;
}
interface CaaAnswer extends BaseAnswer {
  type: RecordType.CAA;
  data: CaaData;
}
interface SoaData {
  mname: string;
  rname: string;
  serial?: number;
  refresh?: number;
  retry?: number;
  expire?: number;
  minimum?: number;
}
interface SoaAnswer extends BaseAnswer {
  type: RecordType.SOA;
  data: SoaData;
}
interface MxData {
  preference?: number;
  exchange: string;
}
interface MxAnswer extends BaseAnswer {
  type: RecordType.MX;
  data: MxData;
}
interface DnskeyData {
  flags: number;
  algorithm: number;
  key: Uint8Array;
}
interface DnskeyAnswer extends BaseAnswer {
  type: RecordType.DNSKEY;
  data: DnskeyData;
}
interface RrsigData {
  typeCovered: RecordType;
  algorithm: number;
  labels: number;
  originalTTL: number;
  expiration: number;
  inception: number;
  keyTag: number;
  signersName: string;
  signature: Uint8Array;
}
interface RrsigAnswer extends BaseAnswer {
  type: RecordType.RRSIG;
  data: RrsigData;
}
interface RpData {
  mbox: string;
  txt: string;
}
interface RpAnswer extends BaseAnswer {
  type: RecordType.RP;
  data: RpData;
}
interface NsecData {
  nextDomain: string;
  rrtypes: RecordType[];
}
interface NsecAnswer extends BaseAnswer {
  type: RecordType.NSEC;
  data: NsecData;
}
interface Nsec3Data {
  algorithm: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
  nextDomain: Uint8Array;
  rrtypes: RecordType[];
}
interface Nsec3Answer extends BaseAnswer {
  type: RecordType.NSEC3;
  data: Nsec3Data;
}
interface SshfpData {
  algorithm: number;
  hash: number;
  fingerprint: Uint8Array;
}
interface SshfpAnswer extends BaseAnswer {
  type: RecordType.SSHFP;
  data: SshfpData;
}
interface DsData {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: Uint8Array;
}
interface DsAnswer extends BaseAnswer {
  type: RecordType.DS;
  data: DsData;
}
interface NaptrData {
  order: number;
  preference: number;
  flags: string;
  services: string;
  regexp: string;
  replacement: string;
}
interface NaptrAnswer extends BaseAnswer {
  type: RecordType.NAPTR;
  data: NaptrData;
}
interface TlsaData {
  usage: number;
  selector: number;
  matchingType: number;
  certificate: Uint8Array;
}
interface TlsaAnswer extends BaseAnswer {
  type: RecordType.TLSA;
  data: TlsaData;
}
interface SvcbData {
  name: string;
  priority?: number;
  params: SvcParams;
}
interface SvcbAnswer extends BaseAnswer {
  type: RecordType.SVCB;
  data: SvcbData;
}
interface HttpsAnswer extends BaseAnswer {
  type: RecordType.HTTPS;
  data: SvcbData;
}
interface OptAnswer {
  type: RecordType.OPT;
  name?: '.';
  udpPayloadSize: number;
  extendedRcode: number;
  ednsVersion: number;
  flags: number;
  data: PacketOpt[];
}
interface PtrAnswer extends BaseAnswer {
  type: RecordType.PTR;
  data: string;
}
interface CnameAnswer extends BaseAnswer {
  type: RecordType.CNAME;
  data: string;
}
interface DnameAnswer extends BaseAnswer {
  type: RecordType.DNAME;
  data: string;
}
interface NullAnswer extends BaseAnswer {
  type: RecordType.NULL;
  data: Uint8Array | string;
}
interface UnknownAnswer extends BaseAnswer {
  type:
    | RecordType.AFSDB
    | RecordType.APL
    | RecordType.AXFR
    | RecordType.CDNSKEY
    | RecordType.CDS
    | RecordType.CERT
    | RecordType.DHCID
    | RecordType.DLV
    | RecordType.HIP
    | RecordType.IPSECKEY
    | RecordType.IXFR
    | RecordType.KEY
    | RecordType.KX
    | RecordType.LOC
    | RecordType.NSEC3PARAM
    | RecordType.NULL
    | RecordType.SIG
    | RecordType.TA
    | RecordType.TKEY
    | RecordType.TSIG;
  data: Uint8Array | string;
}
type Answer =
  | AAnswer
  | AAAAAnswer
  | TxtAnswer
  | SrvAnswer
  | HInfoAnswer
  | CaaAnswer
  | NsAnswer
  | SoaAnswer
  | MxAnswer
  | OptAnswer
  | DnskeyAnswer
  | RrsigAnswer
  | RpAnswer
  | NsecAnswer
  | Nsec3Answer
  | SshfpAnswer
  | DsAnswer
  | NaptrAnswer
  | TlsaAnswer
  | PtrAnswer
  | CnameAnswer
  | DnameAnswer
  | SvcbAnswer
  | HttpsAnswer
  | NullAnswer
  | UnknownAnswer;
declare const compareAnswers: (a: Answer, b: Answer) => number;

interface Packet {
  id?: number;
  type?: PacketType;
  rtype?: PacketRType;
  flags?: PacketFlag | (number & {});
  questions?: Question[];
  answers?: Answer[];
  additionals?: Answer[];
  authorities?: Answer[];
}

declare function decode(bytes: ArrayBufferView | ArrayBufferLike): Packet;
declare function streamDecode(bytes: ArrayBufferView | ArrayBufferLike): Packet;
declare function encodingLength(input: Packet): number;
declare function encode(input: Packet): Uint8Array;
declare function streamEncode(input: Packet): Uint8Array;

export {
  IPType,
  OptCode,
  PacketFlag,
  PacketType,
  RecordClass,
  RecordType,
  SvcParamCode,
  compareAnswers,
  decode,
  encode,
  encodingLength,
  streamDecode,
  streamEncode,
};
export type {
  AAAAAnswer,
  AAnswer,
  Answer,
  BaseAnswer,
  CaaAnswer,
  ClientSubnetOpt,
  CnameAnswer,
  DnameAnswer,
  DnskeyAnswer,
  DsAnswer,
  HInfoAnswer,
  KeepAliveOpt,
  MxAnswer,
  NaptrAnswer,
  NsAnswer,
  Nsec3Answer,
  NsecAnswer,
  NullAnswer,
  OptAnswer,
  Packet,
  PacketOpt,
  PacketRType,
  PaddingOpt,
  PtrAnswer,
  Question,
  RpAnswer,
  RrsigAnswer,
  SoaAnswer,
  SrvAnswer,
  SshfpAnswer,
  SvcParams,
  SvcbAnswer,
  TagOpt,
  TlsaAnswer,
  TxtAnswer,
  UnknownAnswer,
  UnknownOpt,
};
