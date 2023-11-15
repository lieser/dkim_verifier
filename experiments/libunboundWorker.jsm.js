/**
 * A ChromeWorker wrapper for the libunbound DNS library.
 * Currently only the TXT resource record is completely supported.
 *
 * Copyright (c) 2016-2018;2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./ctypes.d.ts" />
///<reference path="./libunbound.d.ts" />
/* eslint-env mozilla/chrome-worker, mozilla/jsm */
/* eslint-disable camelcase */
/* eslint no-global-assign: ["error", {"exceptions": ["onmessage"]}] */

"use strict";


const log_prefix = "libunboundWorker: ";
const postLog = {
	/**
	 * @param {string} msg
	 * @returns {void}
	 */
	error(msg) {
		/** @type {Libunbound.Log} */
		const toSend = { type: "log", subType: "error", message: log_prefix + msg };
		postMessage(toSend);
	},
	/**
	 * @param {string} msg
	 * @returns {void}
	 */
	warn(msg) {
		/** @type {Libunbound.Log} */
		const toSend = { type: "log", subType: "warn", message: log_prefix + msg };
		postMessage(toSend);
	},
	/**
	 * @param {string} msg
	 * @returns {void}
	 */
	info(msg) {
		/** @type {Libunbound.Log} */
		const toSend = { type: "log", subType: "info", message: log_prefix + msg };
		postMessage(toSend);
	},
	/**
	 * @param {string} msg
	 * @returns {void}
	 */
	debug(msg) {
		/** @type {Libunbound.Log} */
		const toSend = { type: "log", subType: "debug", message: log_prefix + msg };
		postMessage(toSend);
	},
};

const Constants = {
	RR_TYPE_A: 1,
	RR_TYPE_A6: 38,
	RR_TYPE_AAAA: 28,
	RR_TYPE_AFSDB: 18,
	RR_TYPE_ANY: 255,
	RR_TYPE_APL: 42,
	RR_TYPE_ATMA: 34,
	RR_TYPE_AXFR: 252,
	RR_TYPE_CERT: 37,
	RR_TYPE_CNAME: 5,
	RR_TYPE_DHCID: 49,
	RR_TYPE_DLV: 32769,
	RR_TYPE_DNAME: 39,
	RR_TYPE_DNSKEY: 48,
	RR_TYPE_DS: 43,
	RR_TYPE_EID: 31,
	RR_TYPE_GID: 102,
	RR_TYPE_GPOS: 27,
	RR_TYPE_HINFO: 13,
	RR_TYPE_IPSECKEY: 45,
	RR_TYPE_ISDN: 20,
	RR_TYPE_IXFR: 251,
	RR_TYPE_KEY: 25,
	RR_TYPE_KX: 36,
	RR_TYPE_LOC: 29,
	RR_TYPE_MAILA: 254,
	RR_TYPE_MAILB: 253,
	RR_TYPE_MB: 7,
	RR_TYPE_MD: 3,
	RR_TYPE_MF: 4,
	RR_TYPE_MG: 8,
	RR_TYPE_MINFO: 14,
	RR_TYPE_MR: 9,
	RR_TYPE_MX: 15,
	RR_TYPE_NAPTR: 35,
	RR_TYPE_NIMLOC: 32,
	RR_TYPE_NS: 2,
	RR_TYPE_NSAP: 22,
	RR_TYPE_NSAP_PTR: 23,
	RR_TYPE_NSEC: 47,
	RR_TYPE_NSEC3: 50,
	RR_TYPE_NSEC3PARAMS: 51,
	RR_TYPE_NULL: 10,
	RR_TYPE_NXT: 30,
	RR_TYPE_OPT: 41,
	RR_TYPE_PTR: 12,
	RR_TYPE_PX: 26,
	RR_TYPE_RP: 17,
	RR_TYPE_RRSIG: 46,
	RR_TYPE_RT: 21,
	RR_TYPE_SIG: 24,
	RR_TYPE_SINK: 40,
	RR_TYPE_SOA: 6,
	RR_TYPE_SRV: 33,
	RR_TYPE_SSHFP: 44,
	RR_TYPE_TSIG: 250,
	RR_TYPE_TXT: 16,
	RR_TYPE_UID: 101,
	RR_TYPE_UINFO: 100,
	RR_TYPE_UNSPEC: 103,
	RR_TYPE_WKS: 11,
	RR_TYPE_X25: 19,
};

/** @type {ctypes.Library?} */
let lib;
/** @type {ctypes.Library[]} */
let libDeps = [];
/** @type {p_ub_ctx} */
let ctx = ctypes.voidptr_t();
// http://unbound.net/documentation/libunbound.html
/** @typedef {ctypes.CDataPointerType<ub_ctx_struct>} p_ub_ctx */
/** @type {ub_ctx_struct|undefined} */
let ub_ctx;
/** @typedef {ctypes.CDataPointerType<ub_result_struct>} p_ub_result */
/** @typedef {ctypes.CDataPointerType<ctypes.PointerTypeI<ub_result_struct>>} pp_ub_result */
/** @type {ub_result_struct} */
let ub_result;
/** @type {()=>p_ub_ctx} */
let ub_ctx_create;
/** @type {(ctx: p_ub_ctx)=>void} */
let ub_ctx_delete;
/** @type {(ctx: p_ub_ctx, fname: string)=>number} */
let ub_ctx_config;
/** @type {(ctx: p_ub_ctx, addr: string)=>number} */
let ub_ctx_set_fwd;
/** @type {(ctx: p_ub_ctx, fname: string|null)=>number} */
let ub_ctx_resolvconf;
/** @type {(ctx: p_ub_ctx, ta: string)=>number} */
let ub_ctx_add_ta;
/** @type {(ctx: p_ub_ctx, d: number)=>number} */
let ub_ctx_debuglevel;
/** @type {(ctx: p_ub_ctx, name: string, rrtype: number, rrclass: number, result: pp_ub_result)=>number} */
let ub_resolve;
/** @type {(result: p_ub_result)=>void} */
let ub_resolve_free;
/** @type {(err: number)=>ReturnType<typeof ctypes.char.ptr>} */
let ub_strerror;

/**
 * Perform resolution of the target name.
 *
 * @param {string} name
 * @param {number} rrtype
 * @returns {ub_result}
 */
function resolve(name, rrtype) {
	if (!ub_resolve) {
		throw new Error("libunbound not correctly initialized (ub_resolve missing)");
	}
	if (!ub_result) {
		throw new Error("libunbound not correctly initialized (ub_result missing)");
	}
	if (!ctx) {
		throw new Error("libunbound not correctly initialized (ctx missing)");
	}

	const _result = ub_result.ptr();

	// query for name
	const retval = ub_resolve(ctx, name,
		rrtype,
		1 /* CLASS IN (internet) */, _result.address()
	);
	if (retval !== 0) {
		postLog.debug(`resolve error: ${ub_strerror(retval).readString()}\n`);
		throw new Error(`resolve error: ${ub_strerror(retval).readString()}`);
	}

	// array of converted rdata
	const data = [];
	// array of rdata as byte array
	/** @type {number[][]} */
	const data_raw = [];
	if (_result.contents.havedata) {
		// get data
		let lenPtr = _result.contents.len;
		let dataPtr = _result.contents.data;
		while (!dataPtr.contents.isNull()) {
			// get rdata as byte array
			const tmp = ctypes.cast(dataPtr.contents,
				ctypes.uint8_t.array(lenPtr.contents).ptr
			).contents;
			/** @type {number[]} */
			const rdata = new Array(tmp.length);
			for (let i = 0; i < tmp.length; i++) {
				// @ts-expect-error
				rdata[i] = tmp[i];
			}
			data_raw.push(rdata);

			// convert rdata for known RR types
			switch (rrtype) {
				case Constants.RR_TYPE_TXT: {
					// http://tools.ietf.org/html/rfc1035#page-20
					let str = "";
					let i = 0;
					/** @type {number} */
					let j;
					// read all <character-string>s
					while (i < rdata.length) {
						// get length of current <character-string>
						// @ts-expect-error
						j = rdata[i];
						i += 1;
						// read current <character-string>
						str += String.fromCharCode.apply(null, rdata.slice(i, i + j));
						i += j;
					}
					data.push(str);
					break;
				}
				default:
					postLog.warn(`skipped converting of unknown rdata type: ${rrtype}`);
			}

			dataPtr = dataPtr.increment();
			lenPtr = lenPtr.increment();
		}

		postLog.debug(`data: ${data}`);
	}

	/** @type {ub_result} */
	const result = {};
	if (!_result.contents.qname.isNull()) {
		result.qname = _result.contents.qname.readString();
	} else {
		postLog.warn("qname missing");
		result.qname = "";
	}
	result.qtype = _result.contents.qtype;
	result.qclass = _result.contents.qclass;
	result.data = data;
	result.data_raw = data_raw;
	if (!_result.contents.canonname.isNull()) {
		result.canonname = _result.contents.canonname.readString();
	} else {
		result.canonname = "";
	}
	result.rcode = _result.contents.rcode;
	result.havedata = _result.contents.havedata === 1;
	result.nxdomain = _result.contents.nxdomain === 1;
	result.secure = _result.contents.secure === 1;
	result.bogus = _result.contents.bogus === 1;
	if (!_result.contents.why_bogus.isNull()) {
		result.why_bogus = _result.contents.why_bogus.readString();
	}
	result.ttl = _result.contents.ttl;

	postLog.debug(`qname: ${result.qname}, qtype: ${result.qtype}, rcode: ${result.rcode}, secure: ${result.secure}, bogus: ${result.bogus}, why_bogus: ${result.why_bogus}`);

	ub_resolve_free(_result);

	return result;
}

/**
 * Load library.
 *
 * @param {string} paths - paths to libraries to load, separated by ";". Last is libunbound.
 * @returns {void}
 */
function load(paths) {
	// if library was already loaded, do a cleanup first before reloading it
	if (lib) {
		// delete old context
		ub_ctx_delete(ctx);
		ctx = ctypes.voidptr_t();
		// close library
		lib.close();
		lib = null;
		// close dependency of library
		for (const libDep of libDeps) {
			libDep.close();
		}
		libDeps = [];
	}
	const libPaths = paths.split(";");
	// Automatic loading of dependencies seems to be buggy.
	// If a dependency was ones loaded, TB will always try to use the same,
	// maybe now outdated location.
	// Explicitly load optionally specified dependency of library as a workaround.
	for (const libDepPath of libPaths.slice(0, -1)) {
		postLog.debug(`loading dependency: ${libDepPath}`);
		libDeps.push(ctypes.open(libDepPath));
	}
	const path = libPaths.slice(-1)[0] ?? "";
	postLog.debug(`loading libunbound: ${path}`);
	lib = ctypes.open(path);

	ub_ctx = new ctypes.StructType("ub_ctx");
	// struct ub_result {
	//     char* qname; /* text string, original question */
	//     int qtype;   /* type code asked for */
	//     int qclass;  /* class code asked for */
	//     char** data; /* array of rdata items, NULL terminated*/
	//     int* len;    /* array with lengths of rdata items */
	//     char* canonname; /* canonical name of result */
	//     int rcode;   /* additional error code in case of no data */
	//     void* answer_packet; /* full network format answer packet */
	//     int answer_len; /* length of packet in octets */
	//     int havedata; /* true if there is data */
	//     int nxdomain; /* true if nodata because name does not exist */
	//     int secure;  /* true if result is secure */
	//     int bogus;   /* true if a security failure happened */
	//     char* why_bogus; /* string with error if bogus */
	//     int ttl;     /* number of seconds the result is valid */
	// };
	ub_result = new ctypes.StructType("ub_result", [
		{ "qname": ctypes.char.ptr },
		{ "qtype": ctypes.int },
		{ "qclass": ctypes.int },
		{ "data": ctypes.char.ptr.ptr },
		{ "len": ctypes.int.ptr },
		{ "canonname": ctypes.char.ptr },
		{ "rcode": ctypes.int },
		{ "answer_packet": ctypes.voidptr_t },
		{ "answer_len": ctypes.int },
		{ "havedata": ctypes.int },
		{ "nxdomain": ctypes.int },
		{ "secure": ctypes.int },
		{ "bogus": ctypes.int },
		{ "why_bogus": ctypes.char.ptr },
		{ "ttl": ctypes.int }
	]);

	// struct ub_ctx * ub_ctx_create(void);
	ub_ctx_create = lib.declare("ub_ctx_create", ctypes.default_abi, ub_ctx.ptr);

	// void ub_ctx_delete(struct ub_ctx* ctx);
	ub_ctx_delete = lib.declare("ub_ctx_delete", ctypes.default_abi, ctypes.void_t,
		ub_ctx.ptr);

	// int ub_ctx_config(struct ub_ctx* ctx, char* fname);
	ub_ctx_config = lib.declare("ub_ctx_config", ctypes.default_abi, ctypes.int,
		ub_ctx.ptr, ctypes.char.ptr);

	//int ub_ctx_set_fwd(struct ub_ctx* ctx, char* addr);
	ub_ctx_set_fwd = lib.declare("ub_ctx_set_fwd", ctypes.default_abi, ctypes.int,
		ub_ctx.ptr, ctypes.char.ptr);

	// int ub_ctx_resolvconf(struct ub_ctx* ctx, char* fname);
	ub_ctx_resolvconf = lib.declare("ub_ctx_resolvconf", ctypes.default_abi, ctypes.int,
		ub_ctx.ptr, ctypes.char.ptr);

	// int ub_ctx_add_ta(struct ub_ctx* ctx, char* ta);
	ub_ctx_add_ta = lib.declare("ub_ctx_add_ta", ctypes.default_abi, ctypes.int,
		ub_ctx.ptr, ctypes.char.ptr);

	// int ub_ctx_debuglevel(struct ub_ctx* ctx, int d);
	ub_ctx_debuglevel = lib.declare("ub_ctx_debuglevel", ctypes.default_abi, ctypes.int,
		ub_ctx.ptr, ctypes.int);

	// int ub_resolve(struct ub_ctx* ctx, char* name,
	//                int rrtype, int rrclass, struct ub_result** result);
	ub_resolve = lib.declare("ub_resolve", ctypes.default_abi, ctypes.int,
		ub_ctx.ptr, ctypes.char.ptr, ctypes.int, ctypes.int, ub_result.ptr.ptr);

	// void ub_resolve_free(struct ub_result* result);
	ub_resolve_free = lib.declare("ub_resolve_free", ctypes.default_abi, ctypes.void_t,
		ub_result.ptr);

	// const char * ub_strerror(int err);
	ub_strerror = lib.declare("ub_strerror", ctypes.default_abi, ctypes.char.ptr,
		ctypes.int);

	postLog.debug("libunbound loaded");
}

/**
 * Updates ctx by deleting the old an creating a new one.
 *
 * @param {string|undefined} conf
 * @param {number|undefined} debuglevel
 * @param {boolean} getNameserversFromOS
 * @param {string[]} nameservers
 * @param {string[]} trustAnchors
 * @returns {void}
 */
function update_ctx(conf, debuglevel, getNameserversFromOS, nameservers, trustAnchors) {
	if (!ub_ctx_create) {
		throw new Error("libunbound not correctly initialized (ub_ctx_create missing)");
	}

	/** @type {number} */
	let retval;

	if (!ctx.isNull()) {
		// delete old context
		ub_ctx_delete(ctx);
		ctx = ctypes.voidptr_t();
	}

	// create context
	ctx = ub_ctx_create();
	if (ctx.isNull()) {
		throw new Error("could not create unbound context");
	}

	// read config file if specified
	if (conf) {
		if ((retval = ub_ctx_config(ctx, conf)) !== 0) {
			throw new Error(`error in ub_ctx_config: ${ub_strerror(retval).readString()}. errno: ${ctypes.errno}`);
		}
	}

	// set debuglevel if specified
	if (debuglevel) {
		if ((retval = ub_ctx_debuglevel(ctx, debuglevel)) !== 0) {
			throw new Error(`error in ub_ctx_debuglevel: ${ub_strerror(retval).readString()}. errno: ${ctypes.errno}`);
		}
	}

	// get DNS servers form OS
	if (getNameserversFromOS) {
		if ((retval = ub_ctx_resolvconf(ctx, null)) !== 0) {
			throw new Error(`error in ub_ctx_resolvconf: ${ub_strerror(retval).readString()}. errno: ${ctypes.errno}`);
		}
	}

	// set additional DNS servers
	nameservers.forEach((element /*, index, array*/) => {
		if ((retval = ub_ctx_set_fwd(ctx, element.trim())) !== 0) {
			throw new Error(`error in ub_ctx_set_fwd: ${ub_strerror(retval).readString()}. errno: ${ctypes.errno}`);
		}
	});

	// add root trust anchors
	trustAnchors.forEach((element /*, index, array*/) => {
		if ((retval = ub_ctx_add_ta(ctx, element.trim())) !== 0) {
			throw new Error(`error in ub_ctx_add_ta: ${ub_strerror(retval).readString()}. errno: ${ctypes.errno}`);
		}
	});

	postLog.debug("context created");
}

/**
 * Handle the requests from libunbound.jsm.
 *
 * @param {Libunbound.WorkerRequest} msg
 * @returns {void}
 */
onmessage = function (msg) {
	try {
		try {
			let res;

			// call requested method
			switch (msg.data.method) {
				case "resolve": {
					/** @type {Libunbound.ResolveRequest} */
					// @ts-expect-error
					const req = msg.data;
					res = resolve(req.name, req.rrtype);
					break;
				}
				case "load": {
					/** @type {Libunbound.LoadRequest} */
					// @ts-expect-error
					const req = msg.data;
					load(req.path);
					break;
				}
				case "update_ctx": {
					/** @type {Libunbound.UpdateCtxRequest} */
					// @ts-expect-error
					const req = msg.data;
					update_ctx(req.conf, req.debuglevel,
						req.getNameserversFromOS, req.nameservers,
						req.trustAnchors);
					break;
				}
				default:
					throw new Error(`unknown method ${msg.data.method}`);
			}

			// return result
			postMessage({
				callId: msg.data.callId,
				result: res,
			});
		} catch (exception) {
			// @ts-expect-error
			postLog.debug(`Posting exception back to main script: ${exception}; stack: ${exception.stack}`);
			postMessage({
				type: "error",
				subType: "DKIM_DNSERROR_UNKNOWN",
				callId: msg.data.callId,
				message: `libunboundWorker: ${exception}`,
				// @ts-expect-error
				stack: exception.stack,
			});
		}
	} catch (e) {
		// @ts-expect-error
		dump(`${e}\n`);
		// @ts-expect-error
		postLog.error(`Exception: ${e}; stack: ${e.stack}`);
	}
};
