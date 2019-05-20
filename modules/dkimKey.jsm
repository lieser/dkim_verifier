/*
 * dkimKey.jsm
 * 
 * Version: 1.2.0 (28 January 2018)
 * 
 * Copyright (c) 2013-2018 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* eslint strict: ["warn", "function"] */
/* global Components, Services, Sqlite */
/* global Logging, DNS */
/* global Deferred, DKIM_SigError, DKIM_InternalError, PREF */
/* exported EXPORTED_SYMBOLS, Key */

// @ts-ignore
const module_version = "1.2.0";

var EXPORTED_SYMBOLS = [
	"Key"
];

// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/Sqlite.jsm");

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");
Cu.import("resource://dkim_verifier/DNSWrapper.jsm");


/**
 * @public
 */
const KEY_DB_NAME = "dkimKey.sqlite";
// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.key.";


// @ts-ignore
var prefs = Services.prefs.getBranch(PREF_BRANCH);
// @ts-ignore
var log = Logging.getLogger("Key");
var dbInitialized = false;
// Deferred<boolean>
/** @type {IDeferred<boolean>} */
var dbInitializedDefer = new Deferred();

var Key = {
	get version() { "use strict"; return module_version; },

	/**
	 * init DB
	 * May be called more then once
	 * 
	 * @return {Promise<boolean>} initialized
	 */
	initDB: function Key_initDB() {
		"use strict";

		if (dbInitialized) {
			return dbInitializedDefer.promise;
		}
		dbInitialized = true;

		var promise = (async () => {
			log.trace("initDB Task begin");

			Logging.addAppenderTo("Sqlite.Connection."+KEY_DB_NAME, "sql.");
			
			var conn = await Sqlite.openConnection({path: KEY_DB_NAME});

			try {
				// get version numbers
				await conn.execute(
					"CREATE TABLE IF NOT EXISTS version (\n" +
					"  name TEXT PRIMARY KEY NOT NULL,\n" +
					"  version INTEGER NOT NULL\n" +
					");"
				);
				var sqlRes = await conn.execute(
					"SELECT * FROM version;"
				);
				const TABLE_KEYS_VERSION_CURRENT = 1;
				var versionTableKeys = 0;
				sqlRes.forEach(function(element/*, index, array*/){
					switch(element.getResultByName("name")) {
						case "TableKeys":
							versionTableKeys = element.getResultByName("version");
							break;
						default:
							log.warn("Version table contains unknown entry: " + element.getResultByName("name"));
					}
				});
				log.trace("versionTableKeys: "+versionTableKeys);

				// table keys
				if (versionTableKeys < TABLE_KEYS_VERSION_CURRENT) {
					log.trace("create table keys");
					// create table
					await conn.execute(
						"CREATE TABLE IF NOT EXISTS keys (\n" +
						"  SDID TEXT NOT NULL,\n" +
						"  selector TEXT NOT NULL,\n" +
						"  key TEXT NOT NULL,\n" +
						"  insertedAt TEXT NOT NULL,\n" +
						"  lastUsedAt TEXT NOT NULL,\n" +
						"  secure INTEGER NOT NULL\n" +
						");"
					);
					// add version number
					await conn.execute(
						"INSERT INTO version (name, version)" +
						"VALUES ('TableKeys', 1);"
					);
					versionTableKeys = 1;
				} else if (versionTableKeys !== TABLE_KEYS_VERSION_CURRENT) {
						throw new DKIM_InternalError("unsupported versionTableKeys");
				}
			} finally {
				await conn.close();
			}
			
			dbInitializedDefer.resolve(true);
			log.debug("DB initialized");
			log.trace("initDB Task end");
			return true;
		})();
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(exception);
			dbInitializedDefer.reject(exception);
		});
		return dbInitializedDefer.promise;
	},

	/**
	 * The result of the verification.
	 * 
	 * @typedef {Object} dkimKeyResult
	 * @property {String} key DKIM key in its textual Representation.
	 * @property {String} gotFrom "DNS" / "Storage"
	 * @property {Boolean} secure
	 */

	/**
	 * Get the DKIM key.
	 * 
	 * @param {String} d_val domain of the Signer
	 * @param {String} s_val selector
	 * 
	 * @return {Promise<dkimKeyResult>}
	 * 
	 * @throws {DKIM_SigError|DKIM_InternalError}
	 */
	getKey: async function Key_getKey(d_val, s_val) {
		"use strict";

		log.trace("getKey Task begin");

		/** @type {dkimKeyResult} */
		var res={};
		var tmp;
		
		switch (prefs.getIntPref("storing")) {
			case PREF.KEY.STORING.DISABLED: // don't store DKIM keys
				tmp = await getKeyFromDNS(d_val, s_val);
				res.gotFrom = "DNS";
				break;
			case PREF.KEY.STORING.STORE: // store DKIM keys
				tmp = await getKeyFromDB(d_val, s_val);
				if (tmp) {
					res.gotFrom = "Storage";
				} else {
					tmp = await getKeyFromDNS(d_val, s_val);
					res.gotFrom = "DNS";
					setKeyInDB(d_val, s_val, tmp.key, tmp.secure);
				}
				break;
			case PREF.KEY.STORING.COMPARE: // store DKIM keys and compare with current key
				var keyDB = await getKeyFromDB(d_val, s_val);
				tmp = await getKeyFromDNS(d_val, s_val);
				res.gotFrom = "DNS";
				if (keyDB) {
					if (keyDB.key !== tmp.key) {
						throw new DKIM_SigError("DKIM_POLICYERROR_KEYMISMATCH");
					}
					tmp.secure = tmp.secure || keyDB.secure;
				} else {
					setKeyInDB(d_val, s_val, tmp.key, tmp.secure);
				}
				break;
			default:
				throw new DKIM_InternalError("invalid key.storing setting");
		}
		res.key = tmp.key;
		res.secure = tmp.secure;

		log.trace("getKey Task begin");
		return res;
	},
	
	/**
	 * Delete stored DKIM key.
	 * 
	 * @param {String} d_val domain of the Signer
	 * @param {String} s_val selector
	 * 
	 * @return {Promise<void>}
	 */
	deleteKey: function Key_deleteKey(d_val, s_val) {
		"use strict";

		var promise = (async () => {
			log.trace("deleteKey Task begin");
			
			// wait for DB init
			await Key.initDB();
			var conn = await Sqlite.openConnection({path: KEY_DB_NAME});
			
			try {
				await conn.executeCached(
					"DELETE FROM keys\n" +
					"WHERE SDID = :SDID AND  selector = :selector;",
					{SDID:d_val, selector: s_val}
				);
				log.debug("deleted key ("+d_val+", "+s_val+")");
			} finally {
				await conn.close();
			}
			
			log.trace("deleteKey Task end");
		})();
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(exception);
		});
		
		return promise;
	},
	
	/**
	 * Mark stored DKIM key as secure.
	 * 
	 * @param {String} d_val domain of the Signer
	 * @param {String} s_val selector
	 * 
	 * @return {Promise<void>}
	 */
	markKeyAsSecure: function Key_markKeyAsSecure(d_val, s_val) {
		"use strict";

		var promise = (async () => {
			log.trace("markKeyAsSecure Task begin");
			
			// wait for DB init
			await Key.initDB();
			var conn = await Sqlite.openConnection({path: KEY_DB_NAME});
			
			try {
				await conn.executeCached(
					"UPDATE keys SET secure = 1\n" +
					"WHERE SDID = :SDID AND  selector = :selector;",
					{SDID:d_val, selector: s_val}
				);
				log.debug("updated key ("+d_val+", "+s_val+") to secure");
			} finally {
				await conn.close();
			}
			
			log.trace("markKeyAsSecure Task end");
		})();
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(exception);
		});
		
		return promise;
	},
};

/**
 * Get the DKIM key from DNS.
 * 
 * @param {String} d_val domain of the Signer
 * @param {String} s_val selector
 * 
 * @return {Promise<{key: string, secure: boolean}>}
 * 
 * @throws {DKIM_SigError|DKIM_InternalError}
 */
async function getKeyFromDNS(d_val, s_val) {
	"use strict";

	log.trace("getKeyFromDNS Task begin");
	
	// get the DKIM key
	var result = await DNS.resolve(s_val+"._domainkey."+d_val, "TXT");
	
	if (result.bogus) {
		throw new DKIM_InternalError(null, "DKIM_DNSERROR_DNSSEC_BOGUS");
	}
	if (result.rcode !== DNS.RCODE.NoError && result.rcode !== DNS.RCODE.NXDomain) {
		log.info("DNS query failed with result: " + result.toSource());
		throw new DKIM_InternalError("rcode: " + result.rcode,
			"DKIM_DNSERROR_SERVER_ERROR");
	}
	if (result.data === null || result.data[0] === "") {
		throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
	}

	log.trace("getKeyFromDNS Task end");
	return {key: result.data[0], secure: result.secure};
}

/**
 * Get the DKIM key from DB.
 * 
 * @param {String} d_val domain of the Signer
 * @param {String} s_val selector
 * 
 * @return {Promise<{key: string, secure:boolean}|Null>} The Key if it's in the DB; null otherwise
 */
async function getKeyFromDB(d_val, s_val) {
	"use strict";

	log.trace("getKeyFromDB Task begin");
	
	// wait for DB init
	await Key.initDB();
	var conn = await Sqlite.openConnection({path: KEY_DB_NAME});
	
	var sqlRes;
	var res = null;
	try {
		sqlRes = await conn.executeCached(
			"SELECT key, secure\n" +
			"FROM keys WHERE\n" +
			"  SDID = :SDID AND\n" +
			"  selector = :selector\n" +
			"ORDER BY insertedAt DESC\n" +
			"LIMIT 1;",
			{SDID:d_val, selector: s_val}
		);

		if (sqlRes.length > 0) {
			res = {
				key: sqlRes[0].getResultByName("key"),
				secure: sqlRes[0].getResultByName("secure") === 1,
			};
			await conn.executeCached(
				"UPDATE keys\n" +
				"SET lastUsedAt = DATE('now') WHERE\n" +
				"  SDID = :SDID AND\n" +
				"  selector = :selector\n" +
				";",
				{SDID:d_val, selector: s_val}
			);
			log.debug("got key from DB");
		}
	} finally {
		await conn.close();
	}
	
	log.trace("getKeyFromDB Task end");
	return res;
}

/**
 * Stores the DKIM key in the DB.
 * 
 * @param {String} d_val domain of the Signer
 * @param {String} s_val selector
 * @param {String} key DKIM key
 * @param {Boolean} secure
 * 
 * @return {Promise<void>}
 */
function setKeyInDB(d_val, s_val, key, secure) {
	"use strict";

	var promise = (async () => {
		log.trace("setKeyInDB Task begin");
		
		// wait for DB init
		await Key.initDB();
		var conn = await Sqlite.openConnection({path: KEY_DB_NAME});
		
		try {
			await conn.executeCached(
				"INSERT INTO keys (SDID, selector, key, insertedAt, lastUsedAt, secure)" +
				"VALUES (:SDID, :selector, :key, DATE('now'), DATE('now'),:secure);",
				{SDID:d_val, selector: s_val, key: key, secure: secure}
			);
			log.debug("inserted key into DB");
		} finally {
			await conn.close();
		}
		
		log.trace("setKeyInDB Task end");
	})();
	promise.then(null, function onReject(exception) {
		// Failure!  We can inspect or report the exception.
		log.fatal(exception);
	});
	
	return promise;
}

/**
 * init
 * @return {void}
 */
function init() {
	"use strict";

	if (prefs.getIntPref("storing") > PREF.KEY.STORING.DISABLED) {
		Key.initDB();
	}
}

Key.KEY_DB_NAME = KEY_DB_NAME;

init();
