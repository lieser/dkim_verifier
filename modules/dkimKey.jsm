/*
 * dkimKey.jsm
 * 
 * Version: 1.0.0pre1 (27 October 2013)
 * 
 * Copyright (c) 2013 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* global Components, Services, Sqlite, Task, Promise */
/* global ModuleGetter, Logging, DNS */
/* global exceptionToStr, DKIM_SigError, DKIM_InternalError */
/* exported EXPORTED_SYMBOLS, Key */

var EXPORTED_SYMBOLS = [
	"Key"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/Task.jsm"); // Requires Gecko 17.0

Cu.import("resource://dkim_verifier/ModuleGetter.jsm");
ModuleGetter.getPromise(this);
ModuleGetter.getSqlite(this);

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");
Cu.import("resource://dkim_verifier/DNSWrapper.jsm");

/**
 * @public
 */
const KEY_DB_NAME = "dkimKey.sqlite";
const PREF_BRANCH = "extensions.dkim_verifier.key.";


var prefs = Services.prefs.getBranch(PREF_BRANCH);
var log = Logging.getLogger("Key");
var dbInitialized = false;
// Deferred<boolean>
var dbInitializedDefer = Promise.defer();

var Key = {
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

		var promise = Task.spawn(function () {
			log.trace("initDB Task begin");
			
			Logging.addAppenderTo("Sqlite.Connection."+KEY_DB_NAME, "sql.");
			
			var conn = yield Sqlite.openConnection({path: KEY_DB_NAME});

			try {
				// get version numbers
				yield conn.execute(
					"CREATE TABLE IF NOT EXISTS version (\n" +
					"  name TEXT PRIMARY KEY NOT NULL,\n" +
					"  version INTEGER NOT NULL\n" +
					");"
				);
				var sqlRes = yield conn.execute(
					"SELECT * FROM version;"
				);
				var versionTableKeys = 0;
				sqlRes.forEach(function(element/*, index, array*/){
					switch(element.getResultByName("name")) {
						case "TableKeys":
							versionTableKeys = element.getResultByName("version");
							break;
					}
				});
				log.trace("versionTableKeys: "+versionTableKeys);

				// table keys
				if (versionTableKeys < 1) {
					log.trace("create table keys");
					// create table
					yield conn.execute(
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
					yield conn.execute(
						"INSERT INTO version (name, version)" +
						"VALUES ('TableKeys', 1);"
					);
					versionTableKeys = 1;
				} else if (versionTableKeys !== 1) {
						throw new DKIM_InternalError("unsupported versionTableKeys");
				}
			} finally {
				yield conn.close();
			}
			
			dbInitializedDefer.resolve(true);
			log.debug("DB initialized");
			log.trace("initDB Task end");
			throw new Task.Result(true);
		});
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(exceptionToStr(exception));
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
	getKey: function Key_getKey(d_val, s_val) {
		"use strict";

		var promise = Task.spawn(function () {
			log.trace("getKey Task begin");

			var res={};
			var tmp;
			
			switch (prefs.getIntPref("storing")) {
				case 0: // don't store DKIM keys
					tmp = yield getKeyFromDNS(d_val, s_val);
					res.gotFrom = "DNS";
					break;
				case 1: // store DKIM keys
					tmp = yield getKeyFromDB(d_val, s_val);
					if (tmp) {
						res.gotFrom = "Storage";
					} else {
						tmp =  yield getKeyFromDNS(d_val, s_val);
						res.gotFrom = "DNS";
						setKeyInDB(d_val, s_val, tmp.key, tmp.secure);
					}
					break;
				case 2: // store DKIM keys and compare with current key
					var keyDB = yield getKeyFromDB(d_val, s_val);
					tmp = yield getKeyFromDNS(d_val, s_val);
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
			throw new Task.Result(res);
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
 * @return {Promise<Object{key, secure}>}
 * 
 * @throws {DKIM_SigError|DKIM_InternalError}
 */
function getKeyFromDNS(d_val, s_val) {
	"use strict";

	var promise = Task.spawn(function () {
		log.trace("getKeyFromDNS Task begin");
		
		// get the DKIM key
		var result = yield DNS.resolve(s_val+"._domainkey."+d_val, "TXT");
		
		if (result.bogus) {
			throw new DKIM_InternalError(null, "DKIM_DNSERROR_DNSSEC_BOGUS");
		}
		if (result.error !== undefined) {
			throw new DKIM_InternalError(result.error, "DKIM_DNSERROR_SERVER_ERROR");
		}
		if (result.rdata === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
		}

		log.trace("getKeyFromDNS Task end");
		throw new Task.Result({key: result.data[0], secure: result.secure});
	});
	
	return promise;
}

/**
 * Get the DKIM key from DB.
 * 
 * @param {String} d_val domain of the Signer
 * @param {String} s_val selector
 * 
 * @return {Promise<Object{key, secure}|Null>} The Key if it's in the DB; null otherwise
 */
function getKeyFromDB(d_val, s_val) {
	"use strict";

	var promise = Task.spawn(function () {
		log.trace("getKeyFromDB Task begin");
		
		// wait for DB init
		yield Key.initDB();
		var conn = yield Sqlite.openConnection({path: KEY_DB_NAME});
		
		var sqlRes;
		var res = null;
		try {
			sqlRes = yield conn.executeCached(
				"SELECT key, secure\n" +
				"FROM keys WHERE\n" +
				"  SDID = :SDID AND\n" +
				"  selector = :selector\n" +
				"ORDER BY insertedAt DESC\n" +
				"LIMIT 1;",
				{SDID:d_val, selector: s_val}
			);

			if (sqlRes.length > 0) {
				res = {};
				res.key = sqlRes[0].getResultByName("key");
				res.secure = (sqlRes[0].getResultByName("secure") === 1);
				conn.executeCached(
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
			yield conn.close();
		}
		
		log.trace("getKeyFromDB Task end");
		throw new Task.Result(res);
	});
	
	return promise;
}

/**
 * Stores the DKIM key in the DB.
 * 
 * @param {String} d_val domain of the Signer
 * @param {String} s_val selector
 * @param {String} key DKIM key
 * @param {Boolean} secure
 * 
 * @return {Promise<Undefined>}
 */
function setKeyInDB(d_val, s_val, key, secure) {
	"use strict";

	var promise = Task.spawn(function () {
		log.trace("setKeyInDB Task begin");
		
		// wait for DB init
		yield Key.initDB();
		var conn = yield Sqlite.openConnection({path: KEY_DB_NAME});
		
		var sqlRes;
		try {
			sqlRes = yield conn.executeCached(
				"INSERT INTO keys (SDID, selector, key, insertedAt, lastUsedAt, secure)" +
				"VALUES (:SDID, :selector, :key, DATE('now'), DATE('now'),:secure);",
				{SDID:d_val, selector: s_val, key: key, secure: secure}
			);
			log.debug("inserted key into DB");
		} finally {
			yield conn.close();
		}
		
		log.trace("setKeyInDB Task end");
	});
	promise.then(null, function onReject(exception) {
		// Failure!  We can inspect or report the exception.
		log.fatal(exceptionToStr(exception));
	});
	
	return promise;
}

/**
 * init
 */
function init() {
	"use strict";

	if (prefs.getIntPref("storing")>0) {
		Key.initDB();
	}
}

Key.KEY_DB_NAME = KEY_DB_NAME;

init();
