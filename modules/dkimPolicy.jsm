/*
 * dkimPolicy.jsm
 * 
 * Version: 1.0.0pre3 (16 October 2013)
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
/* jshint -W069 */ // "['{a}'] is better written in dot notation."
/* global Components, Services, Sqlite, Task, Promise */
/* global Logging */
/* global exceptionToStr, readStringFrom, stringEndsWith, DKIM_InternalError */
/* exported EXPORTED_SYMBOLS, Policy */

var EXPORTED_SYMBOLS = [
	"Policy"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/osfile.jsm"); // Requires Gecko 16.0
Cu.import("resource://gre/modules/Promise.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/Sqlite.jsm"); // Requires Gecko 20.0
Cu.import("resource://gre/modules/Task.jsm"); // Requires Gecko 17.0

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");


const DB_POLICY_NAME = "dkimPolicy.sqlite";
const PREF_BRANCH = "extensions.dkim_verifier.policy.";

// rule types
const RULE_TYPE = {
	SIGNED : 1,
	NEUTRAL: 2,
};
// default rule priorities
const PRIORITY = {
	AUTOINSERT_RULE_SIGNED:  110,
	DEFAULT_RULE_SIGNED:     210,
	DEFAULT_RULE_SIGNED2:     211,
	DEFAULT_RULE_NEUTRAL:    220,
	USERINSERT_RULE_SIGNED:  310,
	USERINSERT_RULE_NEUTRAL: 320,
};


var prefs = Services.prefs.getBranch(PREF_BRANCH);
var log = Logging.getLogger("Policy");
var eTLDService = Components.classes["@mozilla.org/network/effective-tld-service;1"]
	.getService(Components.interfaces.nsIEffectiveTLDService);
var dbInitialized = false;
// Deferred<boolean>
var dbInitializedDefer = Promise.defer();

var Policy = {
	/**
	 * init DB
	 * May be called more then once
	 * 
	 * @return {Promise<boolean>} initialized
	 */
	initDB: function Policy_initDB() {
		"use strict";

		if (dbInitialized) {
			return dbInitializedDefer.promise;
		}
		dbInitialized = true;

		var promise = Task.spawn(function () {
			log.trace("initDB Task begin");
			
			Logging.addAppenderTo("Sqlite.Connection."+DB_POLICY_NAME, "sql.");
			
			var conn = yield Sqlite.openConnection({path: DB_POLICY_NAME});

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
				var versionTableSigners = 0;
				var versionTableSignersDefault = 0;
				var versionDataSignersDefault = 0;
				sqlRes.forEach(function(element/*, index, array*/){
					switch(element.getResultByName("name")) {
						case "TableSigners":
							versionTableSigners = element.getResultByName("version");
							break;
						case "TableSignersDefault":
							versionTableSignersDefault = element.getResultByName("version");
							break;
						case "DataSignersDefault":
							versionDataSignersDefault = element.getResultByName("version");
							break;
					}
				});
				log.trace("versionTableSigners: "+versionTableSigners+
					", versionTableSignersDefault: "+versionTableSignersDefault+
					", versionDataSignersDefault: "+versionDataSignersDefault
				);

				// table signers
				if (versionTableSigners < 1) {
					log.trace("create table signers");
					// create table
					yield conn.execute(
						"CREATE TABLE IF NOT EXISTS signers (\n" +
						"  domain TEXT NOT NULL,\n" +
						"  addr TEXT NOT NULL,\n" +
						"  sdid TEXT,\n" +
						"  ruletype INTEGER NOT NULL,\n" +
						"  priority INTEGER NOT NULL,\n" +
						"  enabled INTEGER NOT NULL\n" + // 0 (false) and 1 (true)
						");"
					);
					// add version number
					yield conn.execute(
						"INSERT INTO version (name, version)" +
						"VALUES ('TableSigners', 1);"
					);
					versionTableSigners = 1;
				} else if (versionTableSigners !== 1) {
						throw new DKIM_InternalError("unsupported versionTableSigners");
				}
				
				// table signersDefault
				if (versionTableSignersDefault < 1) {
					log.trace("create table signersDefault");
					// create table
					yield conn.execute(
						"CREATE TABLE IF NOT EXISTS signersDefault (\n" +
						"  domain TEXT NOT NULL,\n" +
						"  addr TEXT NOT NULL,\n" +
						"  sdid TEXT,\n" +
						"  ruletype INTEGER NOT NULL,\n" +
						"  priority INTEGER NOT NULL\n" +
						");"
					);
					// add version number
					yield conn.execute(
						"INSERT INTO version (name, version)\n" +
						"VALUES ('TableSignersDefault', 1);"
					);
					versionTableSignersDefault = 1;
				} else if (versionTableSignersDefault !== 1) {
						throw new DKIM_InternalError("unsupported versionTableSignersDefault");
				}
				
				// data signersDefault
				// read rules from file
				var jsonStr = yield readStringFrom("resource://dkim_verifier_data/signersDefault.json");
				var signersDefault = JSON.parse(jsonStr);
				// check data version
				if (versionDataSignersDefault < signersDefault.versionData) {
					log.trace("update default rules");
					if (signersDefault.versionTable !== versionTableSignersDefault) {
						throw new DKIM_InternalError("different versionTableSignersDefault in .json file");
					}
					// delete old rules
					yield conn.execute(
						"DELETE FROM signersDefault;"
					);
					// insert new default rules
					yield conn.executeCached(
						"INSERT INTO signersDefault (domain, addr, sdid, ruletype, priority)\n" +
						"VALUES (:domain, :addr, :sdid, :ruletype, :priority);",
						signersDefault.rules.map(function (v) {
							return {
								"domain": v.domain,
								"addr": v.addr,
								"sdid": v.sdid,
								"ruletype": RULE_TYPE[v.ruletype] || v.ruletype,
								"priority": PRIORITY[v.priority] || v.priority,
							};
						})
					);
					// update version number
					yield conn.execute(
						"INSERT OR REPLACE INTO version (name, version)\n" +
						"VALUES ('DataSignersDefault', :version);",
						{"version": signersDefault.versionData}
					);
					versionTableSignersDefault = 1;
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
	 * Determinates if e-mail by fromAddress should be signed
	 * 
	 * @param {String} fromAddress
	 * @param {Function} [callback] function callback(result, callbackData)
	 * @param [callbackData]
	 * 
	 * @return {Promise<Object>}
	 *         .shouldBeSigned true if fromAddress should be signed
	 *         .sdid {String} Signing Domain Identifier
	 *         .foundRule {Boolean} true if enabled rule for fromAddress was found
	 */
	shouldBeSigned: function Policy_shouldBeSigned(fromAddress, callback, callbackData) {
		"use strict";

		var promise = Task.spawn(function () {
			log.trace("shouldBeSigned Task begin");
			
			var result = {};

			// return false if signRules is disabled
			if (!prefs.getBoolPref("signRules.enable")) {
				result.shouldBeSigned = false;
				throw new Task.Result(result);
			}

			var domain = getBaseDomainFromAddr(fromAddress);
			
			// wait for DB init
			yield Policy.initDB();
			var conn = yield Sqlite.openConnection({path: DB_POLICY_NAME});
			
			var sqlRes;
			try {
				if (prefs.getBoolPref("signRules.checkDefaultRules")) {
					// include default rules
					sqlRes = yield conn.executeCached(
						"SELECT addr, sdid, ruletype, priority, enabled\n" +
						"FROM signers WHERE\n" +
						"  domain = :domain AND\n" +
						"  enabled AND\n" +
						"  lower(:from) GLOB addr\n" +
						"UNION SELECT addr, sdid, ruletype, priority, 1\n" +
						"FROM signersDefault WHERE\n" +
						"  domain = :domain AND\n" +
						"  lower(:from) GLOB addr\n" +
						"ORDER BY priority DESC\n" +
						"LIMIT 1;",
						{domain:domain, "from": fromAddress}
					);
				} else {
					// don't include default rules
					sqlRes = yield conn.executeCached(
						"SELECT addr, sdid, ruletype, priority, enabled\n" +
						"FROM signers WHERE\n" +
						"  lower(:from) GLOB addr AND\n" +
						"  enabled\n" +
						"ORDER BY priority DESC\n" +
						"LIMIT 1;",
						{"from": fromAddress}
					);
				}
			} finally {
				yield conn.close();
			}
			
			if (sqlRes.length > 0) {
				if (sqlRes[0].getResultByName("ruletype") === RULE_TYPE["SIGNED"]) {
					result.shouldBeSigned = true;
				} else {
					result.shouldBeSigned = false;
				}
				result.sdid = sqlRes[0].getResultByName("sdid");
				result.foundRule = true;
			} else {
				result.shouldBeSigned = false;
				result.foundRule = false;
			}
			
			log.debug("shouldBeSigned: "+result.shouldBeSigned+"; sdid: "+result.sdid+
				"; foundRule: "+result.foundRule
			);
			log.trace("shouldBeSigned Task end");
			throw new Task.Result(result);
		});
		if (callback !== undefined) {
			promise.then(function onFulfill(result) {
				// result == "Resolution result for the task: Value!!!"
				// The result is undefined if no special Task.Result exception was thrown.
				if (callback) {
					callback(result, callbackData);
				}
			}).then(null, function onReject(exception) {
				// Failure!  We can inspect or report the exception.
				log.fatal(exceptionToStr(exception));
			});
		}
		return promise;
	},
	
	/**
	 * Adds should be signed rule if no enabled rule for fromAddress is found
	 * 
	 * @param {String} fromAddress
	 * @param {String} sdid
	 * 
	 * @return {Promise<Undefined>}
	 */
	signedBy: function Policy_signedBy(fromAddress, sdid) {
		"use strict";

		var promise = Task.spawn(function () {
			log.trace("signedBy Task begin");
			
			// return if autoAddRule is disabled
			if (!prefs.getBoolPref("signRules.autoAddRule")) {
				return;
			}

			// return if fromAddress is not in SDID
			if (!(stringEndsWith(fromAddress, "@"+sdid) ||
			      stringEndsWith(fromAddress, "."+sdid))) {
				return;
			}

			var shouldBeSignedRes = yield Policy.shouldBeSigned(fromAddress);
			if (!shouldBeSignedRes.foundRule) {
				yield addRule(fromAddress, sdid, "SIGNED", "AUTOINSERT_RULE_SIGNED");
			}
			
			log.trace("signedBy Task end");
		});
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(exceptionToStr(exception));
		});
		return promise;
	},

	/**
	 * Adds neutral rule for fromAddress with priority USERINSERT_RULE_NEUTRAL
	 * 
	 * @param {String} fromAddress
	 * 
	 * @return {Promise<Undefined>}
	 */
	addUserException: function Policy_addUserException(fromAddress) {
		"use strict";

		var promise = Task.spawn(function () {
			log.trace("addUserException Task begin");
			
			var domain = getBaseDomainFromAddr(fromAddress);
			
			// wait for DB init
			yield Policy.initDB();
			var conn = yield Sqlite.openConnection({path: DB_POLICY_NAME});

			try {
				var sqlRes = yield conn.executeCached(
					"SELECT addr, sdid, ruletype, priority, enabled\n" +
					"FROM signers WHERE\n" +
					"  domain = :domain AND\n" +
					"  addr = :addr AND\n" +
					"  ruletype = :ruletype AND\n" +
					"  priority = :priority AND\n" +
					"  enabled\n" +
					"LIMIT 1;",
					{
						"domain": domain,
						"addr": fromAddress,
						"ruletype": RULE_TYPE["NEUTRAL"],
						"priority": PRIORITY["USERINSERT_RULE_NEUTRAL"],
					}
				);
				if (sqlRes.length === 0) {
					yield addRule(fromAddress, "", "NEUTRAL", "USERINSERT_RULE_NEUTRAL");
				}
			} finally {
				yield conn.close();
			}
			log.trace("addUserException Task end");
		});
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(exceptionToStr(exception));
		});
		return promise;
	},
};

/**
 * Returns the base domain for an e-mail address; that is, the public suffix with a given number of additional domain name parts.
 * 
 * @param {String} addr
 * @param {Number} [aAdditionalParts=0]
 * 
 * @return {String}
 */
function getBaseDomainFromAddr(addr, aAdditionalParts=0) {
	"use strict";

	// var fullDomain = addr.substr(addr.lastIndexOf("@")+1);
	var nsiURI = Services.io.newURI("http://"+addr, null, null);
	return eTLDService.getBaseDomain(nsiURI, aAdditionalParts);
}

/**
 * Adds rule.
 * Generator function.
 * 
 * @param {String} addr
 * @param {String} sdid
 * @param {String} ruletype
 * @param {String} priority
 * 
 * @return {Promise<Undefined>}
 */
function addRule(addr, sdid, ruletype, priority) {
	"use strict";

	log.trace("addRule begin");
	
	var domain = getBaseDomainFromAddr(addr);

	// wait for DB init
	yield Policy.initDB();
	var conn = yield Sqlite.openConnection({path: DB_POLICY_NAME});
	
	try {
		log.debug("add rule (domain: "+domain+", addr: "+addr+", sdid: "+sdid+
			", ruletype: "+ruletype+", priority: "+priority+", enabled: 1)"
		);
		yield conn.executeCached(
			"INSERT INTO signers (domain, addr, sdid, ruletype, priority, enabled)\n" +
			"VALUES (:domain, :addr, :sdid, :ruletype, :priority, 1);",
			{
				"domain": domain,
				"addr": addr,
				"sdid": sdid,
				"ruletype": RULE_TYPE[ruletype],
				"priority": PRIORITY[priority],
			}
		);
	} finally {
		yield conn.close();
	}

	log.trace("addRule end");
}

/**
 * init module
 */
function init() {
	"use strict";

	if (prefs.getBoolPref("signRules.enable")) {
		Policy.initDB();
	}
}

init();