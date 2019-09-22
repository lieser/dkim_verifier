/*
 * dkimPolicy.jsm
 * 
 * Version: 1.4.0 (01 April 2018)
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
/* eslint no-magic-numbers: ["warn", { "ignoreArrayIndexes": true, "ignore": [0, 1] }] */
/* global Components, Services, Sqlite */
/* global Logging, DMARC */
/* global addrIsInDomain, Deferred, getBaseDomainFromAddr, PREF, readStringFrom, stringEndsWith, stringEqual, DKIM_SigError, DKIM_InternalError */
/* exported EXPORTED_SYMBOLS, Policy */

// @ts-ignore
const module_version = "1.4.0";

var EXPORTED_SYMBOLS = [
	"Policy"
];

// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/Sqlite.jsm");

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");
Cu.import("resource://dkim_verifier/dkimDMARC.jsm");


const DB_POLICY_NAME = "dkimPolicy.sqlite";
// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.policy.";
const ERROR_PREF_BRANCH = "extensions.dkim_verifier.error.";

/**
 * DKIM signing policy for a message.
 * 
 * @typedef {Object} DKIMSignPolicy
 * @property {Boolean} shouldBeSigned
 *           true if message should be signed
 * @property {String[]} sdid
 *           Signing Domain Identifier
 * @property {Boolean} foundRule
 *           true if enabled rule for message was found
 * @property {Boolean} hideFail
 *           true if HIDEFAIL rule was found
 */

/**
 * rule types
 * 
 * @public
 */
const RULE_TYPE = {
	ALL : 1, // all e-mails must be signed
	NEUTRAL: 2,
	HIDEFAIL: 3, // treat invalid signatures as nosig
};
/**
 * default rule priorities
 * 
 * @public
 */
const PRIORITY = {
	AUTOINSERT_RULE_ALL:  1100,
	DEFAULT_RULE_ALL0:     2000, // used for e-mail providers
	USERINSERT_RULE_HIDEFAIL: 2050,
	DEFAULT_RULE_ALL:     2100,
	DEFAULT_RULE_ALL_2:     2110, // used for different SDID for subdomains
	DEFAULT_RULE_NEUTRAL:    2200,
	USERINSERT_RULE_ALL:  3100,
	USERINSERT_RULE_NEUTRAL: 3200,
};


// @ts-ignore
var prefs = Services.prefs.getBranch(PREF_BRANCH);
var error_prefs = Services.prefs.getBranch(ERROR_PREF_BRANCH);
// @ts-ignore
var log = Logging.getLogger("Policy");
var dbInitialized = false;
/** @type {IDeferred<boolean>} */
var dbInitializedDefer = new Deferred();


var favicons;
var rulesUpdatedObservers = [];

var _Policy = {
	get version() { "use strict"; return module_version; },

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

		var promise = (async () => {
			log.trace("initDB Task begin");
			
			Logging.addAppenderTo("Sqlite.Connection."+DB_POLICY_NAME, "sql.");
			
			var conn = await Sqlite.openConnection({path: DB_POLICY_NAME});

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
				const TABLE_SIGNERS_VERSION_CURRENT = 1;
				var versionTableSigners = 0;
				const TABLE_SIGNERS_DEFAULT_VERSION_CURRENT = 1;
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
						default:
							log.warn("Version table contains unknown entry: " + element.getResultByName("name"));
					}
				});
				log.trace("versionTableSigners: "+versionTableSigners+
					", versionTableSignersDefault: "+versionTableSignersDefault+
					", versionDataSignersDefault: "+versionDataSignersDefault
				);

				// table signers
				if (versionTableSigners < TABLE_SIGNERS_VERSION_CURRENT) {
					log.trace("create table signers");
					// create table
					await conn.execute(
						"CREATE TABLE IF NOT EXISTS signers (\n" +
						"  domain TEXT,\n" +
						"  listID TEXT,\n" +
						"  addr TEXT NOT NULL,\n" +
						"  sdid TEXT,\n" +
						"  ruletype INTEGER NOT NULL,\n" +
						"  priority INTEGER NOT NULL,\n" +
						"  enabled INTEGER NOT NULL\n" + // 0 (false) and 1 (true)
						");"
					);
					// add version number
					await conn.execute(
						"INSERT INTO version (name, version)" +
						"VALUES ('TableSigners', 1);"
					);
					versionTableSigners = 1;
				} else if (versionTableSigners !== TABLE_SIGNERS_VERSION_CURRENT) {
						throw new DKIM_InternalError("unsupported versionTableSigners");
				}
				
				// table signersDefault
				if (versionTableSignersDefault < TABLE_SIGNERS_DEFAULT_VERSION_CURRENT) {
					log.trace("create table signersDefault");
					// create table
					await conn.execute(
						"CREATE TABLE IF NOT EXISTS signersDefault (\n" +
						"  domain TEXT NOT NULL,\n" +
						"  addr TEXT NOT NULL,\n" +
						"  sdid TEXT,\n" +
						"  ruletype INTEGER NOT NULL,\n" +
						"  priority INTEGER NOT NULL\n" +
						");"
					);
					// add version number
					await conn.execute(
						"INSERT INTO version (name, version)\n" +
						"VALUES ('TableSignersDefault', 1);"
					);
					versionTableSignersDefault = 1;
				} else if (versionTableSignersDefault !== TABLE_SIGNERS_DEFAULT_VERSION_CURRENT) {
						throw new DKIM_InternalError("unsupported versionTableSignersDefault");
				}
				
				// data signersDefault
				// read rules from file
				var jsonStr = await readStringFrom("resource://dkim_verifier_data/signersDefault.json");
				var signersDefault = JSON.parse(jsonStr);
				// check data version
				if (versionDataSignersDefault < signersDefault.versionData) {
					log.trace("update default rules");
					if (signersDefault.versionTable !== versionTableSignersDefault) {
						throw new DKIM_InternalError("different versionTableSignersDefault in .json file");
					}
					// delete old rules
					await conn.execute(
						"DELETE FROM signersDefault;"
					);
					// insert new default rules
					await conn.executeCached(
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
					// update data version number
					await conn.execute(
						"INSERT OR REPLACE INTO version (name, version)\n" +
						"VALUES ('DataSignersDefault', :version);",
						{"version": signersDefault.versionData}
					);
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
	 * Determinate if an e-mail by fromAddress should be signed
	 * 
	 * @param {String} fromAddress
	 * @param {String|Null} [listID]
	 * 
	 * @return {Promise<DKIMSignPolicy>}
	 */
	shouldBeSigned: function Policy_shouldBeSigned(fromAddress, listID) {
		"use strict";

		var promise = (async () => {
			log.trace("shouldBeSigned Task begin");
			
			/** @type {DKIMSignPolicy} */
			var result = {};

			// return false if signRules is disabled
			if (!prefs.getBoolPref("signRules.enable")) {
				result.shouldBeSigned = false;
				result.sdid = [];
				result.foundRule = false;
				result.hideFail = false;
				log.trace("shouldBeSigned Task end");
				return result;
			}

			var domain = getBaseDomainFromAddr(fromAddress);
			if (listID === "") {
				listID = null;
			}
			
			// wait for DB init
			await Policy.initDB();
			var conn = await Sqlite.openConnection({path: DB_POLICY_NAME});
			
			var sqlRes;
			try {
				var sql =
						"SELECT addr, sdid, ruletype, priority\n" +
						"FROM signers WHERE\n" +
						"  (lower(domain) = lower(:domain) OR\n" +
						"   (listID IS NOT NULL AND\n" +
						"    listID != '' AND\n" +
						"    lower(listID) = lower(:listID))\n" +
						"  ) AND\n" +
						"  enabled AND\n" +
						"  lower(:from) GLOB lower(addr)\n";
				if (prefs.getBoolPref("signRules.checkDefaultRules")) {
					// include default rules
					sql +=
						"UNION SELECT addr, sdid, ruletype, priority\n" +
						"FROM signersDefault WHERE\n" +
						"  lower(domain) = lower(:domain) AND\n" +
						"  lower(:from) GLOB lower(addr)\n";
				}
				sql +=
						"ORDER BY priority DESC\n" +
						"LIMIT 1;";
				sqlRes = await conn.executeCached(
					sql,
					{domain:domain, listID: listID, from: fromAddress}
				);
			} finally {
				await conn.close();
			}
			
			if (sqlRes.length > 0) {
				result.sdid = sqlRes[0].getResultByName("sdid").
					split(" ").filter(function (x) {return x;});
				result.foundRule = true;
				
				switch (sqlRes[0].getResultByName("ruletype")) {
					case RULE_TYPE["ALL"]:
						result.shouldBeSigned = true;
						result.hideFail = false;
						break;
					case RULE_TYPE["NEUTRAL"]:
						result.shouldBeSigned = false;
						result.hideFail = false;
						break;
					case RULE_TYPE["HIDEFAIL"]:
						result.shouldBeSigned = false;
						result.hideFail = true;
						break;
					default:
						throw new DKIM_InternalError("unknown rule type");
				}
			} else {
				var dmarcRes = await DMARC.shouldBeSigned(fromAddress);
				result.shouldBeSigned = dmarcRes.shouldBeSigned;
				result.sdid = dmarcRes.sdid;
				result.foundRule = false;
				result.hideFail = false;
			}
			
			log.debug("shouldBeSigned: "+result.shouldBeSigned+"; sdid: "+result.sdid+
				"; hideFail: "+result.hideFail+"; foundRule: "+result.foundRule
			);
			log.trace("shouldBeSigned Task end");
			return result;
		})();
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.warn(exception);
		});
		return promise;
	},

	/**
	 * Checks the SDID and AUID of a DKIM signatures.
	 * 
	 * @param {String[]} allowedSDIDs
	 * @param {String} from
	 * @param {String} sdid
	 * @param {String} auid
	 * @param {dkimSigWarning[]} warnings - in/out paramter
	 * @return {void}
	 * @throws DKIM_SigError
	 */
	checkSDID: function Policy_checkSDID(allowedSDIDs, from, sdid, auid, warnings) {
		"use strict";

		// error/warning if there is a SDID in the sign rule
		// that is different from the SDID in the signature
		if (allowedSDIDs.length > 0 &&
		    !allowedSDIDs.some(function (element/*, index, array*/) {
		      if (prefs.getBoolPref("signRules.sdid.allowSubDomains")) {
		        return stringEndsWith(sdid, element);
		      }
		      return stringEqual(sdid, element);
		    })) {
			if (error_prefs.getBoolPref("policy.wrong_sdid.asWarning")) {
				warnings.push(
					{name: "DKIM_POLICYERROR_WRONG_SDID", params: [allowedSDIDs]});
				log.debug("Warning: DKIM_POLICYERROR_WRONG_SDID");
			} else {
				throw new DKIM_SigError("DKIM_POLICYERROR_WRONG_SDID", [allowedSDIDs]);
			}
		}

		// if there is no SDID in the sign rule
		if (allowedSDIDs.length === 0) {
			// warning if from is not in SDID or AUID
			if (!addrIsInDomain(from, sdid)) {
				warnings.push({name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID"});
				log.debug("Warning: DKIM_SIGWARNING_FROM_NOT_IN_SDID");
			} else if (!stringEndsWith(from, auid)) {
				warnings.push({name: "DKIM_SIGWARNING_FROM_NOT_IN_AUID"});
				log.debug("Warning: DKIM_SIGWARNING_FROM_NOT_IN_AUID");
			}
		}
	},

	/**
	 * Get the URL to the favicon, if available.
	 * 
	 * @param {String} sdid
	 * @return {Promise<String|undefined>} url to favicon
	 */
	getFavicon: function Policy_getFavicon(sdid) {
		"use strict";

		var promise = (async () => {
			if (!favicons) {
				var faviconsStr = await readStringFrom("resource://dkim_verifier_data/favicon.json");
				favicons = JSON.parse(faviconsStr);
			}

			var url = favicons[sdid];
			if (!url) {
				url = favicons[getBaseDomainFromAddr(sdid)];
			}
			if (url) {
				url = "resource://dkim_verifier_data/favicon/" + url;
			}

			return url;
		})();
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.warn(exception);
		});
		return promise;
	},

	/**
	 * Adds should be signed rule if no enabled rule for fromAddress is found
	 * 
	 * @param {String} fromAddress
	 * @param {String} sdid
	 * 
	 * @return {Promise<void>}
	 */
	signedBy: function Policy_signedBy(fromAddress, sdid) {
		"use strict";

		var promise = (async () => {
			log.trace("signedBy Task begin");
			
			// return if signRules or autoAddRule is disabled
			if (!prefs.getBoolPref("signRules.enable") ||
			    !prefs.getBoolPref("signRules.autoAddRule")) {
				log.trace("autoAddRule is disabled");
				return;
			}

			// return if fromAddress is not in SDID
			// and options state it should
			if (!addrIsInDomain(fromAddress, sdid) &&
			    prefs.getBoolPref("signRules.autoAddRule.onlyIfFromAddressInSDID")) {
				log.trace("fromAddress is not in SDID");
				return;
			}

			var shouldBeSignedRes = await Policy.shouldBeSigned(fromAddress);
			if (!shouldBeSignedRes.foundRule) {
				var domain;
				var fromAddressToAdd;
				switch (prefs.getIntPref("signRules.autoAddRule.for")) {
					case PREF.POLICY.SIGN_RULES.AUTO_ADD_RULE.FOR.FROM:
						fromAddressToAdd = fromAddress;
						break;
					case PREF.POLICY.SIGN_RULES.AUTO_ADD_RULE.FOR.SUBDOMAIN:
						fromAddressToAdd = "*"+fromAddress.substr(fromAddress.lastIndexOf("@"));
						break;
					case PREF.POLICY.SIGN_RULES.AUTO_ADD_RULE.FOR.BASE_DOMAIN:
						domain = getBaseDomainFromAddr(fromAddress);
						fromAddressToAdd = "*";
						break;
					default:
						throw new DKIM_InternalError("invalid signRules.autoAddRule.for");
				}
				await addRule(domain, fromAddressToAdd, sdid, "ALL", "AUTOINSERT_RULE_ALL");
			}
			
			log.trace("signedBy Task end");
		})();
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(exception);
		});
		return promise;
	},

	/**
	 * Adds neutral rule for fromAddress with priority USERINSERT_RULE_NEUTRAL
	 * 
	 * @param {String} fromAddress
	 * 
	 * @return {Promise<void>}
	 */
	addUserException: function Policy_addUserException(fromAddress) {
		"use strict";

		var promise = (async () => {
			log.trace("addUserException Task begin");
			
			var domain = getBaseDomainFromAddr(fromAddress);
			
			// wait for DB init
			await Policy.initDB();
			var conn = await Sqlite.openConnection({path: DB_POLICY_NAME});

			try {
				var sqlRes = await conn.executeCached(
					"SELECT addr, sdid, ruletype, priority, enabled\n" +
					"FROM signers WHERE\n" +
					"  lower(domain) = lower(:domain) AND\n" +
					"  lower(addr) = lower(:addr) AND\n" +
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
					await addRule(null, fromAddress, "", "NEUTRAL", "USERINSERT_RULE_NEUTRAL");
				}
			} finally {
				await conn.close();
			}
			log.trace("addUserException Task end");
		})();
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(exception);
		});
		return promise;
	},

	/**
	 * Adds a function, which is called if sign rules changed.
	 * The handler function is called with the number of added rules
	 * (negative if rules where removed) as an argument.
	 * 
	 * @param {Function} handler
	 * @return {void}
	 */
	addRulesUpdatedObserver: function Policy_addRulesUpdatedListener(handler) {
		"use strict";

		rulesUpdatedObservers.push(handler);
	},

	/**
	 * Removes the sign rules changed observer.
	 * @param {Function} handler
	 * @return {void}
	 */
	removeRulesUpdatedObserver: function Policy_addRulesUpdatedListener(handler) {
		"use strict";

		rulesUpdatedObservers = rulesUpdatedObservers.filter(function(item) {
			if (item === handler) {
				return false;
			}
			return true;
		});
	},

	/**
	 * Notify the sign rules changed observer.
	 * 
	 * @param {Number} count Number of rules added
	 * @return {void}
	 */
	rulesUpdated: function Policy_rulesUpdated(count) {
		"use strict";

		rulesUpdatedObservers.forEach(function(observer) {
			if (observer) {
				observer(count);
			} else {
				log.error("observer undefined/null");
			}
		});
	},
};
var Policy = _Policy;

/**
 * Adds rule.
 * 
 * @param {String|null|undefined} domain
 * @param {String} addr
 * @param {String} sdid
 * @param {String} ruletype
 * @param {String} priority
 * 
 * @return {Promise<void>}
 */
async function addRule(domain, addr, sdid, ruletype, priority) {
	"use strict";

	log.trace("addRule begin");
	
	if (!domain) {
		domain = getBaseDomainFromAddr(addr);
	}

	// wait for DB init
	await Policy.initDB();
	var conn = await Sqlite.openConnection({path: DB_POLICY_NAME});
	
	try {
		log.debug("add rule (domain: "+domain+", addr: "+addr+", sdid: "+sdid+
			", ruletype: "+ruletype+", priority: "+priority+", enabled: 1)"
		);
		await conn.executeCached(
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
		await conn.close();
	}
	Policy.rulesUpdated(1);

	log.trace("addRule end");
}

/**
 * init module
 * @return {void}
 */
function init() {
	"use strict";

	if (prefs.getBoolPref("signRules.enable")) {
		Policy.initDB();
	}
}

Policy.RULE_TYPE = RULE_TYPE;
Policy.PRIORITY = PRIORITY;


init();
