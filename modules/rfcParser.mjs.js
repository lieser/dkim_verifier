/**
 * rfcParser.mjs.js
 *
 * Version: 0.1.0 (31 January 2020)
 *
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import {DKIM_InternalError, DKIM_SigError} from "./error.mjs.js";

export default class RfcParser {
	// WSP help pattern as specified in Section 2.8 of RFC 6376
	static get WSP() { return "[ \t]"; }
	// FWS help pattern as specified in Section 2.8 of RFC 6376
	static get FWS() { return `(?:${RfcParser.WSP}*(?:\r\n)?${RfcParser.WSP}+)`; }

	/**
	 * Parses a Tag=Value list.
	 * Specified in Section 3.2 of RFC 6376.
	 *
	 * @param {String} str
	 *
	 * @return {Map<String, String>|Number} Map
	 *                       -1 if a tag-spec is ill-formed
	 *                       -2 duplicate tag names
	 */
	static parseTagValueList(str) {
		const tval = "[!-:<-~]+";
		const tagName = "[A-Za-z][A-Za-z0-9_]*";
		const tagValue = `(?:${tval}(?:(${RfcParser.WSP}|${RfcParser.FWS})+${tval})*)?`;

		// delete optional semicolon at end
		if (str.charAt(str.length-1) === ";") {
			str = str.substr(0, str.length-1);
		}

		const array = str.split(";");
		/** @type{Map<String, String>} */
		const map = new Map();
		for (const elem of array) {
			// get tag name and value
			const tmp = elem.match(new RegExp(
				`^${RfcParser.FWS}?(${tagName})${RfcParser.FWS}?=${RfcParser.FWS}?(${tagValue})${RfcParser.FWS}?$`
			));
			if (tmp === null) {
				return -1;
			}
			const name = tmp[1];
			const value = tmp[2];

			// check that tag is no duplicate
			if (map.has(name)) {
				return -2;
			}

			// store Tag=Value pair
			map.set(name, value);
		}

		return map;
	}

	/**
	 * Parse a tag value stored in a Map.
	 *
	 * @param {Map<String, String>} map
	 * @param {String} tagName name of the tag
	 * @param {String} patternTagValue Pattern for the tag-value
	 * @param {Number} [expType=1] Type of exception to throw. 1 for DKIM header, 2 for DKIM key, 3 for general.
	 *
	 * @return {RegExpMatchArray|Null} The match from the RegExp if tag_name exists, otherwise null
	 *
	 * @throws {DKIM_SigError|DKIM_InternalError} Throws if tag_value does not match.
	 */
	static parseTagValue(map, tagName, patternTagValue, expType = 1) {
		const tagValue = map.get(tagName);
		// return null if tag_name doesn't exists
		if (tagValue === undefined) {
			return null;
		}

		const res = tagValue.match(new RegExp(`^${patternTagValue}$`));

		// throw DKIM_SigError if tag_value is ill-formed
		if (res === null) {
			if (expType === 1) {
				throw new DKIM_SigError(`DKIM_SIGERROR_ILLFORMED_${tagName.toUpperCase()}`);
			} else if (expType === 2) {
				throw new DKIM_SigError(`DKIM_SIGERROR_KEY_ILLFORMED_${tagName.toUpperCase()}`);
			} else {
				throw new DKIM_InternalError(`illformed tag ${tagName}`);
			}
		}

		return res;
	}
}
