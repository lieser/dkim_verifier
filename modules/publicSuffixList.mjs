/**
 * Utilities around the Public Suffix List https://publicsuffix.org/
 *
 * Copyright (c) 2026 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import { getDomainFromAddr } from "./utils.mjs.js";
import psl from "../thirdparty/psl/dist/psl.mjs";

/**
 * Returns the base domain for an e-mail address.
 *
 * This considers both the section of ICANN domains and PRIVATE domains.
 *
 * @param {string} addr
 * @returns {string}
 */
export default function getBaseDomainFromAddr(addr) {
	const parsed = psl.parse(getDomainFromAddr(addr));
	// @ts-expect-error
	return parsed.domain ?? parsed.tld;
}
