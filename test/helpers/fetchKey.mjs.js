/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import { DKIM_SigError } from "../../modules/error.mjs.js";
import { setKeyFetchFunction } from "../../modules/dkim/verifier.mjs.js";

const keys = {
	"example.com": {
		"brisbane": "v=DKIM1; p=" +
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
			"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
			"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
			"MmPSPDdQPNUYckcQ2QIDAQAB",
	},
};

/** @type {import("../../modules/dkim/verifier.mjs.js").KeyFetchFunction} */
// eslint-disable-next-line require-await
async function getKey(sdid, selector) {
	if (!keys[sdid]) {
		throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
	}
	const key = keys[sdid][selector];
	if (!key) {
		throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
	}
	return {
		key: key,
		secure: false,
	};
}

setKeyFetchFunction(getKey);
