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

// eslint-disable-next-line require-await
async function getKey(domain, sdid) {
	if (!keys[domain]) {
		throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
	}
	const key = keys[domain][sdid];
	if (!key) {
		throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
	}
	return {
		key: key,
		secure: false,
	};
}

setKeyFetchFunction(getKey);
