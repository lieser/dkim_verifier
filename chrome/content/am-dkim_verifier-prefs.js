// @ts-check
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* exported onPreInit, onInit, onSave */

// @ts-expect-error
// eslint-disable-next-line curly
if (!DKIMVerifier) var DKIMVerifier = {};

// var gPref = null;

function onPreInit(account, _accountValues) {
	"use strict";

	DKIMVerifier.server = account.incomingServer;
}

function onInit(_aPageId, _aServerId) {
	"use strict";

	DKIMVerifier.dkimEnable = document.
		getElementById("dkimVerifier_dkim.enable");
	DKIMVerifier.arhRead = document.getElementById("dkimVerifier_arh.read");
	DKIMVerifier.allowedAuthserv = document.
		getElementById("dkimVerifier_arh.allowedAuthserv");

	DKIMVerifier.dkimEnable.value = DKIMVerifier.server.
		getIntValue("dkim_verifier.dkim.enable");
	DKIMVerifier.arhRead.value = DKIMVerifier.server.
		getIntValue("dkim_verifier.arh.read");
	DKIMVerifier.allowedAuthserv.value = DKIMVerifier.server.
		getCharValue("dkim_verifier.arh.allowedAuthserv");
}

function onSave() {
	"use strict";

	DKIMVerifier.server.setIntValue("dkim_verifier.dkim.enable",
		DKIMVerifier.dkimEnable.value);
	DKIMVerifier.server.setIntValue("dkim_verifier.arh.read",
		DKIMVerifier.arhRead.value);
	DKIMVerifier.server.setCharValue("dkim_verifier.arh.allowedAuthserv",
		DKIMVerifier.allowedAuthserv.value);
}
