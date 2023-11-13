// @ts-nocheck
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* global Components */
/* global Logging, Policy */
/* exported onAccept, onCancel, init */

Components.utils.import("resource://dkim_verifier/logging.jsm.js");
Components.utils.import("resource://dkim_verifier/dkimPolicy.jsm.js");

var log = Logging.getLogger("addSignersRule");

function onAccept(){
	"use strict";

	try {
		var input = {};
		input.domain = document.getElementById("domain").value;
		input.listID = document.getElementById("listID").value;
		input.addr = document.getElementById("addr").value;
		input.sdid = document.getElementById("sdid").value;
		input.ruletype = document.getElementById("ruletype").value;
		var priorityMode = document.getElementById("priorityMode").value;
		if (priorityMode === "1") {
			switch (parseInt(input.ruletype, 10)) {
				case Policy.RULE_TYPE["ALL"]:
					input.priority = Policy.PRIORITY.USERINSERT_RULE_ALL;
					break;
				case Policy.RULE_TYPE["NEUTRAL"]:
					input.priority = Policy.PRIORITY.USERINSERT_RULE_NEUTRAL;
					break;
				case Policy.RULE_TYPE["HIDEFAIL"]:
					input.priority = Policy.PRIORITY.USERINSERT_RULE_HIDEFAIL;
					break;
				default:
					input.priority = 0;
			}
		} else {
			input.priority = document.getElementById("priority").value;
		}
		input.enabled = document.getElementById("enabled").checked;

		window.arguments[0].addRow(input);
	} catch (exception) {
		log.fatal(exception);
		return false;
	}
  return true;
}

function onCancel(){
	"use strict";

  return true;
}

function updatePriorityMode() {
	"use strict";

	document.getElementById("priority").disabled =
		document.getElementById("priorityMode").value === "1";
}

function init() {
	"use strict";

	updatePriorityMode();
}
