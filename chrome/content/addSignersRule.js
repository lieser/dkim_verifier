"use strict";

var { Logging } = ChromeUtils.import("resource://dkim_verifier/logging.jsm");
var { Policy } = ChromeUtils.import("resource://dkim_verifier/dkimPolicy.jsm");

var log = Logging.getLogger("addSignersRule");

function onAccept() {
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

function onCancel() {
	return true;
}

function updatePriorityMode() {
	document.getElementById("priority").disabled =
		(document.getElementById("priorityMode").value === "1");
}

function init() {
	updatePriorityMode();
}

document.addEventListener("dialogaccept", function (event) {
	return onAccept();
});

document.addEventListener("dialogcancel", function (event) {
	return onCancel();
});
