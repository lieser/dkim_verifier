/* eslint strict: ["warn", "function"] */
/* global Preferences */

// @ts-ignore
Preferences.addAll([
	// ===== general settings =====

	// --- general tab ---
	{ id: "extensions.dkim_verifier.dkim.enable", type: "bool" },
	{ id: "extensions.dkim_verifier.key.storing", type: "int" },
	{ id: "extensions.dkim_verifier.saveResult", type: "bool" },
	{ id: "extensions.dkim_verifier.arh.read", type: "bool" },

	// --- DNS tab ---
	{ id: "extensions.dkim_verifier.dns.resolver", type: "int" },
	{ id: "extensions.dkim_verifier.dns.getNameserversFromOS", type: "bool" },
	{ id: "extensions.dkim_verifier.dns.nameserver", type: "string" },

	{ id: "extensions.dkim_verifier.dns.timeout_connect", type: "int" },
	{ id: "extensions.dkim_verifier.dns.proxy.enable", type: "bool" },
	{ id: "extensions.dkim_verifier.dns.proxy.type", type: "string" },
	{ id: "extensions.dkim_verifier.dns.proxy.host", type: "string" },
	{ id: "extensions.dkim_verifier.dns.proxy.port", type: "string" },

	{ id: "extensions.dkim_verifier.dns.libunbound.path", type: "string" },
	{ id: "extensions.dkim_verifier.dns.libunbound.path.relToProfileDir", type: "bool" },

	// --- policy tab ---
	{ id: "extensions.dkim_verifier.policy.signRules.enable", type: "bool" },
	{ id: "extensions.dkim_verifier.policy.signRules.checkDefaultRules", type: "bool" },
	{ id: "extensions.dkim_verifier.policy.signRules.autoAddRule", type: "bool" },
	{ id: "extensions.dkim_verifier.policy.signRules.autoAddRule.onlyIfFromAddressInSDID", type: "bool" },
	{ id: "extensions.dkim_verifier.policy.signRules.autoAddRule.for", type: "int" },
	{ id: "extensions.dkim_verifier.policy.signRules.sdid.allowSubDomains", type: "bool" },
	{ id: "extensions.dkim_verifier.error.policy.wrong_sdid.asWarning", type: "bool" },
	{ id: "extensions.dkim_verifier.policy.DMARC.shouldBeSigned.enable", type: "bool" },

	// ===== discplay settings =====

	{ id: "extensions.dkim_verifier.colorFrom", type: "bool" },

	{ id: "extensions.dkim_verifier.color.success.text", type: "string" },
	{ id: "extensions.dkim_verifier.color.success.background", type: "string" },
	{ id: "extensions.dkim_verifier.color.warning.text", type: "string" },
	{ id: "extensions.dkim_verifier.color.warning.background", type: "string" },
	{ id: "extensions.dkim_verifier.color.permfail.text", type: "string" },
	{ id: "extensions.dkim_verifier.color.permfail.background", type: "string" },
	{ id: "extensions.dkim_verifier.color.tempfail.text", type: "string" },
	{ id: "extensions.dkim_verifier.color.tempfail.background", type: "string" },
	{ id: "extensions.dkim_verifier.color.nosig.text", type: "string" },
	{ id: "extensions.dkim_verifier.color.nosig.background", type: "string" },

	{ id: "extensions.dkim_verifier.showDKIMHeader", type: "int" },
	{ id: "extensions.dkim_verifier.showDKIMStatusbarpanel", type: "int" },
	{ id: "extensions.dkim_verifier.statusbarpanel.result.style", type: "int" },
	{ id: "extensions.dkim_verifier.showDKIMFromTooltip", type: "int" },

	{ id: "extensions.dkim_verifier.display.favicon.show", type: "bool" },

	// ===== discplay settings =====

	{ id: "extensions.dkim_verifier.debug", type: "bool" },
	{ id: "extensions.dkim_verifier.error.detailedReasons", type: "bool" },
	{ id: "extensions.dkim_verifier.error.key_testmode.ignore", type: "bool" },
	{ id: "extensions.dkim_verifier.display.keySecure", type: "bool" },
	{ id: "extensions.dkim_verifier.arh.replaceAddonResult", type: "bool" },
	{ id: "extensions.dkim_verifier.arh.relaxedParsing", type: "bool" },
	{ id: "extensions.dkim_verifier.error.illformed_i.treatAs", type: "int" },
	{ id: "extensions.dkim_verifier.error.illformed_s.treatAs", type: "int" },
	{ id: "extensions.dkim_verifier.error.policy.key_insecure.treatAs", type: "int" },
	{ id: "extensions.dkim_verifier.error.algorithm.sign.rsa-sha1.treatAs", type: "int" },
	{ id: "extensions.dkim_verifier.error.algorithm.rsa.weakKeyLength.treatAs", type: "int" },
]);

// @ts-ignore
Preferences.forceEnableInstantApply();
