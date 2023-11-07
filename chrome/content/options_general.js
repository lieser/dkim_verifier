// @ts-nocheck

var gDKIMOptionsGeneralPane = {
	init: function () {
		gDKIMonpaneload("paneGeneral");
		this.update_key_storing();
		this.update_dns_resolver();
		this.update_dns_proxy();
		this.update_Policy_signRules_enable();
	},
	
	update_key_storing: function () {
		var disabled = document.getElementById("key.storing").value == 0;
		document.getElementById("key.viewKeys").disabled = disabled;
	},
	
	update_dns_resolver: function () {
		var deckIndex = document.getElementById("dns.resolver.label").value - 1;
		document.getElementById("resolverDeck").selectedIndex = deckIndex;
	},

	update_dns_proxy: function () {
		var disabled = !document.getElementById("dns.proxy.enable").checked;
		var proxyConfigs = document.querySelectorAll(".proxyConfig")
		for (var e of proxyConfigs) {
			e.disabled = disabled;
		}
	},

	update_Policy_signRules_enable: function () {
		var disabled = !document.getElementById("policy.signRules.enable").checked;
		document.getElementById("policy.signRules.checkDefaultRules").disabled = disabled;
		document.getElementById("policy.signRules.autoAddRule").disabled = disabled;
		document.getElementById("policy.signRules.sdid.allowSubDomains").disabled = disabled;
		document.getElementById("error.policy.wrong_sdid.asWarning").disabled = disabled;
		document.getElementById("viewSigners").disabled = disabled;
		document.getElementById("viewSignerDefaults").disabled = disabled;
		document.getElementById("policy.DMARC.shouldBeSigned.enable").disabled = disabled;
		
		this.update_Policy_autoAddRule_enable();
	},
	
	update_Policy_autoAddRule_enable: function () {
		var disabled = !document.getElementById("policy.signRules.enable").checked ||
			!document.getElementById("policy.signRules.autoAddRule").checked;
		document.getElementById("policy.signRules.autoAddRule.onlyIfFromAddressInSDID").
			disabled = disabled;
		document.getElementById("policy.signRules.autoAddRule.for").disabled = disabled;
	},
}
