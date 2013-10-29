var gDKIMOptionsGeneralPane = {
	init: function () {
		this.update_Policy_signRules_enable();
	},
	
	update_Policy_signRules_enable: function () {
		var disabled = !document.getElementById("policy.signRules.enable").checked;
		document.getElementById("policy.signRules.checkDefaultRules").disabled = disabled;
		document.getElementById("policy.signRules.autoAddRule").disabled = disabled;
		document.getElementById("viewSigners").disabled = disabled;
		document.getElementById("viewSignerDefaults").disabled = disabled;
	},
}
