var gDKIMOptionsGeneralPane = {
	init: function () {
		this.update_Policy_signRules_enable();
		this.update_key_storing();
	},
	
	update_key_storing: function () {
		var disabled = document.getElementById("key.storing").value == 0;
		document.getElementById("key.viewKeys").disabled = disabled;
	},
	
	update_Policy_signRules_enable: function () {
		var disabled = !document.getElementById("policy.signRules.enable").checked;
		document.getElementById("policy.signRules.checkDefaultRules").disabled = disabled;
		document.getElementById("policy.signRules.autoAddRule").disabled = disabled;
		document.getElementById("viewSigners").disabled = disabled;
		document.getElementById("viewSignerDefaults").disabled = disabled;
	},
}
