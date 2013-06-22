function onLoad(paneID) {
	var fadeInEffect = Application.prefs.get('browser.preferences.animateFadeIn');
	if (!fadeInEffect.value) {
		window.sizeToContent();
	} else {
		var currentPane = document.getElementById(paneID);
		var changeWidthBy = currentPane._content.scrollWidth - currentPane._content.clientWidth;
		window.resizeBy(changeWidthBy, 0);
	}
}
