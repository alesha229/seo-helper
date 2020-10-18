function openAuth() {
	closeReg()
	document.getElementById("auth-warp").style.top = "200px";
}

function closeAuth() {
    document.getElementById("auth-warp").style.top = "-400px";
}
function openReg() {
	closeAuth()
	document.getElementById("reg").style.top = "200px";
}

function closeReg() {
    document.getElementById("reg").style.top = "-400px";
}