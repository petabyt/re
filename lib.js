function hex(integer) {
	return "0x" + integer.toString(16);
}

function int(str) {
	return Math.floor(Number(str));
}

function chr(code) {
	return String.fromCharCode(code);
}

function ord(char) {
	return char.charCodeAt();
}
