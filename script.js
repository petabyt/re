var asm = document.getElementById("asm");
var bytes = document.getElementById("bytes");
var log_ = document.getElementById("log");

asm.value = 
`// Arm preprocessor test
.macro HELLO_WORLD
.ascii "Hello, World"
.endm

// Jump over these bytes
b end
foo:
	.ascii "Hello, World"
	.byte 0,0,0,0
end:

// Return a string in r0
adr r0, foo`;

baseAddr = "0x10000";

log_.value = "Stupid reverse engineering tool v1\n";
log_.value += "Running Capstone ARM, Unicorn-arm\n";
log_.value += "You can use python like hex() and chr() functions in the JS console."

function log(t) {
	log_.value += t + "\n";
}

log("");

function convertHex(text) {
	ret = [];

	text = text.replace(/0x/g, "");
	re = text.matchAll(/([0-9A-Fa-f]+)/g);
	for (i of re) {
		ret.push(parseInt(i[1], 16));
	}

	return ret;
}

function dis() {
	byte = convertHex(bytes.value)
	asm.value = "";

	if (bytes.length < 4) {
		log("Not enough bytes from parser");
		return;
	}

	var offset = baseAddr;
	var d = new cs.Capstone(cs.ARCH_ARM, cs.MODE_LITTLE_ENDIAN);
	try {
		var instructions = d.disasm(byte, offset);
		instructions.forEach(function (instr) {
			asm.value += instr.mnemonic + " " + instr.op_str + "\n";
		});
	} catch (e) {
		log(e);
		return;
	}

	// Delete decoder
	d.close();
}

function assemble() {
	bytes.value = "";
	var a = new ks.Keystone(ks.ARCH_ARM, ks.MODE_LITTLE_ENDIAN);
	var code = a.asm(asm.value, baseAddr);
	for (var i = 0; i < code.length; i++) {
		bytes.value += code[i].toString(16) + " ";
	}

	a.close();
}

function execute() {
	var code = convertHex(bytes.value);
	var e = new uc.Unicorn(uc.ARCH_ARM, uc.MODE_ARM);
	e.mem_map(eval(baseAddr), 0x10000, uc.PROT_ALL);
	e.mem_write(eval(baseAddr), code);
	
	try {
		e.emu_start(eval(baseAddr), eval(baseAddr) + code.length + 0x100, 0, 0);
	} catch (err) {
		log(err);
	}

	for (var i = 1; i < 10; i++) {
		log("R" + i + ":\t0x" +
			(e.reg_read_i32(uc["ARM_REG_R" + i]) >>> 0).toString(16)) >> 0;
	}

	var r0 = e.reg_read_i32(uc.ARM_REG_R0);
	log("r0 return value: " + (r0 >>> 0).toString(16));

	try {
		var returnString = e.mem_read(r0, 100);
		
		var i;
		for (i = 0; returnString[i] != 0; i++);
		
		returnString = returnString.slice(0, i);
		
		try {
			log("Return string: " + String.fromCharCode.apply(null, returnString));
		} catch {
			console.log("No string");
		}
	} catch (e) {
		//console.log(e);
	}

	log_.scrollTop = log_.scrollHeight;
}
