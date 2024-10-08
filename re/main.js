const highlight = editor => {
	editor.textContent = editor.textContent
	hljs.highlightBlock(editor)
};

var ReTool = {
	asm: null,
	bytes: document.getElementById("bytes"),
	log_: document.getElementById("log"),
	baseAddr: "0x10000",

	log: function (t) {
		this.log_.value += t + "\n";
	},
	logch: function (t) {
		this.log_.value += t;
	},

	exportC: function () {
		this.log_.value = "char export[] = {";
		var hex = this.convertHex(this.bytes.value);
		for (var c in hex) {
			this.log_.value += "0x" + hex[c].toString(16) + ", ";
		}
		this.log_.value += "};";
	},

	convertHex: function (text) {
		var ret = [];
		text = text.replace(/0x/g, "");
		var re = text.matchAll(/([0-9A-Fa-f]+)/g);
		for (var i of re) {
			ret.push(parseInt(i[1], 16));
		}
		return ret;
	},
	
	fromU32: function () {
		var array = this.convertHex(this.bytes.value);
		var byteArray = [];

		for (let i = 0; i < array.length; i++) {
		    const u32 = array[i];
		    byteArray.push(u32 & 0xFF);
		    byteArray.push((u32 >> 8) & 0xFF);
		    byteArray.push((u32 >> 16) & 0xFF);
		    byteArray.push((u32 >> 24) & 0xFF);
		}
		
		this.bytes.value = "";
		for (var i = 0; i < byteArray.length; i++) {
			var hex = byteArray[i].toString(16);
			if (hex.length == 1) {
				this.bytes.value += "0";
			}
			this.bytes.value += hex;
			if (i != 0 && !((i + 1) % 4)) {
				this.bytes.value += "\n";
			} else {
				this.bytes.value += " ";
			}
		}
	},

	prettify: function () {
		var text = this.bytes.value;
		this.bytes.value = "";
		var code = this.convertHex(text);
		for (var i = 0; i < code.length; i++) {
			var hex = code[i].toString(16);
			if (hex.length == 1) {
				this.bytes.value += "0";
			}
			this.bytes.value += hex;
			if (i != 0 && !((i + 1) % 4)) {
				this.bytes.value += "\n";
			} else {
				this.bytes.value += " ";
			}
		}
	},

	prettifyUint: function () {
		var text = this.bytes.value;
		this.bytes.value = "";
		var code = this.convertHex(text);
		for (var i = 0; i < code.length; i += 4) {
			var uint = (code[i + 3] << 24) | (code[i + 2] << 16) | (code[i + 1] << 8) | code[i + 0];
			var hex = (new Uint32Array([uint])[0]).toString(16);
			this.bytes.value += hex;
			this.bytes.value += "\n";
		}
	},

	cs_arch: cs.ARCH_ARM,
	ks_arch: ks.ARCH_ARM,
	uc_arch: uc.ARCH_ARM,

	dis: function () {
		var byte = this.convertHex(this.bytes.value);
		this.asm.updateCode("");
		var offset = this.baseAddr;
		var d = new cs.Capstone(this.cs_arch, cs.MODE_LITTLE_ENDIAN);
		try {
			var instructions = d.disasm(byte, offset);
			var value = "";
			instructions.forEach(function (instr) {
				value += instr.mnemonic + " " + instr.op_str + "\n";
			}, this);
			this.asm.updateCode(value);
		} catch (e) {
			this.log(e);
			return;
		}
		try {
			d.close();
		} catch (e) {
			return;
		}
	},

	assemble: function () {
		this.bytes.value = "";
		var mode = 0;
		if (this.ks_arch == ks.ARCH_X86) mode |= ks.MODE_64;
		var a = new ks.Keystone(this.ks_arch, mode);
		var code;
		try {
			code = a.asm(this.asm.toString() + "\n", this.baseAddr);
		} catch (err) {
			this.log(err);
			throw err;
			return;
		}
		for (var i = 0; i < code.length; i++) {
			this.bytes.value += code[i].toString(16) + " ";
		}
		a.close();
		this.prettify();
	},

	read_reg: function(e, i) {
		if (this.uc_arch == uc.ARCH_ARM64) {
			return e.reg_read_i64(uc["ARM64_REG_X" + i]) >>> 0;
		} else if (this.uc_arch == uc.ARCH_ARM) {
			return e.reg_read_i32(uc["ARM_REG_R" + i]) >>> 0;
		} else if (this.uc_arch == uc.ARCH_X86) {
			var x86 = ["X86_REG_EAX", "X86_REG_EBX", "X86_REG_ECX", "X86_REG_ESP", "X86_REG_EBP", "X86_REG_EDI", "X86_REG_ESI", "X86_REG_EDX"];
			return e.reg_read_i32(uc[x86[i]]) >>> 0;
		} else {
			throw Error("bad");
		}
	},

	execute: function () {
		var code = this.convertHex(this.bytes.value);
		var mode = 0;
		if (this.uc_arch == uc.ARCH_ARM64 || this.uc_arch == uc.ARCH_ARM) mode |= uc.MODE_ARM;
		if (this.uc_arch == uc.ARCH_X86) mode |= uc.MODE_32;
		var e = new uc.Unicorn(this.uc_arch, mode);
		e.hook_add(uc.HOOK_INTR, function(e, intr, user_data) {
			var chr = ReTool.read_reg(e, 0);
			ReTool.logch(String.fromCharCode(chr));
		});
		e.mem_map(eval(this.baseAddr), 1024 * 1024 * 2, uc.PROT_ALL);
		e.mem_write(eval(this.baseAddr), code);

		try {
			e.emu_start(eval(this.baseAddr), eval(this.baseAddr) + code.length, 0, 0);
		} catch (err) {
			this.log(err);
		}

		var r0 = this.read_reg(e, 0);
		for (var i = 1; i < 8; i++) {
			console.log("r" + i + ":\t0x" + this.read_reg(e, i).toString(16)) >> 0;
		}
		this.log("r0 return value: " + r0.toString(16));

		this.log_.scrollTop = this.log_.scrollHeight;
	},

	init: function () {
		this.asm = CodeJar(document.querySelector(".editor"), highlight);
		this.log("RE v3");
		this.log("Running Capstone, Unicorn, and Keystone");
		this.log("You can use python-like hex() and chr() functions in the JS console.");
	},
};

ReTool.init();
