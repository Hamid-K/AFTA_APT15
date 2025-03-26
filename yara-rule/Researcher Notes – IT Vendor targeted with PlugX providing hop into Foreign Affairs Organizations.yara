import "pe"

rule apt_PlugX_MEIT_MEM {
meta:
	description = "Rule to detect full PlugX backdoor payload, plugin timestamps 20120123"
	author = "afta"
	copyright = "afta"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2021-12-06"
	
strings:
	$s = "GULP" ascii
	$timestamp_plug = {c7 ?? 23 01 12 20} // mov [r], 0x20120123
	$c2a = "efanshion.com" ascii
	$c2b = "popanalysis.com" ascii

	$f1 = {c7 4? 04 00 10 00 00}  // mov [r+0x4], 0x1000
	$f2 = {c7 4? 04 0? c0 00 00}  // mov [r+0x4], 0xc00x (SQL functions)
	$f3 = {c7 4? 04 0? 20 00 00}  // mov [r+0xe], 0x200x (option functions)
	
condition:
	filesize < 512000 and
	all of them
}

rule apt_PlugX_MEIT_loader {
meta:
	description = "Rule to detect plugX loader deployed in ME"
	author = "afta"
	copyright = "afta"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2021-12-06"

strings:
	$enc_name = "Nv.mp" wide
	$de = { 2B C6 83 E8 05 C7 45 FC 00 00 00 00 8B 55 FC 8B C8 C1 E9 10 88 4E 03 0F B6 C9 33 CA 89 4D FC 8B 55 FC 8B C8 C1 E9 08 88 4E 02 0F B6 C9 33 CA 89 4D FC 8B 55 FC 8B C8 C1 E9 18 88 4E 04 0F B6 C9 33 CA 89 4D FC C6 06 E9 81 75 FC E9 00 00 00 8B 4D FC 88 46 01 0F B6 C0 }

condition:
	pe.characteristics & pe.DLL and
	pe.exports("NvSmartMaxNotifyAppHWND") and
	all of them
}

rule apt_PlugX_MEIT_Nvmpxenc {
meta:
	description = "Rule to detect encrypted payload deployed in ME"
	author = "afta"
	copyright = "afta"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2021-12-06"
	hash = "7d12c99b123a7caee229ad9815d4eb3c"

strings:
	$de = { 81 F1 21 C1 72 BC F7 C1 D9 00 02 05 4A 47 81 CF 44 43 A2 FF 41 4F 4F 42 81 E1 6A A0 C1 72 41 81 CA 9C C1 C9 A0 F7 C7 A5 00 F1 9D 47 47 81 FF F4 25 5C B3 81 E9 B1 2F 9C 40 81 E7 C5 55 0D FA 81 E9 7A 1B 59 99 4A F7 C7 37 3D C4 A5 81 E9 88 5F 6B FC E8 00 00 00 00 }

condition:
	filesize > 100KB and filesize < 120KB and
	all of them
}

rule apt_Cmstarinfo_Downloader_MEIT {
meta:
	description = "Rule to detect Cmstarinfo downloader - unknown OSVersion callback"
	author = "afta"
	copyright = "afta"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2021-10-06"
	hash = "c65b75d37bbf6f011e966b38da94cf28"

strings:
	$unc_OSversion_str = "Major=%d Min=%d" fullword ascii
	$c1 = { 51 ff 84 d2 75 08 85 c0 74 04 c6 41 ff 65 8d 7c }
	$c2 = { 81 ec e4 02 00 00 53 55 56 57 33 db b9 0b 00 00 }
	$c3 = { 54 24 1d 88 5c 24 18 f3 ab 89 54 24 21 8d 84 24 }

condition:
	uint16(0) == 0x5A4D and
	all of them
}
