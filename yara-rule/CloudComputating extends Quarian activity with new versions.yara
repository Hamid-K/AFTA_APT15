import "pe"

rule apt_CloudComputating_QuarianBackdoor_Ver_1_2 {
meta:
	description = "Rule to detect Quarian backdoor used in CloudComputating campaign Ver 1 and 2"
	author = "afta"
	copyright = "afta"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2021-08-25"
	hash = "A0254C1D451F1B3EAD967A27EF4C3A9B"
	hash = "F76C8F372305DBA357347A16AF96D07A"
	hash = "D96862823246AB5C0C8E26CCBB3130E0"

strings:
	$a1 = "http=@ProxyServer@ProxyEnable@\\Software\\Microsoft" wide ascii
	
	$b1 = "\\alg.exe" wide ascii
	$b2 = "\\acrobat17.exe" wide ascii
	$b3 = "sharedaccess.ini" wide ascii
	$b4 = "the.db" wide ascii
	$b5 = "ComSpec" wide ascii nocase
	$b6 = "the.ini" wide ascii
	$b7 = "ssp.tmp" wide ascii
	$b8 = "icmp.db" wide ascii
	$b9 = "log.dat" wide ascii

condition:
	uint16(0) == 0x5A4D and
	(filesize > 10000) and (filesize < 200000) and
	($a1 or (3 of ($b*)))
}

rule apt_CloudComputating_QuarianBackdoor_Ver_3{
meta:
	description   = "Rule to detect Quarian Ver 3 aka Turian"
	author = "afta"
	copyright = "afta"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2021-08-25"
	hash = "D3068DBBB1C7D1188C9C8DBE1DC0C15D"
	hash = "417963AECAD13EE04728862A9D71DACA"
	hash = "066023CC695E54B67CE0D7FA26438CEC"

strings:
	$a1 = "ReG aDd %s%s /v \"%S\" /t REG_SZ /d \"%S\" /f" wide
	$a2 = "ReG aDd %s%S /v ImagePath /t REG_EXPAND_SZ /d \"%S\"" wide
	$a3 = "ReG dELete %s%S\\pARamEteRs /v ServiceDllUnloadOnSto" wide
	$a4 = "ReG aDd %s%S\\pARamEteRs /v ServiceDll /t REG_EXPAND" wide
	$a5 = "hKEy_LOcAl_MaChiNE\\SYsTEm\\CuRRenTCoNTRolSeT\\SeRViCe" wide
	$a6 = "\\\\sOFtWArE\\\\MIcrOsOft\\\\WindOwS\\\\CurRentVeRsiOn\\\\RuN" wide
	$a7 = "ReG aDd \"HKEY_LOCAL_MaCHiNE\\SoFTwArE\\MicrOsoFt\\WindoWs NT\\CurrENtVersion\\WinDOws\""

	$b1 = "AntiVir" wide
	$b2 = "CData" wide
	$b3 = "Cloud" wide
	$b4 = ".ini" wide

	$gu1 = "[WW]" wide
	$gu2 = "[DW]" wide
	$gu3 = "[WS]" wide
	$gu4 = "[DS]" wide
	$gu5 = "[DC]" wide
	$gu6 = "[DP]" wide
	$gu7 = "[UK]" wide

condition:
	uint16(0) == 0x5A4D and
	(filesize > 10KB) and (filesize < 1MB) and
	(
		any of ($a*) and 3 of ($b*) or
		any of ($a*) and 5 of ($gu*) or 
		3 of ($b*) and 5 of ($gu*)
	)
}

rule apt_CloudComputating_QuarianBackdoor_Ver_4_TinyQuarian {
meta:
	description   = "Rule to detect Tiny Quarian aka Ver 4"
	author = "afta"
	copyright = "afta"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2021-08-25"
	hash = "2C96638ACF0672F80AC05EEB107C0CC7"
	hash = "1E36CB3895B0A29DCC0D2535F3CD469D"
	hash = "F9E2B8139B53A4E83442A3F0AACFFC79"

strings:
	$c1 = "test-pc" ascii
	$c2 = "workgroup" ascii
	$c3 = "00:00:00:00" ascii
	$c4 = "%s %s %s %s" ascii
	$c5 = "1.1.1.1" ascii

	$d1 = "InterlockedIncrementbydll" ascii
	$d2 = "version = %d" ascii
	$d3 = "comadmin.msc" ascii
	$d4 = "threaddll.dll" wide
	$d5 = "cmdinfodll\\threaddll\\Release\\threaddll.dll" wide
	$d6 = "comadmin.dll" ascii

condition:
	uint16(0) == 0x5A4D and
	(filesize > 10KB) and (filesize < 400KB) and
	(
		4 of ($c*) and 3 of ($d*)
	)
}
