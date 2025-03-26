rule QSC_Framework_GoClient{

meta:
	description = "Rule to detect GoClient backdoor"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2024-05-03"
	hash = "5eba7f8a9323c2d9ceac9a0f91fad02f"

strings:
	$s1 = "Command.go"
	$s2 = "File.go"
	$s3 = "GetClientInfo.go"
	$s4 = "ScreenShot.go"

condition:
	uint16(0) == 0x5a4d and 
	(filesize >= 4000KB and 
	filesize <= 6000KB) and 
	all of them
}
