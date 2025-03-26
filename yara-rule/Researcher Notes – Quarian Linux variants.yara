rule apt_CloudComputating_QuarianLinux {
meta:	
	description = "Rule to detect linux version of Quarian"
	author = "afta"
	copyright = "afta"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2021-06-18"
	hash		  = "cc2736b1572c211d3fae685156a41332"
	hash		  = "90ce1320bd999c17abdf8975c92b08f7"

strings:
	$u1 = {34 30 37 20 00 20 32 30 30 20 00 00 00 00 00 00 43 4F 4E 4E 45 43 54}
	$u2 = "/tmp/AntiVirtmp" ascii wide
	$u3 = {25 73 3A 25 75 00 20 25 73 3A 25 73 40 25 73 3A 25 75 00 61 2B 62 00 72 62 00}
	$u4 = {0F B6 03 89 DA 40 28 EA 83 F0 A9 31 D0 88 03 48 83 C3 01}

	$a1 = "'$PWD\">\"" ascii
	$a2 = "echo $PWD\">\"" ascii
	$a3 = "/proc/%d/exe" ascii

	$c1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)"
	$c2 = "CONNECT %s:%u HTTP/1.1"
	$c3 = "Proxy-Authenticate: Basic"

condition:
	uint32(0)==0x464c457f and
	(filesize > 10KB) and (filesize < 50KB) and
	(
		(any of ($u*)) or
		(2 of ($a*)) and
		(all of ($c*))
	)
}
