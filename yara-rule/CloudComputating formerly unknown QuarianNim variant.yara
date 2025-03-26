rule apt_CouldComputating_QuarianNim {
meta:
	description = "Rule to detect new QuarianNim variant"
	author = "afta"
	copyright = "afta"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2021-10-20"
	hash = "EB5BBA1FAADEBC148674F912CE6DDF20"

strings:
	$a1 = "@<>:U&*(IHRFGHBD^&*(IOKN"

	$b1 = "@cmd /K chcp 65001"
	$b2 = "@\\\\.\\pipe\\stdin"
	$b3 = "@\\\\.\\pipe\\stdout"

	$c1 = "net.nim"
	$c2 = "threads.nim"
	$c3 = "streams.nim"
	$c4 = "httpclient.nim"
	$c5 = "agent.nim"

condition:
	(filesize > 40KB) and (filesize < 500KB) and
	(
		$a1 or
		(all of ($b*) and 3 of ($c*))
	)
}
