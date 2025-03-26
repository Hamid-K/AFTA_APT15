rule apt_BlueTraveller
{
meta:

    report        = "BlueTraveller"
    description   = "Rule to detect BlueTraveller samples"
    hash          = "ad2ffe89d65907fcd570a5d4ca9ef1bf"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.4"
    date          = "2015-12-10"
    last_modified = "2015-12-10"

strings:

    $a1 = "PROXY_PROXY_PROXY_PROXY"  fullword ascii
    $a2 = "0ROXY_TYPE" fullword ascii
    
    $b1 = "cmd.exe /c hostname" fullword ascii
    $b2 = "/O.htm" fullword ascii
    $b3 = "%s%04d/%s" fullword ascii
    $b4 = "http://%s/%s/%s/" fullword ascii
    
    $c1 = "cmd.exe /c" fullword ascii
    $c2 = "Upload failed..." fullword ascii
    $c3 = "Download OK!" fullword ascii
    $c4 = "-download" fullword ascii
    $c5 = "-exit" fullword ascii
    $c6 = "james" fullword ascii

condition:

    uint16(0) == 0x5A4D and
    (any of ($a*) or 2 of ($b*) or 4 of ($c*))
    and filesize < 400000
}



rule apt_BlueTraveller_2
{
meta:

    report        = "BlueTraveller"
    description   = "Rule to detect BlueTraveller samples"
    hash          = "a30dc2b085d47755e6dcf39e247df98b"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.2"
    date          = "2015-12-11"
    last_modified = "2015-12-11"

strings:

    $a1 = "http://%s/%02d%02d.htm"  fullword ascii
    $a2 = "%-25s %6s %6s %22s" fullword ascii
    
    $b1 = "WinHttpCrackUrl" fullword ascii
    $b2 = "UnRegisterTypeLib" fullword ascii
    $b3 = "GetProcessTimes" fullword ascii
    $b4 = "CharToOemBuffA" fullword ascii
    $b5 = "GetInputState" fullword ascii
    $b6 = "PostThreadMessageA" fullword ascii
    
    $c1 = "Crack url failed" fullword ascii
    $c2 = "Upload data ok!" fullword ascii
    $c3 = "Error! Set privilege failed.." fullword ascii
    $c4 = "Heap alloc when download failed" fullword ascii
    $c5 = "Fully-qualified distinguished name:" ascii
    $c6 = "%sCreate file %s failed" fullword ascii

condition:

    uint16(0) == 0x5A4D and
    (any of ($a*) or 5 of ($b*) or 2 of ($c*))
    and filesize < 100000
}



rule apt_BlueTraveller_3
{
meta:

    report        = "BlueTraveller"
    description   = "Rule to detect BlueTraveller samples"
    hash          = "577f51088376e7aeb9038be96f84a2d8"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2015-12-16"
    last_modified = "2015-12-16"

strings:

    $a1 = " :install -u ServiceName"  ascii
    $a2 = "can find file %s,please check!" fullword ascii
    $a3 = "AddsvchostService() error!"
    
    $b1 = "\\Drivers" fullword ascii
    $b2 = "%s\\%s.dll" fullword ascii
    $b3 = "Ipsec%d" fullword ascii
    $b4 = "AddAccessAllowedAceEx" fullword ascii    

condition:

    uint16(0) == 0x5A4D and
    (any of ($a*) or all of ($b*))
    and filesize < 100000
}



