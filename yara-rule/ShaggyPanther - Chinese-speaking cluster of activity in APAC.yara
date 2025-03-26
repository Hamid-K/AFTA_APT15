rule apt_ShaggyPanther_backdoor: ShaggyPanther
{
meta:

    report        = "ShaggyPanther - Chinese-speaking cluster of activity in APAC"
    description   = "Rule to detect ShaggyPanther samples"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2017-12-13"
    last_modified = "2017-12-13"

strings:

    $a1 = "Referer: http://%s:%d/FileAttached.asp?FtCache=%d"
    $a2 = "POST /FileAttached.asp?FtCache=%d HTTP/1.1"
    $a3 = "Xor@neisAdmin"
    $a4 = "SYSTEM\\CurrentControlSet\\Services\\ntmssvc"
    $a5 = "Ntmssvcmain"
    $a6 = "%s\\xpr122.dll"

condition:

    uint16(0) == 0x5A4D and
    filesize < 1200000 and
    3 of them
}



rule apt_ShaggyPanther_registry_payload_loader: ShaggyPanther
{
meta:

    report        = "ShaggyPanther - Chinese-speaking cluster of activity in APAC"
    description   = "Rule to detect ShaggyPanther registry payload loader"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.1"
    date          = "2018-06-12"
    last_modified = "2018-06-12"

strings:

    $a1 = {0F BE 07 47 8B 04 85 ?? ?? ?? ?? 3D FF 00 00 00 74 21 C1 E1 06 0B C8 4E 75 19 88 4A 02 83 C2 03 C1 E9 08 88 4A FE BE 04 00 00 00 C1 E9 08 88 4A FD 33 C9 }
    $a2 = "SBk0EFGHIJKLMNrPQRATUXWVYZabcdefghijClmnvpqOstuowxyzD128456739#%"

condition:

    uint16(0) == 0x5A4D and
    filesize < 1200000 and
    all of them
}



