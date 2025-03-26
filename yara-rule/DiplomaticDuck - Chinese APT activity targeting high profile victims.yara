rule apt_DiplomaticDuck: VixenPanda
{
meta:

    report        = "DiplomaticDuck - Chinese APT activity targeting high profile victims"
    description   = "Rule to detect DiplomaticDuck APT samples"
    hash          = "2529a937f41b92ec5a3fc0b2f911458f"
    hash          = "6469f3cd1b402e91c0314ba44fd5c595"
    hash          = "6d88c0cbb8db653537e9f1edf85d0b61"
    hash          = "76b3266d57cf918594f407100d7c1607"
    hash          = "9b325e3006a36e5d20cdf7cb7a4b1eec"
    hash          = "c2520431d6d945f168b91afd6e9d775a"
    hash          = "f23e30762b07cc49e92a3c09b75ac9f2"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.3"
    date          = "2015-12-25"
    last_modified = "2015-12-25"

strings:

    $a1 = "gtSvc.dll" fullword ascii
    $a2 = "cacls.exe c:\\windows\\temp /e /g everyone:f" fullword ascii
    $a3 = "%s%scftmon.exe" fullword ascii
    $a4 = "Common Files\\Firefox\\iadacf.exe"
    $a5 = "%s\\winini.exe" fullword ascii
    $a6 = "%s&%s&YES" fullword ascii
    $a8 = "bloomek.eudiplomats.com"
    $a9 = "/lo%s?to%sn=%S"
    $a10 = "duckyard.suptvshow.com"
    $b1 = "GetLastActivePopup"
    $b2 = "WarnOnPostRedirect"
    $b3 = "WarnonZoneCrossing"
    $b4 = "ShownVerifyBalloon"
    $b5 = "Check_Associations"

condition:

    uint16(0) == 0x5A4D  
    and (any of ($a*) or all of ($b*))
    and filesize < 400000
}



rule apt_DiplomaticDuck_2: VixenPanda
{
meta:

    report        = "DiplomaticDuck - Chinese APT activity targeting high profile victims"
    description   = "Rule to detect DiplomaticDuck APT samples"
    hash          = "28cfca519d8de5438065ebda4f6182a3"
    hash          = "6d88c0cbb8db653537e9f1edf85d0b61"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2015-12-29"
    last_modified = "2015-12-29"

strings:

    $http = "http://%s" ascii
    $a2 = "IEXPLORE.EXE" fullword ascii
    $a3 = "%s\\cmd.exe" fullword ascii
    $a4 = "GetLastActivePopup"
    $a5 = "SleepEx" fullword ascii
    $a6 = "CryptDestroyKey" fullword ascii
    $a8 = "ShellExecuteA" fullword ascii
    $a9 = "PathFileExistsA" fullword ascii

condition:

    uint16(0) == 0x5A4D
    and (#http == 5 and all of ($a*))
    and filesize < 400000
}



rule apt_DiplomaticDuck_dropper1: VixenPanda
{
meta:

    report        = "DiplomaticDuck - Chinese APT activity targeting high profile victims"
    description   = "Rule to detect DiplomaticDuck dropper"
    hash          = "9823b21abbaeaea9aa986ebf2ffa6dca"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2016-08-01"
    last_modified = "2016-08-01"

strings:

    $a1 = "%temp%\\Low\\nv.exe %temp%\\Low\\mm.exe" fullword ascii
    $a2 = "mkdir %temp%\\Low" fullword ascii
    $a3 = "command.com"

condition:

    uint16(0) == 0x5A4D
    and (all of ($a*))
}



rule apt_DiplomaticDuck_dropper2: VixenPanda
{
meta:

    report        = "DiplomaticDuck - Chinese APT activity targeting high profile victims"
    description   = "Rule to detect DiplomaticDuck WinRar dropper"
    hash          = "d59b808d637112a514cca45d02aa53e4"
    hash          = "31376fff617e6d4805d344d5cd917a34"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2016-08-01"
    last_modified = "2016-08-01"

strings:

    $a1 = "word.exe" fullword ascii
    $a2 = "note.doc" fullword ascii
    $a3 = "paxa.doc" fullword ascii
    $a4 = "winrarsfxmappingfile.tmp" wide
    $a5 = "__tmp_rar_sfx_access_check_%u" wide

condition:

    uint16(0) == 0x5A4D
    and $a1 and ($a2 or $a3) and $a4 and $a5
}



rule apt_Bewymids_backdoor: VixenPanda
{
meta:

    report        = "DiplomaticDuck - Chinese APT activity targeting high profile victims"
    description   = "Rule to detect Bewymids backdoor related to Ke3chang and possibly related to DiplomaticDuck APT"
    hash          = "52f557953c7dba2eee513f0d0cc909a3"
    hash          = "98c6e985266f4258c79727449964c25b"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.1"
    date          = "2016-05-31"
    last_modified = "2016-05-31"

strings:

    $b1 = "%s\\cmdnew.exe"
    $b2 = "%s\\wuauclt.exe"
    $b3 = "%s\\cmd.exe"
    $b4 = "%s\\wuacult.txt"
    $b5 = "dd1=%s&dd2=%s"
    $b6 = "CLSID\\{0002DF01-0000-0000-C000-000000000046}\\LocalServer32\\"
    $b7 = "SOFTWARE\\Clients\\StartMenuInternet\\IEXPLORE.EXE\\shell\\open\\command\\"

condition:

    uint16(0) == 0x5A4D  
    and all of ($b*)
    and filesize < 400000
}



rule apt_DiplomaticDuck_keylogger_dropper: VixenPanda
{
meta:

    report        = "DiplomaticDuck - Chinese APT activity targeting high profile victims"
    description   = "Rule to detect a dropper that drops a keylogger related to DiplomaticDuck APT"
    hash          = "f4d6502ec59dd95767fe87daa03f5426"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2016-08-01"
    last_modified = "2016-08-01"

strings:

    $a1 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2luZG93cw=="
    $a2 = "bnRzaHJ1aS5kbGw="
    $a3 = "EncdDecd"
    $a4 = "SOFTWARE\\Borland\\Delphi\\RTL"

condition:

    uint16(0) == 0x5A4D  
    and (all of ($a*))

}



rule apt_DiplomaticDuck_keylogger: VixenPanda
{
meta:

    report        = "DiplomaticDuck - Chinese APT activity targeting high profile victims"
    description   = "Rule to detect a keylogger related to DiplomaticDuck APT"
    hash          = "35a436b8274bbd6f52eb24d0f6f02807"
    hash          = "5c1a18f0156a8dddf8fa245a9517f2fd"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2016-08-01"
    last_modified = "2016-08-01"

strings:

    $a1 = "pstorec.dll"
    $a2 = "newtopic.php"
    $a3 = "pk.tmp"
    $a4 = "The Active Windows Title"
    $a5 = "www.google.de"
    $a6 = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    $a7 = "File  download stop"
    $a8 = "SmartView"

condition:

    uint16(0) == 0x5A4D  
    and (all of ($a*))

}



