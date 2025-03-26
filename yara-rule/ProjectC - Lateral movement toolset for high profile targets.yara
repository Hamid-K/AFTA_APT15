rule APT_ProjC_PowerShell: FakingDragon CloudComputating
{
meta:

    report        = "ProjectC - Lateral movement toolset for high profile targets"
    description   = "Rule to detect ProjC PowerShell starter and injector"
    hash          = "939648AC4C2A7A21246490C9C4CE30E6"
    hash          = "A31A7E9FCF79B54608AFABC343B1C834"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.3"
    date          = "2017-01-27"
    last_modified = "2017-01-27"

strings:

    // encoded Powershell starter beginning, custom
    $enc1 = "JABFAG4AYwBvAGQAZQBkAFAAY"
    // WMI class to store injector (mentioned in starter)
    $dec1 = "root\\cimv2:Win32_DiskDriveSetting"
    // common payload starter
    $dec2 = "FromBase64String($EncodedPayload)"
    // WMI class to store binary payload (mentioned in injector)
    $dec3 = "root\\cimv2:Win32_DCOMApplicationInfo"

condition:

    any of them
}



rule APT_ProjC_PE: FakingDragon CloudComputating
{
meta:

    report        = "ProjectC - Lateral movement toolset for high profile targets"
    description   = "Rule to detect ProjC PE files"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.1"
    date          = "2017-01-27"
    last_modified = "2017-01-27"

strings:

    // .pdb path part for all samples
    $path1 = "C:\\Work\\Git\\FUN\\Proj" ascii
    // original files names
    $path2 = "Proj_S.dll" ascii
    $path3 = "Proj_C.dll" ascii
    $path4 = "Proj_Notepad" ascii
    // "not"-encoded proj_c name netplwizer.dll in proj_s
    $enc_s = { 91 9A 8B 8F 93 88 96 85 9A 8D D1 9B 93 93 }
    // "not"-encoded proj_s name nettmag.dll just in case
    $enc_c = { 91 9A 8B 8B 92 9E 98 D1 9B 93 93 }
    
    // "not"-encoded netsh firewall command
    $enc_cmd = { 91 9A 8B 8C 97 DF 99 96 8D 9A 88 9E 93 93 DF 8C 9A 8B DF 96 9C 92 8F 8C 9A 8B 8B 96 }
    // log codes
    $a1 = "FSBIBS"
    $a2 = "FSBIBR"
    $a3 = "IBS"
    $a4 = "FSBIBRRE"
    $a5 = "FSBERR"
    $a6 = "FCBIPER"
    $a7 = "FGIPER"
    // other not so uniq strings
    $str1 = "File Not Existing" ascii
    $str2 = "VMware Tools" ascii

condition:

    filesize < 5MB and
    uint16(0) == 0x5A4D and
    ((3 of ($a*))
    or any of ($path*)
    or $enc_s or $enc_c or $enc_cmd
    or all of ($str*))
}



