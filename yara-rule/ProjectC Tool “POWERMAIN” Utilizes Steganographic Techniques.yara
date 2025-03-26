rule apt_ProjectC_PNG_Loader
{
meta:
    report        = "ProjectC Tool “POWERMAIN” Utilizes Steganographic Techniques"
    description = "ProjectC Steganography Loader"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date = "2020-03-25"
    last_modified = "2020-03-18"

strings:
    	$a1 = "Jsprofile" nocase ascii wide
    	$a2 = "Setfilter" nocase ascii wide
    	$a3 = "DecodePng" nocase ascii wide
    	$b1 = "pngpcd" nocase ascii wide
    	$b2 = "PngCoder" nocase ascii wide
   	 
condition:
    	uint16(0) == 0x5A4D and filesize >= 60KB and filesize <= 150KB and (all of ($a*) or all of ($b*))  	 
}

rule apt_ProjectC_UAC_Dll
{
meta:
    report        = "ProjectC Tool “POWERMAIN” Utilizes Steganographic Techniques"
    description = "ProjectC Sideloaded DLL"
    author        = "afta Lab"
    copyright     = "afta Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date = "2020-03-25"
    last_modified = "2020-03-18"

strings:       	 
    	$a1 = "Setfilter" nocase ascii wide
    	$a2 = "Proj_C.dll" nocase ascii wide
    	$a3 = "C:\\Program Files\\Internet Explorer\\Jsprofile.dll" nocase ascii wide
   	 
	condition:
    	uint16(0) == 0x5A4D and filesize >= 30KB and filesize <= 70KB and (all of ($a*))
 }
