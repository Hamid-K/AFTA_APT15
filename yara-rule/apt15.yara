/*
   YARA Rule Set
   Author: csirt
   Date: 2024-11-27
   Identifier: dll
   Reference: afta.gov.ir
*/

/* Rule Set ----------------------------------------------------------------- */

rule dll_2 {
   meta:
      description = "dll - file 2.dll"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "0c9348b2cddc55f24d6b2124177ab8e6a06309022ae8f791e7a0f8fb52f5d9ab"
   strings:
      $s1 = "ReG aDd %s%S\\pARamEteRs /v ServiceDll /t REG_EXPAND_SZ /d \"%S\" /f" fullword wide
      $s2 = "ReG dELete %s%S\\pARamEteRs /v ServiceDllUnloadOnStop /f" fullword wide
      $s3 = "task.exe" fullword wide
      $s4 = "en-US\\cmd.exe.mui" fullword wide
      $s5 = "ths.dll" fullword ascii
      $s6 = "ReG aDd %s%S /v Start /t REG_DWORD /d 2 /f" fullword wide
      $s7 = "ReG aDd %s%S /v ImagePath /t REG_EXPAND_SZ /d \"%S\" /f" fullword wide
      $s8 = "tmp.bat" fullword wide
      $s9 = "\\task.exe" fullword wide
      $s10 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s11 = "en-US\\task.exe.mui" fullword wide
      $s12 = " Type Descriptor'" fullword ascii
      $s13 = "update.mainvt.org" fullword ascii
      $s14 = "net start " fullword ascii
      $s15 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s16 = " %s:%u" fullword ascii
      $s17 = " %s:%s@%s:%u" fullword ascii
      $s18 = " Base Class Descriptor at (" fullword ascii
      $s19 = " Class Hierarchy Descriptor'" fullword ascii
      $s20 = "hKEy_LOcAl_MaChiNE\\SYsTEm\\CuRRenTCoNTRolSeT\\SeRViCeS\\" fullword wide

      $op0 = { 0f b7 84 0d 68 f8 ff ff 66 89 84 0d 34 fb ff ff }
      $op1 = { ff 15 08 30 01 10 ff b5 44 f8 ff ff ff 15 10 30 }
      $op2 = { be 80 b4 01 10 8d bd 34 fd ff ff f3 a5 50 68 36 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule tapisrvs {
   meta:
      description = "dll - file tapisrvs.dll"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "f63750ac7fa6516961a2c8145dbfe20c244d2154488a94680f71d3f6a593e00c"
   strings:
      $x1 = "C:\\Users\\develop\\Desktop\\myfault\\service-dll - x86\\Release\\service-dll.pdb" fullword ascii
      $s2 = "service.dll" fullword wide
      $s3 = "service-dll.dll" fullword ascii
      $s4 = "server.dll" fullword ascii
      $s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.2792.7" wide
      $s7 = "service-dll" fullword wide
      $s8 = "https://185.14.45.191:8443/DAD4Whs7qfxDeUJ4JGZ13wJeBODE0GEXTAxihnIMzl70hXodB1GziSbv0nLaDHUVn_kinOncHEK5h7Q93XMsWQOXg_gacYjzHlZsq" wide
      $s9 = " Type Descriptor'" fullword ascii
      $s10 = "operator co_await" fullword ascii
      $s11 = "operator<=>" fullword ascii
      $s12 = "cDllMain" fullword wide
      $s13 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s14 = "9.:>:W:\\:a:f:" fullword ascii
      $s15 = "Microsoft@Company" fullword wide
      $s16 = " Base Class Descriptor at (" fullword ascii
      $s17 = " Class Hierarchy Descriptor'" fullword ascii
      $s18 = " inflate 1.0.4 Copyright 1995-1996 Mark Adler " fullword ascii
      $s19 = " deflate 1.0.4 Copyright 1995-1996 Jean-loup Gailly " fullword ascii
      $s20 = "need more for packet flush" fullword ascii

      $op0 = { 81 f9 5b 99 0a 89 89 e8 0f 84 7a ff ff ff 81 f9 }
      $op1 = { 32 db 88 5d e7 c7 45 fc fe ff ff ff e8 3d }
      $op2 = { 53 57 ff 75 08 e8 29 ff ff ff 8b f0 89 75 e4 85 }
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule dll_winsat {
   meta:
      description = "dll - file winsat.exe"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "261e36a0d9cfe897d3f5dcecf77e7e87d099b2b98dd9f5de945e24d959181b52"
   strings:
      $s1 = "task.exe" fullword wide
      $s2 = "en-US\\cmd.exe.mui" fullword wide
      $s3 = "@Security.dll" fullword wide
      $s4 = "\\task.exe" fullword wide
      $s5 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s6 = "en-US\\task.exe.mui" fullword wide
      $s7 = " Type Descriptor'" fullword ascii
      $s8 = "update.mainvt.org" fullword ascii
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s10 = " %s:%u" fullword ascii
      $s11 = " %s:%s@%s:%u" fullword ascii
      $s12 = " Base Class Descriptor at (" fullword ascii
      $s13 = " Class Hierarchy Descriptor'" fullword ascii
      $s14 = " Complete Object Locator'" fullword ascii
      $s15 = "Microsoft Unified Security Protocol Provider" fullword ascii /* Goodware String - occured 63 times */
      $s16 = " delete[]" fullword ascii
      $s17 = ".?AVCProtocolClient@@" fullword ascii
      $s18 = "?:?V?s?" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "  </trustInfo>" fullword ascii
      $s20 = "6%7S7y7" fullword ascii /* Goodware String - occured 1 times */

      $op0 = { 0f b7 84 0d 68 f8 ff ff 66 89 84 0d 34 fb ff ff }
      $op1 = { cc cc 55 8b ec 56 8b f1 e8 55 ff ff ff f6 45 08 }
      $op2 = { 5e c3 cc cc 56 8b f1 e8 68 ff ff ff 85 c0 74 41 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule appmgmts {
   meta:
      description = "dll - file appmgmts.dll"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "c729f1608239f51167a925993b516358d2da6ee545669a0427fa15bf6dca9d21"
   strings:
      $x1 = "C:\\Users\\develop\\Desktop\\myfault\\service-dll-x64\\x64\\Release\\service-dll.pdb" fullword ascii
      $s2 = "service.dll" fullword wide
      $s3 = "service-dll.dll" fullword ascii
      $s4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s5 = "5d7e6e25735e" ascii /* hex encoded string ']~n%s^' */
      $s6 = "262730576b36" ascii /* hex encoded string '&'0Wk6' */
      $s7 = "7163223c5772" ascii /* hex encoded string 'qc"<Wr' */
      $s8 = "262f24403772" ascii /* hex encoded string '&/$@7r' */
      $s9 = "523030576b36" ascii /* hex encoded string 'R00Wk6' */
      $s10 = "556323385773" ascii /* hex encoded string 'Uc#8Ws' */
      $s11 = "5263235d2f53" ascii /* hex encoded string 'Rc#]/S' */
      $s12 = "44526355583a" ascii /* hex encoded string 'DRcUX:' */
      $s13 = "7d63223c5772" ascii /* hex encoded string '}c"<Wr' */
      $s14 = "262b24405f21" ascii /* hex encoded string '&+$@_!' */
      $s15 = "service-dll" fullword wide
      $s16 = "Micorosoft@Windows@Operating System" fullword wide
      $s17 = "2e21cb1d5b3d" ascii /* base64 encoded string '{m\oWyow' */
      $s18 = " Type Descriptor'" fullword ascii
      $s19 = "operator co_await" fullword ascii
      $s20 = "operator<=>" fullword ascii

      $op0 = { 48 8b 0d 34 79 09 00 ff 15 2e ce 07 00 b8 99 0a }
      $op1 = { e8 56 ff ff ff 48 83 c4 28 c3 cc 48 89 4c 24 08 }
      $op2 = { 4c 8b c6 8b d7 49 8b ce e8 3c ff ff ff 8b d8 89 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule dll_appmgmt {
   meta:
      description = "dll - file appmgmt.dll"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "7e1b14a436d077b8f2a1ae907098d53566dbbd00cbd6f8f95c2fb8bfe9655fdb"
   strings:
      $x1 = "ImageList_ReplaceIconInscriptional_PahlaviLoadIconWithScaleDownLookupPrivilegeValueWMagadan Standard TimeMorocco Standard TimeMy" ascii
      $x2 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii
      $x3 = "28421709430404007434844970703125: day-of-year does not match dayCertAddCertificateContextToStoreCertVerifyCertificateChainPolicy" ascii
      $x4 = "(unknown), newval=, oldval=, size = , tail = 2001::/322002::/162441406253ffe::/16: status=AuthorityBassa_VahBhaiksukiClassINETCr" ascii
      $x5 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x6 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii
      $x7 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x8 = "127.0.0.1:53152587890625762939453125Bidi_ControlCIDR addressCMDWindow*_*CfgMgr32.dllChooseColorWCircleMinus;CircleTimes;CoCreate" ascii
      $x9 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepatternTransformpatterntransformreflect mismatchremote I/O error" ascii
      $x10 = "entersyscalleqslantless;exit status expectation;feMorphologyfePointLightfeTurbulencefemorphologyfepointlightfeturbulencegcBitsAr" ascii
      $x11 = "heapBitsSetTypeGCProg: small allocationmath/big: buffer too small to fit valuemismatched count during itab table copymspan.sweep" ascii
      $x12 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnabletRNS, color " ascii
      $x13 = ", elemsize=, npages = .WithCancel/dev/stderr/dev/stdout30517578125: frame.sp=BLAKE2b-256BLAKE2b-384BLAKE2b-512BLAKE2s-256Bernoul" ascii
      $x14 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii
      $x15 = "value=aacute;aarch64abl1943abortedabreve;addressagrave;akuapemalalc97andand;angmsd;angsph;answersapacir;approx;arevelaarevmdaark" ascii
      $x16 = " to unallocated span37252902984619140625AddFontMemResourceExArabic Standard TimeAzores Standard TimeBad chunk length: %dCertFind" ascii
      $x17 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x18 = "structure needs cleaningtext/html; charset=utf-8unpacking Question.Classupdate during transitionwmi: invalid entity typex509: ma" ascii
      $x19 = "flate: internal error: garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid Print" ascii
      $x20 = " to non-Go memory , locked to thread298023223876953125: day out of rangeAddFontResourceExWArab Standard TimeCM_MapCrToWin32ErrCa" ascii

      $op0 = { e9 55 ff ff ff 66 0f 1f 44 00 00 31 c0 48 87 03 }
      $op1 = { e9 28 ff ff ff 66 90 b9 1f }
      $op2 = { e8 1e 62 24 00 e9 0c ff ff ff 90 41 54 55 57 56 }
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule MDEvents {
   meta:
      description = "dll - file MDEvents.exe"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "467e53a25476c5e2c55d78dbcf23fa2095a990827ec1b964ceb9b54cfd16f077"
   strings:
      $s1 = "Error retrieving item from io_service queue: GetQueuedCompletionStatus" fullword ascii
      $s2 = "Connect operation failed: ConnectEx" fullword ascii
      $s3 = "\\\\?\\pipe\\Win32Pipes.%08x.%08x" fullword wide
      $s4 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s5 = "Error creating socket: CreateIoCompletionPort" fullword ascii
      $s6 = "not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugs/):" fullword ascii
      $s7 = "template parameter object for " fullword ascii
      $s8 = "Error creating io_service: CreateIoCompletionPort" fullword ascii
      $s9 = "e\\\\?\\pipe\\Win32Pipes.%08x.%08x" fullword wide
      $s10 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii
      $s11 = "Disconnect operation failed: DisconnectEx" fullword ascii
      $s12 = "Socket accept operation failed: setsockopt(SO_UPDATE_ACCEPT_CONTEXT)" fullword ascii
      $s13 = "error getting file size: GetFileSizeEx" fullword ascii
      $s14 = "Error configuring socket: setsockopt(SO_RCVTIMEO)" fullword ascii
      $s15 = "Failed to start listening on bound endpoint: listen" fullword ascii
      $s16 = "Error binding to endpoint: bind()" fullword ascii
      $s17 = "random_device::random_device(const std::string&): unsupported token" fullword ascii
      $s18 = "Error configuring socket: setsockopt(SO_SNDTIMEO)" fullword ascii
      $s19 = "Accepting a connection failed: AcceptEx" fullword ascii
      $s20 = "  VirtualProtect failed with code 0x%x" fullword ascii

      $op0 = { 31 c0 85 d2 0f 95 c0 e9 79 ff ff ff 8d 76 00 c7 }
      $op1 = { 83 79 74 0e 0f 86 54 ff ff ff 8b 89 e8 }
      $op2 = { 31 c0 85 c9 0f 95 c0 e9 42 ff ff ff 8d b4 26 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( 8 of them and all of ($op*) )
}

rule dll_update {
   meta:
      description = "dll - file update.exe"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "a499da56ff3c8319d0c81c4ca7ac6caf1c07c80cb66f794f464d1a7ae756d288"
   strings:
      $x1 = "ImageList_ReplaceIconInscriptional_PahlaviLoadIconWithScaleDownLookupPrivilegeValueWMagadan Standard TimeMorocco Standard TimeMy" ascii
      $x2 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii
      $x3 = "28421709430404007434844970703125: day-of-year does not match dayCertAddCertificateContextToStoreCertVerifyCertificateChainPolicy" ascii
      $x4 = "(unknown), newval=, oldval=, size = , tail = 2001::/322002::/162441406253ffe::/16: status=AuthorityBassa_VahBhaiksukiClassINETCr" ascii
      $x5 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x6 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii
      $x7 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x8 = "127.0.0.1:53152587890625762939453125Bidi_ControlCIDR addressCMDWindow*_*CfgMgr32.dllChooseColorWCircleMinus;CircleTimes;CoCreate" ascii
      $x9 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepatternTransformpatterntransformreflect mismatchremote I/O error" ascii
      $x10 = "entersyscalleqslantless;exit status expectation;feMorphologyfePointLightfeTurbulencefemorphologyfepointlightfeturbulencegcBitsAr" ascii
      $x11 = "heapBitsSetTypeGCProg: small allocationmath/big: buffer too small to fit valuemismatched count during itab table copymspan.sweep" ascii
      $x12 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnabletRNS, color " ascii
      $x13 = ", elemsize=, npages = .WithCancel/dev/stderr/dev/stdout30517578125: frame.sp=BLAKE2b-256BLAKE2b-384BLAKE2b-512BLAKE2s-256Bernoul" ascii
      $x14 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii
      $x15 = "value=aacute;aarch64abl1943abortedabreve;addressagrave;akuapemalalc97andand;angmsd;angsph;answersapacir;approx;arevelaarevmdaark" ascii
      $x16 = " to unallocated span37252902984619140625AddFontMemResourceExArabic Standard TimeAzores Standard TimeBad chunk length: %dCertFind" ascii
      $x17 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x18 = "structure needs cleaningtext/html; charset=utf-8unpacking Question.Classupdate during transitionwmi: invalid entity typex509: ma" ascii
      $x19 = "flate: internal error: garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid Print" ascii
      $x20 = " to non-Go memory , locked to thread298023223876953125: day out of rangeAddFontResourceExWArab Standard TimeCM_MapCrToWin32ErrCa" ascii

      $op0 = { 48 39 d9 0f 8d fd fc ff ff 0f b6 34 08 40 80 fe }
      $op1 = { e8 48 02 00 00 45 0f 57 ff 65 4c 8b 34 25 28 }
      $op2 = { e8 ea 01 00 00 45 0f 57 ff 65 4c 8b 34 25 28 }
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule wmpencode {
   meta:
      description = "dll - file wmpencode.exe"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "54891d2164847bb1ffb9404790474d248843c14472e3b18fa1b82e7961ebb301"
   strings:
      $x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertFindChainInStoreCertOpenSystemStoreWChangeSe" ascii
      $x2 = "; asn1: invalid UTF-8 stringauth-agent-req@openssh.combad certificate hash valuebase 128 integer too largebinary.Read: invalid t" ascii
      $x3 = "slice bounds out of range [:%x] with length %yssh: unmarshal error for field %s of type %s%sstopTheWorld: not stopped (status !=" ascii
      $x4 = "; DNSSEC ALGORITHM UNDERSTOOD: bad input point: low order pointbufio: invalid use of UnreadBytebufio: invalid use of UnreadRuneb" ascii
      $x5 = "ssh: only P-256, P-384 and P-521 EC keys are supportedssh: unexpected packet in response to channel open: %Ttls: certificate use" ascii
      $x6 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x7 = "heapBitsSetTypeGCProg: small allocationmath/big: buffer too small to fit valuemismatched count during itab table copymspan.sweep" ascii
      $x8 = "entersyscallexit status gcBitsArenasgcpacertracegetaddrinfowharddecommithmac-sha1-96hmac-sha256.host is downillegal seekinvalid " ascii
      $x9 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Failed to create PTY output pipe: %vGo pointer stored in" ascii
      $x10 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolarray of non-uint8 in field %d: %Tbad scalar length: %d, exp" ascii
      $x11 = "mallocgc called with gcphase == _GCmarkterminationrecursive call during initialization - linker skewruntime: unable to acquire -" ascii
      $x12 = " to non-Go memory , locked to thread298023223876953125: day out of rangeArab Standard TimeCM_MapCrToWin32ErrCaucasian_AlbanianCe" ascii
      $x13 = "127.0.0.1:%d127.0.0.1:53152587890625762939453125Bidi_ControlCIDR addressCached ErrorCfgMgr32.dllCoCreateGuidCreateEventWCreateMu" ascii
      $x14 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5v" ascii
      $x15 = "garbage collection scangcDrain phase incorrectglobalRequestFailureMsgglobalRequestSuccessMsgindex out of range [%x]interrupted s" ascii
      $x16 = "reflect: reflect.Value.UnsafePointer on an invalid notinheap pointertls: handshake message of length %d bytes exceeds maximum of" ascii
      $x17 = "; NSID: atomicor8bad indirbad prunebad rcodebad rdatabus errorchan sendcomplex64connectexcopystackctxt != 0d.nx != 0debugLockdns" ascii
      $x18 = "structure needs cleaningunknown channel type: %vunpacking Question.Classunsupported channel typeupdate during transitionx509: ma" ascii
      $x19 = "unixpacketunknown pcuser32.dllws2_32.dll  of size   (targetpc= , plugin:  ---pty cmd KiB work,  exp.) for  freeindex= gcwaiting=" ascii
      $x20 = "GOMAXPROCSGOMEMLIMITGetIfEntryGetVersionGlagoliticIP addressIsValidSidKharoshthiLocalAllocLockFileExManichaeanNSEC3PARAMOPENPGPK" ascii

      $op0 = { 48 39 d9 0f 8d fd fc ff ff 0f b6 34 08 40 80 fe }
      $op1 = { e8 48 02 00 00 45 0f 57 ff 65 4c 8b 34 25 28 }
      $op2 = { e8 ea 01 00 00 45 0f 57 ff 65 4c 8b 34 25 28 }
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule TSMSISrv {
   meta:
      description = "dll - file TSMSISrv.dll"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "c701e9d4d1c6782b5635ecb069f46119c959eb682f640e947bcb3d4dd17b362e"
   strings:
      $x1 = "C:\\Users\\develop\\Desktop\\myfault\\DLL-cs-delay-load\\test-wishper-x64-llvm-obsucator\\x64\\Release\\test-wishper.pdb" fullword ascii
      $s2 = "Component.dll" fullword wide
      $s3 = "0ntdll.dll" fullword wide
      $s4 = "test-wishper.dll" fullword ascii
      $s5 = "5d7e6e25735e" ascii /* hex encoded string ']~n%s^' */
      $s6 = "262730576b36" ascii /* hex encoded string '&'0Wk6' */
      $s7 = "7163223c5772" ascii /* hex encoded string 'qc"<Wr' */
      $s8 = "262f24403772" ascii /* hex encoded string '&/$@7r' */
      $s9 = "523030576b36" ascii /* hex encoded string 'R00Wk6' */
      $s10 = "556323385773" ascii /* hex encoded string 'Uc#8Ws' */
      $s11 = "5263235d2f53" ascii /* hex encoded string 'Rc#]/S' */
      $s12 = "44526355583a" ascii /* hex encoded string 'DRcUX:' */
      $s13 = "7d63223c5772" ascii /* hex encoded string '}c"<Wr' */
      $s14 = "262b24405f21" ascii /* hex encoded string '&+$@_!' */
      $s15 = "4ProcessH" fullword ascii
      $s16 = "2e21cb1d5b3d" ascii /* base64 encoded string '{m\oWyow' */
      $s17 = "remote\\2:Default" fullword ascii
      $s18 = "remote\\1" fullword ascii
      $s19 = "UAWAVAUATVWSH" fullword ascii
      $s20 = "adefdb023198" ascii

      $op0 = { 4c 8b c6 8b d7 49 8b ce e8 3c ff ff ff 8b d8 89 }
      $op1 = { e8 c4 ff ff ff 33 d2 48 8d 4d f0 41 b8 d0 04 00 }
      $op2 = { e8 bd 04 00 00 8a d8 88 44 24 40 40 b7 01 83 3d }
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule dll_msinfo {
   meta:
      description = "dll - file msinfo.exe"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "09844c85dc0586e900715660d64a55ed965ac26482152afd9489d29bfbcbcf40"
   strings:
      $s1 = "6user32.dll" fullword ascii
      $s2 = "L}iphlpapi.dll" fullword ascii
      $s3 = "* \"6K\"9[7" fullword ascii
      $s4 = "m:\\o)," fullword ascii
      $s5 = "cF:\\@,PK" fullword ascii
      $s6 = "@ZU:\"(" fullword ascii
      $s7 = "fQG.txZ'" fullword ascii
      $s8 = "'^ dlLf" fullword ascii
      $s9 = "cracked by ximo" fullword ascii
      $s10 = "\\=ePvb\"\"\\VrGq" fullword ascii
      $s11 = "hT -B:" fullword ascii
      $s12 = "9f\\a+ " fullword ascii
      $s13 = "VtkYcC6" fullword ascii
      $s14 = "y- !jQ" fullword ascii
      $s15 = "P- mG." fullword ascii
      $s16 = "lnqdfg" fullword ascii
      $s17 = "#RbHBiN" fullword ascii
      $s18 = "RpGFx1:-" fullword ascii
      $s19 = "MFpN42:Yc" fullword ascii
      $s20 = "jtQIumBhO-" fullword ascii

      $op0 = { ff 25 28 2a 53 00 60 c1 eb 0c f9 ff 34 24 81 fc }
      $op1 = { 53 74 72 53 74 72 49 41 00 47 37 d5 34 20 ef eb }
      $op2 = { 66 0f ba e6 0b 66 0f bb d6 8b 74 24 34 0f ba e1 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( 8 of them and all of ($op*) )
}

/* Super Rules ------------------------------------------------------------- */

rule _appmgmts_TSMSISrv_0 {
   meta:
      description = "dll - from files appmgmts.dll, TSMSISrv.dll"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "c729f1608239f51167a925993b516358d2da6ee545669a0427fa15bf6dca9d21"
      hash2 = "c701e9d4d1c6782b5635ecb069f46119c959eb682f640e947bcb3d4dd17b362e"
   strings:
      $s1 = "5d7e6e25735e" ascii /* hex encoded string ']~n%s^' */
      $s2 = "262730576b36" ascii /* hex encoded string '&'0Wk6' */
      $s3 = "7163223c5772" ascii /* hex encoded string 'qc"<Wr' */
      $s4 = "262f24403772" ascii /* hex encoded string '&/$@7r' */
      $s5 = "523030576b36" ascii /* hex encoded string 'R00Wk6' */
      $s6 = "556323385773" ascii /* hex encoded string 'Uc#8Ws' */
      $s7 = "5263235d2f53" ascii /* hex encoded string 'Rc#]/S' */
      $s8 = "44526355583a" ascii /* hex encoded string 'DRcUX:' */
      $s9 = "7d63223c5772" ascii /* hex encoded string '}c"<Wr' */
      $s10 = "262b24405f21" ascii /* hex encoded string '&+$@_!' */
      $s11 = "2e21cb1d5b3d" ascii /* base64 encoded string '{m\oWyow' */
      $s12 = "UAWAVAUATVWSH" fullword ascii
      $s13 = "adefdb023198" ascii
      $s14 = "adbcdb705885" ascii
      $s15 = "adcfdb345882" ascii
      $s16 = "bdadd8946226" ascii
      $s17 = "adaddb755892" ascii
      $s18 = "RetpolineV1" fullword ascii
      $s19 = "addadb265885" ascii
      $s20 = "adcddb195897" ascii

      $op0 = { 4c 8b c6 8b d7 49 8b ce e8 3c ff ff ff 8b d8 89 }
      $op1 = { e8 c4 ff ff ff 33 d2 48 8d 4d f0 41 b8 d0 04 00 }
      $op2 = { e8 bd 04 00 00 8a d8 88 44 24 40 40 b7 01 83 3d }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them ) and all of ($op*)
      ) or ( all of them )
}

rule _appmgmt_update_wmpencode_1 {
   meta:
      description = "dll - from files appmgmt.dll, update.exe, wmpencode.exe"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "7e1b14a436d077b8f2a1ae907098d53566dbbd00cbd6f8f95c2fb8bfe9655fdb"
      hash2 = "a499da56ff3c8319d0c81c4ca7ac6caf1c07c80cb66f794f464d1a7ae756d288"
      hash3 = "54891d2164847bb1ffb9404790474d248843c14472e3b18fa1b82e7961ebb301"
   strings:
      $s1 = "os.(*ProcessState).sys" fullword ascii
      $s2 = "os.(*ProcessState).Sys" fullword ascii
      $s3 = "os/exec.Command" fullword ascii
      $s4 = "3*struct { F uintptr; errc chan error; c *exec.Cmd }" fullword ascii
      $s5 = "os/exec.(*Cmd).closeDescriptors" fullword ascii
      $s6 = "runtime.getempty.func1" fullword ascii
      $s7 = "runtime.getempty" fullword ascii
      $s8 = "sync.runtime_SemacquireMutex" fullword ascii
      $s9 = "runtime.execute" fullword ascii
      $s10 = "runtime.tracebackHexdump" fullword ascii
      $s11 = "os.Executable" fullword ascii
      $s12 = "runtime.dumpgstatus" fullword ascii
      $s13 = "crypto/tls.(*rsaKeyAgreement).processServerKeyExchange" fullword ascii
      $s14 = "runtime.tracebackHexdump.func1" fullword ascii
      $s15 = "processClientKeyExchange" fullword ascii
      $s16 = "runtime.hexdumpWords" fullword ascii
      $s17 = "processServerKeyExchange" fullword ascii
      $s18 = "/*struct { F uintptr; pw *os.File; c *exec.Cmd }" fullword ascii
      $s19 = "crypto/tls.(*ecdheKeyAgreement).processServerKeyExchange" fullword ascii
      $s20 = "l32.dll" fullword ascii

      $op0 = { 48 39 d9 0f 8d fd fc ff ff 0f b6 34 08 40 80 fe }
      $op1 = { e8 48 02 00 00 45 0f 57 ff 65 4c 8b 34 25 28 }
      $op2 = { e8 ea 01 00 00 45 0f 57 ff 65 4c 8b 34 25 28 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them ) and all of ($op*)
      ) or ( all of them )
}

rule _appmgmt_update_2 {
   meta:
      description = "dll - from files appmgmt.dll, update.exe"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "7e1b14a436d077b8f2a1ae907098d53566dbbd00cbd6f8f95c2fb8bfe9655fdb"
      hash2 = "a499da56ff3c8319d0c81c4ca7ac6caf1c07c80cb66f794f464d1a7ae756d288"
   strings:
      $x1 = "ImageList_ReplaceIconInscriptional_PahlaviLoadIconWithScaleDownLookupPrivilegeValueWMagadan Standard TimeMorocco Standard TimeMy" ascii
      $x2 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii
      $x3 = "28421709430404007434844970703125: day-of-year does not match dayCertAddCertificateContextToStoreCertVerifyCertificateChainPolicy" ascii
      $x4 = "(unknown), newval=, oldval=, size = , tail = 2001::/322002::/162441406253ffe::/16: status=AuthorityBassa_VahBhaiksukiClassINETCr" ascii
      $x5 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x6 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii
      $x7 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x8 = "127.0.0.1:53152587890625762939453125Bidi_ControlCIDR addressCMDWindow*_*CfgMgr32.dllChooseColorWCircleMinus;CircleTimes;CoCreate" ascii
      $x9 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepatternTransformpatterntransformreflect mismatchremote I/O error" ascii
      $x10 = "entersyscalleqslantless;exit status expectation;feMorphologyfePointLightfeTurbulencefemorphologyfepointlightfeturbulencegcBitsAr" ascii
      $x11 = "heapBitsSetTypeGCProg: small allocationmath/big: buffer too small to fit valuemismatched count during itab table copymspan.sweep" ascii
      $x12 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnabletRNS, color " ascii
      $x13 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii
      $x14 = "value=aacute;aarch64abl1943abortedabreve;addressagrave;akuapemalalc97andand;angmsd;angsph;answersapacir;approx;arevelaarevmdaark" ascii
      $x15 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x16 = "structure needs cleaningtext/html; charset=utf-8unpacking Question.Classupdate during transitionwmi: invalid entity typex509: ma" ascii
      $x17 = "flate: internal error: garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid Print" ascii
      $x18 = " to non-Go memory , locked to thread298023223876953125: day out of rangeAddFontResourceExWArab Standard TimeCM_MapCrToWin32ErrCa" ascii
      $x19 = "reflect: reflect.Value.UnsafePointer on an invalid notinheap pointertls: handshake message of length %d bytes exceeds maximum of" ascii
      $x20 = "GOMAXPROCSGOMEMLIMITGetBkColorGetDlgItemGetIfEntryGetObjectWGetSubMenuGetVersionGlagoliticGlobalFreeGlobalLockHumpEqual;IP addre" ascii

      $op0 = { 48 39 d9 0f 8d fd fc ff ff 0f b6 34 08 40 80 fe }
      $op1 = { e8 48 02 00 00 45 0f 57 ff 65 4c 8b 34 25 28 }
      $op2 = { e8 ea 01 00 00 45 0f 57 ff 65 4c 8b 34 25 28 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and ( 1 of ($x*) ) and all of ($op*)
      ) or ( all of them )
}

rule _2_appmgmts_tapisrvs_winsat_3 {
   meta:
      description = "dll - from files 2.dll, appmgmts.dll, tapisrvs.dll, winsat.exe"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "0c9348b2cddc55f24d6b2124177ab8e6a06309022ae8f791e7a0f8fb52f5d9ab"
      hash2 = "c729f1608239f51167a925993b516358d2da6ee545669a0427fa15bf6dca9d21"
      hash3 = "f63750ac7fa6516961a2c8145dbfe20c244d2154488a94680f71d3f6a593e00c"
      hash4 = "261e36a0d9cfe897d3f5dcecf77e7e87d099b2b98dd9f5de945e24d959181b52"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = " Base Class Descriptor at (" fullword ascii
      $s3 = " Class Hierarchy Descriptor'" fullword ascii
      $s4 = " Complete Object Locator'" fullword ascii
      $s5 = " delete[]" fullword ascii
      $s6 = " delete" fullword ascii
      $s7 = " new[]" fullword ascii
      $s8 = " Base Class Array'" fullword ascii

      $op0 = { 0f b7 84 0d 68 f8 ff ff 66 89 84 0d 34 fb ff ff }
      $op1 = { cc cc 55 8b ec 56 8b f1 e8 55 ff ff ff f6 45 08 }
      $op2 = { 5e c3 cc cc 56 8b f1 e8 68 ff ff ff 85 c0 74 41 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them ) and all of ($op*)
      ) or ( all of them )
}

rule _2_winsat_4 {
   meta:
      description = "dll - from files 2.dll, winsat.exe"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "0c9348b2cddc55f24d6b2124177ab8e6a06309022ae8f791e7a0f8fb52f5d9ab"
      hash2 = "261e36a0d9cfe897d3f5dcecf77e7e87d099b2b98dd9f5de945e24d959181b52"
   strings:
      $s1 = "task.exe" fullword wide
      $s2 = "en-US\\cmd.exe.mui" fullword wide
      $s3 = "\\task.exe" fullword wide
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s5 = "en-US\\task.exe.mui" fullword wide
      $s6 = "update.mainvt.org" fullword ascii
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s8 = " %s:%u" fullword ascii
      $s9 = " %s:%s@%s:%u" fullword ascii
      $s10 = "Microsoft Unified Security Protocol Provider" fullword ascii /* Goodware String - occured 63 times */
      $s11 = ".?AVCProtocolClient@@" fullword ascii
      $s12 = "?:?V?s?" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "  </trustInfo>" fullword ascii
      $s14 = "6%7S7y7" fullword ascii /* Goodware String - occured 1 times */
      $s15 = ".?AVCCrypt@@" fullword ascii
      $s16 = ".?AVCNetwork@@" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "0\"080g0" fullword ascii /* Goodware String - occured 1 times */
      $s18 = ">B>d>x>" fullword ascii /* Goodware String - occured 2 times */
      $s19 = ".?AVCClient@@" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "      </requestedPrivileges>" fullword ascii

      $op0 = { 0f b7 84 0d 68 f8 ff ff 66 89 84 0d 34 fb ff ff }
      $op1 = { cc cc 55 8b ec 56 8b f1 e8 55 ff ff ff f6 45 08 }
      $op2 = { 5e c3 cc cc 56 8b f1 e8 68 ff ff ff 85 c0 74 41 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( 8 of them ) and all of ($op*)
      ) or ( all of them )
}

rule _appmgmts_tapisrvs_5 {
   meta:
      description = "dll - from files appmgmts.dll, tapisrvs.dll"
      author = "csirt"
      reference = "afta.gov.ir"
      date = "2024-11-27"
      hash1 = "c729f1608239f51167a925993b516358d2da6ee545669a0427fa15bf6dca9d21"
      hash2 = "f63750ac7fa6516961a2c8145dbfe20c244d2154488a94680f71d3f6a593e00c"
   strings:
      $s1 = "service.dll" fullword wide
      $s2 = "service-dll.dll" fullword ascii
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "service-dll" fullword wide
      $s5 = "operator co_await" fullword ascii
      $s6 = "operator<=>" fullword ascii
      $s7 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s8 = "__swift_3" fullword ascii
      $s9 = "__swift_2" fullword ascii
      $s10 = "__swift_1" fullword ascii
      $s11 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s12 = "ext-ms-" fullword wide
      $s13 = "api-ms-" fullword wide

      $op0 = { 81 f9 5b 99 0a 89 89 e8 0f 84 7a ff ff ff 81 f9 }
      $op1 = { 32 db 88 5d e7 c7 45 fc fe ff ff ff e8 3d }
      $op2 = { 53 57 ff 75 08 e8 29 ff ff ff 8b f0 89 75 e4 85 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them ) and all of ($op*)
      ) or ( all of them )
}

