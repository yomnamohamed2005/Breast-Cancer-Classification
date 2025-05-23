@{
    GUID = 'A51E6D9E-BC14-41A7-98A8-888195641250'
    Author="Microsoft Corporation"
    CompanyName="Microsoft Corporation"
    Copyright="Copyright (C) Microsoft Corporation. All rights reserved."
    ModuleVersion = '1.0'
    NestedModules = @('MSFT_MpPerformanceRecording.psm1')

    FormatsToProcess = @('MSFT_MpPerformanceReport.Format.ps1xml')

    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @( 'New-MpPerformanceRecording',
                           'Get-MpPerformanceReport'
                           )
    HelpInfoUri="https://aka.ms/winsvr-2022-pshelp"
    PowerShellVersion = '5.1'
}

# SIG # Begin signature block
# MIImAgYJKoZIhvcNAQcCoIIl8zCCJe8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALMtnQG5KhaVi8
# /j7ONkfb/EMugE0iBrx7n8hqD9uLdaCCC1MwggTgMIIDyKADAgECAhMzAAAKdX3r
# GbkiXfErAAAAAAp1MA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIzMDIxNjE5MDA0NloXDTI0MDEzMTE5MDA0NlowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCm8WsyPSBF
# EhzxVlIBXzf7oJ80Ie8UY2fgPE40Efe97fn7mMo3Pyr4zWv4B3mG5tfMta6fULwC
# 4FuNpgEHBntPXOpyCHpJXYIggff2YOllKtdP4jPi0kueDvim/+uhBVHVvQTJfuG1
# HhG6tAQ9Ts2+QtrMMUyvLuRT1Mt6dANp9XJ2dlshPAR0IMyvVr/B5UxrvsBBjGd9
# nwVJdGaMOEcX4GY1JS0WV+md+vKTeZBh+kAl8Vc21p2FkTqmgqlBSALAhZvWgisa
# RSRIQc330EKeTuqM8Isrpn+5sQ8khBzAaimOFtYu1DvnY0q2ZvCCcIcr3T39uyq1
# 4N88zal30wCtAgMBAAGjggFoMIIBZDAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUviUXPislHupG6qw+6BLkdAIZjgowRQYDVR0RBD4w
# PKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMN
# MjMwMDI4KzUwMDE4OTAfBgNVHSMEGDAWgBTRT6mKBwjO9CQYmOUA//PWeR03vDBT
# BgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNXaW5QQ0FfMjAxMC0wNy0wNi5jcmwwVwYIKwYBBQUHAQEE
# SzBJMEcGCCsGAQUFBzAChjtodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4IBAQBX8cmfh/BkgIZ0YrvNBGc0eniJX+zamIxh08ELJtiKcmhA
# jiBOq6AU7PAT9bZq+zYSoyIkSV4K3YpYy6T4qZ755rbjPuh87Yjb/boFg5BL3SDH
# 0KQ/6Su2khM2T+HicYWro0JsiPGwPv/GFOMRGvQN0tf2IiYV+BedAM2TmNF2f6LS
# jX24PO6O81VcqJD13Qj0UlGG6OezTI/P9lxupc2MVxTullLlGXwjN2cP2rgGKZiE
# qQrCiO6/Y7hqEdNvhKrs9NnDo9PGbDWUMN4DwKGwJZFRySG+KogcZkk7ozOvM6p9
# +TLQS+3TmlFJlmRHtf7Fjma2sWc3mhyz17drnj05MIIGazCCBFOgAwIBAgIKYQxq
# GQAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzA2MjA0MDIzWhcNMjUwNzA2MjA1MDIz
# WjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMwIQYDVQQD
# ExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMB5uzqx8A+EuK1kKnUWc9C7B/Y+DZ0U5LGfwciUsDh8H9Az
# VfW6I2b1LihIU8cWg7r1Uax+rOAmfw90/FmV3MnGovdScFosHZSrGb+vlX2vZqFv
# m2JubUu8LzVs3qRqY1pf+/MNTWHMCn4x62wK0E2XD/1/OEbmisdzaXZVaZZM5Njw
# NOu6sR/OKX7ET50TFasTG3JYYlZsioGjZHeYRmUpnYMUpUwIoIPXIx/zX99vLM/a
# FtgOcgQo2Gs++BOxfKIXeU9+3DrknXAna7/b/B7HB9jAvguTHijgc23SVOkoTL9r
# XZ//XTMSN5UlYTRqQst8nTq7iFnho0JtOlBbSNECAwEAAaOCAeMwggHfMBAGCSsG
# AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTRT6mKBwjO9CQYmOUA//PWeR03vDAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBnQYDVR0gBIGVMIGSMIGPBgkrBgEE
# AYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9Q
# S0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcA
# YQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZI
# hvcNAQELBQADggIBAC5Bpoa1Bm/wgIX6O8oX6cn65DnClHDDZJTD2FamkI7+5Jr0
# bfVvjlONWqjzrttGbL5/HVRWGzwdccRRFVR+v+6llUIz/Q2QJCTj+dyWyvy4rL/0
# wjlWuLvtc7MX3X6GUCOLViTKu6YdmocvJ4XnobYKnA0bjPMAYkG6SHSHgv1QyfSH
# KcMDqivfGil56BIkmobt0C7TQIH1B18zBlRdQLX3sWL9TUj3bkFHUhy7G8JXOqiZ
# VpPUxt4mqGB1hrvsYqbwHQRF3z6nhNFbRCNjJTZ3b65b3CLVFCNqQX/QQqbb7yV7
# BOPSljdiBq/4Gw+Oszmau4n1NQblpFvDjJ43X1PRozf9pE/oGw5rduS4j7DC6v11
# 9yxBt5yj4R4F/peSy39ZA22oTo1OgBfU1XL2VuRIn6MjugagwI7RiE+TIPJwX9hr
# cqMgSfx3DF3Fx+ECDzhCEA7bAq6aNx1QgCkepKfZxpolVf1Ayq1kEOgx+RJUeRry
# DtjWqx4z/gLnJm1hSY/xJcKLdJnf+ZMakBzu3ZQzDkJQ239Q+J9iguymghZ8Zrzs
# mbDBWF2osJphFJHRmS9J5D6Bmdbm78rj/T7u7AmGAwcNGw186/RayZXPhxIKXezF
# ApLNBZlyyn3xKhAYOOQxoyi05kzFUqOcasd9wHEJBA1w3gI/h+5WoezrtUyFMYIa
# BTCCGgECAQEwgZAweTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEjMCEGA1UEAxMaTWljcm9zb2Z0IFdpbmRvd3MgUENBIDIwMTACEzMAAAp1fesZ
# uSJd8SsAAAAACnUwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIBhT7C0VQ9IYyvNiupSGOc577LyiUPub5f/VTSflWIz9MEIGCisGAQQB
# gjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEADKXGWsppMm1hziXEzEx9bOCX
# OLZ0aZITOpbQ/xf0BKWv2MTyRj+Y64s+IiLLIVjvBPVekirtqjTwcetvVbPkA0db
# mQ3/7+5ICymwvP22kXiJak9fEV00+JWIDAia1j9/56AtE82SAR32u3Gu+wkJjUw+
# 9JxnEViG4pXmnD760LA2kEqYgTlNxOloviLjG/ddCGrzW4MuLelze4uzRdwXbcCD
# 53UH11ciUvBQ8syUsLvkttOdgXZmig3XjS85OH8mXhKU0yrK66E8aHMupyJSoy3U
# OVGefeHyThva+sruJUkKvnCBeyRSXtCTq4kMPzfkSiSpwV0afhnt5rTVBzif+6GC
# F5QwgheQBgorBgEEAYI3AwMBMYIXgDCCF3wGCSqGSIb3DQEHAqCCF20wghdpAgED
# MQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEEggE9MIIBOQIB
# AQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCB4hU5q9Kxnmu6cbB5sKmhe
# AyUR+kl+CB99Zq9LtpqoGwIGZSiP2aaAGBMyMDIzMTEwNjIzNTQxMi41MDRaMASA
# AgH0oIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQL
# Ex5uU2hpZWxkIFRTUyBFU046REMwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghHqMIIHIDCCBQigAwIBAgITMwAAAdIh
# JDFKWL8tEQABAAAB0jANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDAeFw0yMzA1MjUxOTEyMjFaFw0yNDAyMDExOTEyMjFaMIHLMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNy
# b3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBF
# U046REMwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDcYIhC0QI/
# SPaT5+nYSBsSdhBPO2SXM40Vyyg8Fq1TPrMNDzxChxWUD7fbKwYGSsONgtjjVed5
# HSh5il75jNacb6TrZwuX+Q2++f2/8CCyu8TY0rxEInD3Tj52bWz5QRWVQejfdCA/
# n6ZzinhcZZ7+VelWgTfYC7rDrhX3TBX89elqXmISOVIWeXiRK8h9hH6SXgjhQGGQ
# bf2bSM7uGkKzJ/pZ2LvlTzq+mOW9iP2jcYEA4bpPeurpglLVUSnGGQLmjQp7Sdy1
# wE52WjPKdLnBF6JbmSREM/Dj9Z7okxRNUjYSdgyvZ1LWSilhV/wegYXVQ6P9MKjR
# nE8CI5KMHmq7EsHhIBK0B99dFQydL1vduC7eWEjzz55Z/DyH6Hl2SPOf5KZ4lHf6
# MUwtgaf+MeZxkW0ixh/vL1mX8VsJTHa8AH+0l/9dnWzFMFFJFG7g95nHJ6MmYPrf
# moeKORoyEQRsSus2qCrpMjg/P3Z9WJAtFGoXYMD19NrzG4UFPpVbl3N1XvG4/uld
# o1+anBpDYhxQU7k1gfHn6QxdUU0TsrJ/JCvLffS89b4VXlIaxnVF6QZh+J7xLUNG
# tEmj6dwPzoCfL7zqDZJvmsvYNk1lcbyVxMIgDFPoA2fZPXHF7dxahM2ZG7AAt3vZ
# EiMtC6E/ciLRcIwzlJrBiHEenIPvxW15qwIDAQABo4IBSTCCAUUwHQYDVR0OBBYE
# FCC2n7cnR3ToP/kbEZ2XJFFmZ1kkMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
# KDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCw
# 5iq0Ey0LlAdz2PcqchRwW5d+fitNISCvqD0E6W/AyiTk+TM3WhYTaxQ2pP6Or4qO
# V+Du7/L+k18gYr1phshxVMVnXNcdjecMtTWUOVAwbJoeWHaAgknNIMzXK3+zguG5
# TVcLEh/CVMy1J7KPE8Q0Cz56NgWzd9urG+shSDKkKdhOYPXF970Mr1GCFFpe1oXj
# Ey6aS+Heavp2wmy65mbu0AcUOPEn+hYqijgLXSPqvuFmOOo5UnSV66Dv5FdkqK7q
# 5DReox9RPEZcHUa+2BUKPjp+dQ3D4c9IH8727KjMD8OXZomD9A8Mr/fcDn5FI7lf
# Zc8ghYc7spYKTO/0Z9YRRamhVWxxrIsBN5LrWh+18soXJ++EeSjzSYdgGWYPg16h
# L/7Aydx4Kz/WBTUmbGiiVUcE/I0aQU2U/0NzUiIFIW80SvxeDWn6I+hyVg/sdFSA
# LP5JT7wAe8zTvsrI2hMpEVLdStFAMqanFYqtwZU5FoAsoPZ7h1ElWmKLZkXk8ePu
# ALztNY1yseO0TwdueIGcIwItrlBYg1XpPz1+pMhGMVble6KHunaKo5K/ldOM0mQQ
# T4Vjg6ZbzRIVRoDcArQ5//0875jOUvJtYyc7Hl04jcmvjEIXC3HjkUYvgHEWL0QF
# /4f7vLAchaEZ839/3GYOdqH5VVnZrUIBQB6DTaUILDCCB3EwggVZoAMCAQICEzMA
# AAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMw
# MDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3u
# nAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1
# jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZT
# fDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+
# jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c
# +gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+
# cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C6
# 26p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV
# 2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoS
# CtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxS
# UV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJp
# xq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkr
# BgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYI
# KwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9S
# ZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
# HSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1
# dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwEx
# JFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts
# 0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9I
# dQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYS
# EhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMu
# LGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT9
# 9kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2z
# AVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6Ile
# T53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6l
# MVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbh
# IurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3u
# gm2lBRDBcQZqELQdVTNYs6FwZvKhggNNMIICNQIBATCB+aGB0aSBzjCByzELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9z
# b2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNO
# OkRDMDAtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCJptLCZsE06NtmHQzB5F1TroFSBqCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUA
# AgUA6PNYHDAiGA8yMDIzMTEwNjEyMTgzNloYDzIwMjMxMTA3MTIxODM2WjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDo81gcAgEAMAcCAQACAgt+MAcCAQACAhRbMAoC
# BQDo9KmcAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAHfRi8HLLtS5i+g9
# GyYvGm2JXkbUyStFMgR7IoS2S+LyeI0fH8aDmPP3r9KJ8w//C4hHsGThHy0j34Kx
# zigscb+5N0ecr87kBxj4ajNkna+JMJMjdgtIoWfHHT6Pl7p2EIirhszJjfvvj6XU
# jdFXgytgZdl0z6GkX45fdu/ycy3f+C+oy5SBFOL+4d58BKBXD/T4Nuf46Eq4M8Vc
# +t8iklJpxbZmH/JDmQIJdOu+xHnG3rCkeXiZAfU9ceRAfhQrKVyh7al3bt9WNPsl
# OTveDk4eNPLsLgC68lYFARCSKyHURad3tesI5TgLbcv6s1ilKZgtNoLiknn37pQa
# 6ttxGeAxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MAITMwAAAdIhJDFKWL8tEQABAAAB0jANBglghkgBZQMEAgEFAKCCAUowGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAOhpJiHG/4EYYs
# LrcOmSBWbOaiZ1qp42T1TREopQnUdDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQw
# gb0EIMeAIJPf30i9ZbOExU557GwWNaLH0Z5s65JFga2DeaROMIGYMIGApH4wfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHSISQxSli/LREAAQAAAdIw
# IgQgrCdrWZubDeDc1+QxzwtwsJUo8yxl5+4T4cQYKtXdp0gwDQYJKoZIhvcNAQEL
# BQAEggIAIIa+uA1s7eH8hVET891Dwdi2uGSxk+6eyYeRLTM5rlO+E1EvebHz1u7W
# ChoyyGl37dstdWEVPNdib+LFhW7wuI6Wsge387LMF+lY63ExHcO6U3YumcXMiZOh
# sRgHemWfu3RlV2JmnT7P8Izt3ZzLt5i4U4A/RJWUcJPKzE9VgQoFmJBl3NmJu97I
# LJ9xjWsmb3YI1c31yzuc3M4ZEe34L64TmvadaPc3nLkZ18mArmQtecQRfl1XwRWv
# IptWFnhZzI6eZBTZgU9M5NlVoLA7EVVii5NdLsdl+bAAkIFS3Qtsz1W6Z3ZvQ+ZU
# mere2pz6GLsL+fWxL0TLBwEXNsTG6j3+0TmO1uPz7dLy2ZChZBSQzPgh1c3nZOOk
# ygAPOBkcgQ36mR/hOo+8Z6IvZVOoQZRY2QeXXd1FMoUeeD79cBq+GMNhNIYF+PwC
# ITMCB532IZI3Ght/8B/OzqqtT/1dw4SW7zP/ca7nTDdfe/4Em5pl8tlah/xAYjj9
# Zzkm12epe1cVf1NyQsdr6k5Mmwli4nHcXyY5It3gI0nwofbo8ZveK1tDdo2Kdsfi
# bb6D1rQWNOtwQZvqEN3qUwinvm/wXDOgWYC3P4xguL1wEtOyXzZZvnrWiutSsl1y
# 8JULHnX6JKGF3pukTsFCWuuIFMF5ks/zJ8MSjG1lg6Jb8rr8FzQ=
# SIG # End signature block
