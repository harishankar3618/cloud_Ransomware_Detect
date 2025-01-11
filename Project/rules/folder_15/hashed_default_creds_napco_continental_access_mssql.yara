/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        id = "v0nt41vqyL3KafyFXIg2I"
        fingerprint = "e221ccb89738948f9ba2529ad122f0f634d11d670d7c40aad0e15a9b508709ce"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5c30aba9a200e487dddc9a00b134031"
    $a1="b5c30aba9a200e487dddc9a00b134031"
    $a2="93fbb3f777552ca8f66945daa0bcab50"
    $a3="b5c30aba9a200e487dddc9a00b134031"
    $a4="cde8b750965f6fb65986e527ca350258"
    $a5="b5c30aba9a200e487dddc9a00b134031"
    $a6="b5c30aba9a200e487dddc9a00b134031"
    $a7="9cb285c0622b8e5e8181a2b3d1654c17"
    $a8="93fbb3f777552ca8f66945daa0bcab50"
    $a9="9cb285c0622b8e5e8181a2b3d1654c17"
    $a10="cde8b750965f6fb65986e527ca350258"
    $a11="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b44775d226429b1"
    $a1="7b44775d226429b1"
    $a2="4a2a2992420660a7"
    $a3="7b44775d226429b1"
    $a4="649e8432104b4a47"
    $a5="7b44775d226429b1"
    $a6="7b44775d226429b1"
    $a7="077ff75a4925858c"
    $a8="4a2a2992420660a7"
    $a9="077ff75a4925858c"
    $a10="649e8432104b4a47"
    $a11="077ff75a4925858c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a1="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a2="*EC42B280643D13F3BF89ED2EC99BE05B2FB5AE9D"
    $a3="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a4="*656356A25E1A77D26C33E42D2F5C8FDFF140BC24"
    $a5="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a6="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a7="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a8="*EC42B280643D13F3BF89ED2EC99BE05B2FB5AE9D"
    $a9="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a10="*656356A25E1A77D26C33E42D2F5C8FDFF140BC24"
    $a11="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a1="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a2="{MD5}vIuAn1XEdEY9L7Bfg3klMg=="
    $a3="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a4="{MD5}yx8eDfNv4jmtKormKKkU8Q=="
    $a5="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a6="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a7="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a8="{MD5}vIuAn1XEdEY9L7Bfg3klMg=="
    $a9="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a10="{MD5}yx8eDfNv4jmtKormKKkU8Q=="
    $a11="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a1="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a2="{SHA}5AqM1HGUJJG5tBKlF9b9gVyl9Fs="
    $a3="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a4="{SHA}PWrPWwZkyEIsbAr6ftHTn/FVyio="
    $a5="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a6="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a7="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a8="{SHA}5AqM1HGUJJG5tBKlF9b9gVyl9Fs="
    $a9="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a10="{SHA}PWrPWwZkyEIsbAr6ftHTn/FVyio="
    $a11="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="87c225cf0ef858082c1e638eae0cce66"
    $a1="87c225cf0ef858082c1e638eae0cce66"
    $a2="bc8b809f55c474463d2fb05f83792532"
    $a3="87c225cf0ef858082c1e638eae0cce66"
    $a4="cb1f1e0df36fe239ad2a8ae628a914f1"
    $a5="87c225cf0ef858082c1e638eae0cce66"
    $a6="87c225cf0ef858082c1e638eae0cce66"
    $a7="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a8="bc8b809f55c474463d2fb05f83792532"
    $a9="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a10="cb1f1e0df36fe239ad2a8ae628a914f1"
    $a11="c12e01f2a13ff5587e1e9e4aedb8242d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a1="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a2="e40a8cd471942491b9b412a517d6fd815ca5f45b"
    $a3="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a4="3d6acf5b0664c8422c6c0afa7ed1d39ff155ca2a"
    $a5="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a6="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a7="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a8="e40a8cd471942491b9b412a517d6fd815ca5f45b"
    $a9="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a10="3d6acf5b0664c8422c6c0afa7ed1d39ff155ca2a"
    $a11="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a1="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a2="a8a30f05f7fcd4254c4f62146b345af017a22306a7aa989c544bf41709cfc830f6313bc14ea4d47a02cdf9767750280b"
    $a3="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a4="6cd6e255b7f726821099ba11765af0902d128c2d29bdeccd0bb1d907cd347b909e48c27008375e291e03b1c594e04803"
    $a5="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a6="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a7="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a8="a8a30f05f7fcd4254c4f62146b345af017a22306a7aa989c544bf41709cfc830f6313bc14ea4d47a02cdf9767750280b"
    $a9="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a10="6cd6e255b7f726821099ba11765af0902d128c2d29bdeccd0bb1d907cd347b909e48c27008375e291e03b1c594e04803"
    $a11="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a1="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a2="26cd8a8653b5a2ccacf99920f0be8318e824d19126a79a005beae800"
    $a3="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a4="05eb62f24bed29b0bef10e5eefe60619c0a5cf482e5fd961b05d3aac"
    $a5="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a6="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a7="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a8="26cd8a8653b5a2ccacf99920f0be8318e824d19126a79a005beae800"
    $a9="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a10="05eb62f24bed29b0bef10e5eefe60619c0a5cf482e5fd961b05d3aac"
    $a11="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a1="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a2="903557e89325da88e4f8eb3823344eca7985bd290ec3ef1bac564e649e06530cce39b8781d877c9e9f330e114356b05f3e0c51374eb804f0aaebeac069c8a633"
    $a3="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a4="68a4c0f67fc1fb5bd01187b365ffb622602c62afa0b62e8baeceb4f59f69589767952d4644d6e0387cdea13081bc412d39aeccec638b7dfa733ce6ee461701be"
    $a5="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a6="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a7="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a8="903557e89325da88e4f8eb3823344eca7985bd290ec3ef1bac564e649e06530cce39b8781d877c9e9f330e114356b05f3e0c51374eb804f0aaebeac069c8a633"
    $a9="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a10="68a4c0f67fc1fb5bd01187b365ffb622602c62afa0b62e8baeceb4f59f69589767952d4644d6e0387cdea13081bc412d39aeccec638b7dfa733ce6ee461701be"
    $a11="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a1="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a2="a2f29d1c5e994056c6e23c5bff19b6542f2aa19f0d94320ada5f17fbd34b48c3"
    $a3="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a4="d2d92511448b371f9ec196aa08fb64ef71602098494dfe3ab97d493b5ea53c89"
    $a5="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a6="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a7="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a8="a2f29d1c5e994056c6e23c5bff19b6542f2aa19f0d94320ada5f17fbd34b48c3"
    $a9="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a10="d2d92511448b371f9ec196aa08fb64ef71602098494dfe3ab97d493b5ea53c89"
    $a11="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a1="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a2="3a68f3b19c9ab7bb4e1809a75946ffed3378b42abc57ed4e3105235b40e8681fce0b1c0f967677f9b7b583423bbb9c79edef0dc71b256788734dbd0fa517abce"
    $a3="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a4="8852ab57ae31da7958a4aa7e7282447b86a5fbc12264cffc7451741c5c9e7dd054f11e2011bc2a4f72caa470ad028a719bce039196614137fae869af966eb3a2"
    $a5="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a6="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a7="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a8="3a68f3b19c9ab7bb4e1809a75946ffed3378b42abc57ed4e3105235b40e8681fce0b1c0f967677f9b7b583423bbb9c79edef0dc71b256788734dbd0fa517abce"
    $a9="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a10="8852ab57ae31da7958a4aa7e7282447b86a5fbc12264cffc7451741c5c9e7dd054f11e2011bc2a4f72caa470ad028a719bce039196614137fae869af966eb3a2"
    $a11="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a1="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a2="af6a96f08629a1ce62a4f187a682f649068007fe3793e2ba057967f6ddb284f6"
    $a3="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a4="6d2dde5b9ba3dabce745ae144372bfb3c58d5fe900679fc9d19e30849fdeb83e"
    $a5="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a6="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a7="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a8="af6a96f08629a1ce62a4f187a682f649068007fe3793e2ba057967f6ddb284f6"
    $a9="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a10="6d2dde5b9ba3dabce745ae144372bfb3c58d5fe900679fc9d19e30849fdeb83e"
    $a11="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a1="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a2="84240bfc80604d83dbdc446e1f147650c530a0abadf4e522537759e9"
    $a3="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a4="9ef40170e5f7deda01302b182500aa8f97b294bc61fbce159105de46"
    $a5="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a6="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a7="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a8="84240bfc80604d83dbdc446e1f147650c530a0abadf4e522537759e9"
    $a9="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a10="9ef40170e5f7deda01302b182500aa8f97b294bc61fbce159105de46"
    $a11="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a1="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a2="25b32184d8410e57df05a91c1fce6e458ac880a144321bf9e14944c1f07bfa34"
    $a3="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a4="fd055150cfa1f6e3da04cc4d9d89f4ce306addde4a1e0ee1ca032d302e590221"
    $a5="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a6="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a7="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a8="25b32184d8410e57df05a91c1fce6e458ac880a144321bf9e14944c1f07bfa34"
    $a9="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a10="fd055150cfa1f6e3da04cc4d9d89f4ce306addde4a1e0ee1ca032d302e590221"
    $a11="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a1="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a2="9929168af61528e55d28a8052ea346e64983547f3533f8b4a94c679aff656397e20be03dc0c164cf939ef4c038a9f99c"
    $a3="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a4="90d8b2614e03cbd3e27035e740262081af34faf99b266f8ca0735c9f7173dd62d94fd88ad58b1a540e56ef1e57d95a11"
    $a5="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a6="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a7="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a8="9929168af61528e55d28a8052ea346e64983547f3533f8b4a94c679aff656397e20be03dc0c164cf939ef4c038a9f99c"
    $a9="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a10="90d8b2614e03cbd3e27035e740262081af34faf99b266f8ca0735c9f7173dd62d94fd88ad58b1a540e56ef1e57d95a11"
    $a11="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a1="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a2="deb019673e9b858eefe959067862d59d390101f67cd4fa7c4ead9dd66e39592d8ca578220fbd0a6d430491565a94a011f54847154fa69286c51694b8f6bdea6f"
    $a3="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a4="c83535b5dc2c468944618a2ae54fe4f522b45728e387f198d042b3bf28c03b0588b1cb39cad3c3f0c31b09ad7a8925470acb63ab1f24c1f71ccfa270e86f43b2"
    $a5="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a6="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a7="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a8="deb019673e9b858eefe959067862d59d390101f67cd4fa7c4ead9dd66e39592d8ca578220fbd0a6d430491565a94a011f54847154fa69286c51694b8f6bdea6f"
    $a9="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a10="c83535b5dc2c468944618a2ae54fe4f522b45728e387f198d042b3bf28c03b0588b1cb39cad3c3f0c31b09ad7a8925470acb63ab1f24c1f71ccfa270e86f43b2"
    $a11="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y2lj"
    $a1="Y2lj"
    $a2="Y2lj"
    $a3="Y2ljITIzNDU2Nzg5"
    $a4="Y2lj"
    $a5="Q2ljITIzNDU2Nzg5"
    $a6="c2E="
    $a7="Y2lj"
    $a8="c2E="
    $a9="Y2ljITIzNDU2Nzg5"
    $a10="c2E="
    $a11="Q2ljITIzNDU2Nzg5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

