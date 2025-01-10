/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_niksun
{
    meta:
        id = "5xoEIzpRNg81a4YuuM7J3D"
        fingerprint = "1fd30bf78b05b01e2d7f017d207a6a1a900408a53d3ac25e1b9a96d3bb840cfb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b636c517f6228573b669000debc59c86"
    $a1="7ecceeb0e39023aaed2c81d35014e531"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3510064412ed9c0f"
    $a1="67bfa0253d351f46"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8298E6021F80305148EEEEE73459169D9BD97EF1"
    $a1="*1D43B9D22FC8DACD39CA0D27716D738F80FC4F53"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Azz6nqs++VsVrx0LqPMFAQ=="
    $a1="{MD5}yVdDTVBGvLzUjGKklFm5EA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}NR1f+J80TNHdyXQbhWjQzf7fqS4="
    $a1="{SHA}fNlXZQTJ12nPL3G2WRQ9n5RQQ/A="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="033cfa9eab3ef95b15af1d0ba8f30501"
    $a1="c957434d5046bcbcd48c62a49459b910"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="351d5ff89f344cd1ddc9741b8568d0cdfedfa92e"
    $a1="7cd9576504c9d769cf2f71b659143d9f945043f0"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="736310e9279ef220a4c499f59a932031c5a6d3e401059881e2c521a77d2a201824dd901a75faf060e5c0f68ccb3e1f64"
    $a1="9a2134f0b7deb5a770e1ad6fb875a6cf6012d933c855682917aa5d5da84c1d39f48f8d3f57101aa488ee091d6a300ba3"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d624b35af544bf7f559a08c8066dd069f20bf0738f9706717247f35"
    $a1="8dd5f10b21e5eb6bedf1097c3153378a5a54ec49a8a1d4871a79e17d"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4c881366d51b5135df67ba20ae7b74db83d3528ba850fdc2769367cfa14d4019b3599f643828897f554f0615a4f819ea73291facfa1a414affe6444ddf290bc"
    $a1="12e0b4e14f49444ee4f3b58ccfc0fdbcd16a9d74e272e23b24ee8d956bda5fa751f3ad77cf23ee18f3254774156d40ea1cc3e580243b23c2efc94571e65719a5"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac966e97f37d15130e47307565a9f0e86a69186b02b1a44798207704669aaf5e"
    $a1="ca5d4525f3e86ac4b688a47207e56c6b01265a1884272a6282aa4c09b712c7a6"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eca7eb4aca59d1a50ae994605c2a77e972cb44f566c4be2c15e866ade60e6505587ba24cea30fc27971ff09a53e54bdd27bb2f63a52ebb72d4302f50b46b0abe"
    $a1="14ef26a80b45f8113198d534133f6bd1b720eb249ec0a195b87e82c84495e76517faca41a0cd7a7c94b7053926fc505a422b886395447f77ae2512c98d148dbb"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1c9d696d9123101677c1d7d7d49a16dfb9a701b72a83905256f22ec2750fd20a"
    $a1="98b473f3f808ea88a715fa09a2a276a4a01dc4692ee6620a2ba31a94e878586f"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="540a18a8ae6396f3bba8c66b521c2614e81f1bd0559185cbc6b7601a"
    $a1="df36674a8da336c83804938538e2456b388779e2cac9534c4c1b11a6"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43a65721c3317dddf29a2afd46049330f18cd4d660f27421b447e85cf56228d5"
    $a1="009da20536b14ddcecb05c30a819f51db52ad4e1cef1e8b3f60180138fa85cb5"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="830bb9a985c04eccadbc32f9cbad61698a0c31ac1a92ae40e701066e919a7369ecd02c48afeb0dc7364f69742069e017"
    $a1="36b46464be360e9c12478de60a363b93217ee2ff7abe18bdef2d51fce22b72874a13dc518b300a5addab42a4e755deca"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c304b99f8171cfd5c4c914cdc0a88a95ba45fcf7a49bd6effb87c53a7a825cc2d50284cdc1fbd2ebc66d0a05fcd24b475d00751a23604b60a8f2f92112fa83b6"
    $a1="17b284bf77f2a2b42a49485e33002c8c5dbbcfc351c7bebf5579f3db326757513fdd6e07da24bc30bb2007004383b7b0ab64fcbff238eb8c10763a5fac54f08d"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dmNy"
    $a1="TmV0VkNS"
condition:
    ($a0 and $a1)
}

