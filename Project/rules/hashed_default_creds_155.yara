/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_155
{
    meta:
        id = "1NQWcEgxAiRBUPWGpVilIa"
        fingerprint = "1eaeed5c3ef4a826c7afd91c52b65f2c89ad18ba9cbdd3e8f6da0d60b08f397c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98ccaa746ecf56c4107e58674b04b1c2"
    $a1="d47ce0c3e3f78529db2f266d5e7afe8d"
    $a2="06da4042f45ed8e9a8d0574b0437c14b"
    $a3="06da4042f45ed8e9a8d0574b0437c14b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="515b87cb3f4ff43c"
    $a1="4829c53d6f9319a1"
    $a2="37bd7c4221e8a247"
    $a3="37bd7c4221e8a247"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*047E18A4C8E3777114B166A4EF752F2E28E5362A"
    $a1="*34E8D02C361F409EFA12A0DC2D59029648DCF5D5"
    $a2="*B09F1B2C210DEEA69C662977CC69C6C461965B09"
    $a3="*B09F1B2C210DEEA69C662977CC69C6C461965B09"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}l/q3zqGhD6cMf7H2F53iyw=="
    $a1="{MD5}rUL2aXsDW3WA5P75O+ILTQ=="
    $a2="{MD5}2fkTP7EgzWCWhwvCtJaAWw=="
    $a3="{MD5}2fkTP7EgzWCWhwvCtJaAWw=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}OqM71h3kQwLVAVDyTUh0mO/v+yI="
    $a1="{SHA}MvquysdCEA93U/DB0KoK3QG0BGs="
    $a2="{SHA}yV7kdomgquxww+uVAkRldyLGmx8="
    $a3="{SHA}yV7kdomgquxww+uVAkRldyLGmx8="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97fab7cea1a10fa70c7fb1f6179de2cb"
    $a1="ad42f6697b035b7580e4fef93be20b4d"
    $a2="d9f9133fb120cd6096870bc2b496805b"
    $a3="d9f9133fb120cd6096870bc2b496805b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3aa33bd61de44302d50150f24d487498efeffb22"
    $a1="32faaecac742100f7753f0c1d0aa0add01b4046b"
    $a2="c95ee47689a0aaec70c3eb950244657722c69b1f"
    $a3="c95ee47689a0aaec70c3eb950244657722c69b1f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da5d66dd3bd1dcae077c06bc64b7f3315a6f13b21ac0921081b9e97d95fb5203057015b95f98368cbffa3400ed8900ad"
    $a1="b345909bba936cdc8ea81ae3ffe6c668481d351df7c46efd502f7f7f94dff566d40a9ecaa6621609419ad1903f74a799"
    $a2="d7d4375a6045ae4b2dd32d6ccf53ee632c2d858cc5e67b2292f60e7e497f3f22efa1093e67ff66301ef64633437df096"
    $a3="d7d4375a6045ae4b2dd32d6ccf53ee632c2d858cc5e67b2292f60e7e497f3f22efa1093e67ff66301ef64633437df096"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7fb217f198e4e8875fe94ec571fba472477807b65106f871802bb656"
    $a1="5cd7fd4c793de52376f74a016cf373db2426deac143682521f0d7779"
    $a2="09fdbc623941c03d3cc3743c3f4923873e75ab6173375aca0500e2a0"
    $a3="09fdbc623941c03d3cc3743c3f4923873e75ab6173375aca0500e2a0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3edb18ab9cdd4b29aa5f73c8591ea2ee40b182769e4d153577369f3720a38960cb9d4caef3a70bf6cec3c63b74a506fcc6ed2cccc185001f6911e6d9ca4a8539"
    $a1="225d05b918519458a8fcc1e6493a4e854c004da76f6250b8f52197f47094f71ee984725c31446a1967f0d55f4dc74793dd44d932f2bdf50d77d4288d663bf1ab"
    $a2="03e27e1cb5c4dc29a516e09233b4ab6d6521eb98d2da9be0522e197798149f9be841dafc8833c431f295d6ce1d1fe6beadaaa1d31d726d227f0627c82757664b"
    $a3="03e27e1cb5c4dc29a516e09233b4ab6d6521eb98d2da9be0522e197798149f9be841dafc8833c431f295d6ce1d1fe6beadaaa1d31d726d227f0627c82757664b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b544267fc76fc36f8360339b3af58e150a6658822c76c1d7bac00d78d838d62"
    $a1="0b8e9e995d8d77f1e4770f0f79665aee6f3f70247b3735422daba73df4c3096f"
    $a2="fe9bbd400bb6cb314531e3462507661401959afc69aae96bc6aec2c213b83bc1"
    $a3="fe9bbd400bb6cb314531e3462507661401959afc69aae96bc6aec2c213b83bc1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="49fffb0b9ec4bb472321946ddeeff90bb82b4c637b54dc647a1c42a627760dec09e44b1c997af5b9b333b00485f7344945e724a79687c6a6bc90bf11081e2365"
    $a1="1261c79e61aae75b7c20e76f0e04c29647a6effdc2d41a7a17582402fd6858060bf834cfa56771a1afa7b5da1ac3bf9eaae3d96fea8873b3eb17b48e9b733081"
    $a2="e61e21ceb5bc71f78b38263da5b67fc43356d4496918503d44af171fc8b80fe19d144524370712c245f5a71a217ef04e65169dd934cf3685d9af46017962bba5"
    $a3="e61e21ceb5bc71f78b38263da5b67fc43356d4496918503d44af171fc8b80fe19d144524370712c245f5a71a217ef04e65169dd934cf3685d9af46017962bba5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f70f0557c4f76d274cb79d700ab485d363f0b7722f5c5e94ce70c2b7cee1fc74"
    $a1="61b83c12ccabd0333a492ba2d826cbeae8d9b2febdc369da09614c29342a2bd1"
    $a2="cebe32cdfd4b0014d09ee07bdb2f8816518d0599798bb30b9a303bc1c663af70"
    $a3="cebe32cdfd4b0014d09ee07bdb2f8816518d0599798bb30b9a303bc1c663af70"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7dbd92d14482ba4f9d0ed23691a4785ace8b2c693b250d726205abc"
    $a1="5122338bd461aecad5e9cd8266c965d6068c3a17e6283d041e4d4627"
    $a2="2012e43628843a91e7188cdd08486c8b10768aca107aa7af995974c3"
    $a3="2012e43628843a91e7188cdd08486c8b10768aca107aa7af995974c3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9001e1a9258d57e0e61b8222a25a04927b12ed41eb39364f180eb5d7bdd8a937"
    $a1="789cf532419e99b67093f10b9059465900d073c466c25efd00771189d38f7e66"
    $a2="6bb4c8e14fe4dc77a7a27a5d75c181cffa632c0c2907086c0f67fb9a55016b96"
    $a3="6bb4c8e14fe4dc77a7a27a5d75c181cffa632c0c2907086c0f67fb9a55016b96"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f2b7e1bfe94444e3f1e34f8aa38591a2650c3a782982036dd7fc3f1872df5b07142b703d57b3d126308f87550c2e5f0"
    $a1="4e5a6f0fba604547745375eb56ccc6f7cecb54dfcbb0b3b65813667ed0ad417ab61e9be79f05ad44e85b29dde2b3fbe1"
    $a2="3a742726566f6d65b11330667491a565ca4f74afa94ff04ef0e13b98fec6b50ec9efe4f779d45f90ce883367841ee691"
    $a3="3a742726566f6d65b11330667491a565ca4f74afa94ff04ef0e13b98fec6b50ec9efe4f779d45f90ce883367841ee691"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f9369583a0dbb2f14041e9149a05ba44ab290f0e1e7e515070f0a92cf6d48d0b886b5593afb0473603b9b6edd0d1566666f317fe317fc5f5d60aa50b3a8b459e"
    $a1="1b553e6e2f919758eaceb4c940055d95507e3a6f2bc82252dac4ba0e72bfd3cb1faff77f8d2d727c309ecc92f3571f92dc5cd1c77ab1d62c91e3187da543026b"
    $a2="00ec7004fc7306dcdb8cda65db82cd35a68b6c9146a2afc84e112c97c71f8e016fbd113fed86326fb3787dcb13274b25e3f909c58fcfdcd13c18e82905f1f464"
    $a3="00ec7004fc7306dcdb8cda65db82cd35a68b6c9146a2afc84e112c97c71f8e016fbd113fed86326fb3787dcb13274b25e3f909c58fcfdcd13c18e82905f1f464"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZGVidWc="
    $a1="c3lubmV0"
    $a2="dGVjaA=="
    $a3="dGVjaA=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

