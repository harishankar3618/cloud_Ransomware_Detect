/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_3m
{
    meta:
        id = "7Zma473braAJiB60auIv53"
        fingerprint = "379fac464c20e7500d1ce28cda3d7504bd6a6bb2cfb5656dcabcdd44cb3dfa9e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3680aecee838ae00a97ce9bb72c256d"
    $a1="a3680aecee838ae00a97ce9bb72c256d"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23b07dee31994287"
    $a1="23b07dee31994287"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5469DDC8202169A20B18B52EE7FB2BA32756514B"
    $a1="*5469DDC8202169A20B18B52EE7FB2BA32756514B"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}RjkiXa6Xu028lzhq7RUqXw=="
    $a1="{MD5}RjkiXa6Xu028lzhq7RUqXw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}AP8cFwkPr2TmcF33qpOGGiTMGp8="
    $a1="{SHA}AP8cFwkPr2TmcF33qpOGGiTMGp8="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4639225dae97bb4dbc97386aed152a5f"
    $a1="4639225dae97bb4dbc97386aed152a5f"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="00ff1c17090faf64e6705df7aa93861a24cc1a9f"
    $a1="00ff1c17090faf64e6705df7aa93861a24cc1a9f"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e2b1d58065dd5507a22acf0e6be84e9d6e6cfaab56dd2303cd1e955c2df22a86993e7c8ea941c7a437b58533a8c4a3a8"
    $a1="e2b1d58065dd5507a22acf0e6be84e9d6e6cfaab56dd2303cd1e955c2df22a86993e7c8ea941c7a437b58533a8c4a3a8"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4293831082809645462ed6947c4a90c10a9b531bfc360d409bf49a35"
    $a1="4293831082809645462ed6947c4a90c10a9b531bfc360d409bf49a35"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c69744a9ea50de30fbb41d1cfd41d20c326a6fb5d75df61a18eaf581a694f9f6f86b37ab04a04b1ca2f03aa1fe2236d4892e71d58c30670797cd56da385fd56"
    $a1="5c69744a9ea50de30fbb41d1cfd41d20c326a6fb5d75df61a18eaf581a694f9f6f86b37ab04a04b1ca2f03aa1fe2236d4892e71d58c30670797cd56da385fd56"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad6a450bf4435f8f305481804ca478b0ebc73b03c86f5c19acef4b29bee7658a"
    $a1="ad6a450bf4435f8f305481804ca478b0ebc73b03c86f5c19acef4b29bee7658a"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b74107dc535dbd829045bc54050ec629f9b8f39e8e04e3d267fd93cb06384d5366447caa4808dcc5b258edd1935d4119cc322aab0fbf0f5a4f4bfaee990aa2d4"
    $a1="b74107dc535dbd829045bc54050ec629f9b8f39e8e04e3d267fd93cb06384d5366447caa4808dcc5b258edd1935d4119cc322aab0fbf0f5a4f4bfaee990aa2d4"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90401a1ec1d23d8b1979ee0a1f632186781fdb749ea3f431d3c1bebbbdce7a21"
    $a1="90401a1ec1d23d8b1979ee0a1f632186781fdb749ea3f431d3c1bebbbdce7a21"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aca5858048ee50443cb5ac1d6355f7639741fe5e842027136004a906"
    $a1="aca5858048ee50443cb5ac1d6355f7639741fe5e842027136004a906"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05155a9f2e0696cd4a54b7380187698f74bf5799f56c99579c94dfce58ad6f8a"
    $a1="05155a9f2e0696cd4a54b7380187698f74bf5799f56c99579c94dfce58ad6f8a"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62b8ff9b82a95fc17205943fa97d28ccecdc90c157df42b72e83ab980ad3ba845c241e3821151139cd5590d936153ed2"
    $a1="62b8ff9b82a95fc17205943fa97d28ccecdc90c157df42b72e83ab980ad3ba845c241e3821151139cd5590d936153ed2"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15a53dbbfb963a99dc174afd5d0860d072134f35ce9e7c53370cd5d00db50b6ae58dc4cc0473672216f5a04a7670cc021cf707bdec518e1cb15107e25167e1b4"
    $a1="15a53dbbfb963a99dc174afd5d0860d072134f35ce9e7c53370cd5d00db50b6ae58dc4cc0473672216f5a04a7670cc021cf707bdec518e1cb15107e25167e1b4"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dm9saXRpb24="
    $a1="dm9saXRpb24="
condition:
    ($a0 and $a1)
}

