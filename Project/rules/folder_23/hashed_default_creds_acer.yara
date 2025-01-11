/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_acer
{
    meta:
        id = "39jb2sY1zpXh00Az6UmzCj"
        fingerprint = "64f15e13b49b590ed3bbc1723929f19dc89cd8752b7d68121c5df3324c01609c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50b8c8aad511b8de23ff38a871f5fd03"
    $a1="50b8c8aad511b8de23ff38a871f5fd03"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2fda4375786c076c"
    $a1="2fda4375786c076c"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*AA11D1A1567EFC5FB36636D67E126B7A02ABAC08"
    $a1="*AA11D1A1567EFC5FB36636D67E126B7A02ABAC08"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}5HIc3t2IT+7YjckHmGPCeA=="
    $a1="{MD5}5HIc3t2IT+7YjckHmGPCeA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}wKnXR7G3NA2qzdP0EWJP0mlMrRI="
    $a1="{SHA}wKnXR7G3NA2qzdP0EWJP0mlMrRI="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e4721cdedd884feed88dc9079863c278"
    $a1="e4721cdedd884feed88dc9079863c278"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0a9d747b1b7340daacdd3f411624fd2694cad12"
    $a1="c0a9d747b1b7340daacdd3f411624fd2694cad12"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b2e4ff6dd431e7734b45cee108a76aba75a48ceb7f51e8a8976200e0cc5ab033afbb7c18f7814500fb325a87cc7cffd"
    $a1="6b2e4ff6dd431e7734b45cee108a76aba75a48ceb7f51e8a8976200e0cc5ab033afbb7c18f7814500fb325a87cc7cffd"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c465252174f74c5783e0d4cd748db155c58b968dc97b61fe20452502"
    $a1="c465252174f74c5783e0d4cd748db155c58b968dc97b61fe20452502"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37eeaab35694c370627464426956120b0eb8e6b8028ab8bb2779bedcc989cd1dd8f4b1d3f9167e50006a2473739977cc703867201f0f4f5bfb3e284a4f89b0af"
    $a1="37eeaab35694c370627464426956120b0eb8e6b8028ab8bb2779bedcc989cd1dd8f4b1d3f9167e50006a2473739977cc703867201f0f4f5bfb3e284a4f89b0af"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="166cfb0e8bff35f92abb8a9a90df45610ac02af4990d740adae6cb00bc16e2f9"
    $a1="166cfb0e8bff35f92abb8a9a90df45610ac02af4990d740adae6cb00bc16e2f9"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d456dbae707f166825ff591499ee1315367a3a56e596cfcba85ac1911870ad4c63b0731cf7dcb6c824854946f817da39516fc284787e7e46c3c9df781bd4812d"
    $a1="d456dbae707f166825ff591499ee1315367a3a56e596cfcba85ac1911870ad4c63b0731cf7dcb6c824854946f817da39516fc284787e7e46c3c9df781bd4812d"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="197dd409b8e7170377488c35c3c56d0797cb84e8563b222f8f5b1fa0156a4a9d"
    $a1="197dd409b8e7170377488c35c3c56d0797cb84e8563b222f8f5b1fa0156a4a9d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eee9ea7585172d022712be451b8554c75dbfda3e2dad7c6ead64ccb7"
    $a1="eee9ea7585172d022712be451b8554c75dbfda3e2dad7c6ead64ccb7"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5879f5e2e502c1c5ef36ef1cff4080bc4d02666957678e294930ff2d00d119d0"
    $a1="5879f5e2e502c1c5ef36ef1cff4080bc4d02666957678e294930ff2d00d119d0"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04c7448cbbe633402510adaed5f9ece5d9016c048b4fb07c6d9c6e7b4ca8662582b76e7b2bc0fe5fa56dd75893c74c5a"
    $a1="04c7448cbbe633402510adaed5f9ece5d9016c048b4fb07c6d9c6e7b4ca8662582b76e7b2bc0fe5fa56dd75893c74c5a"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c854940114cc79363911683ad83bbf9e967dc613eeca7bf03590d8ef5da38e4bedffa091132c0c68effa6c51ba6db11a0fc712f8ab73bd5d511c8d36dd861b6"
    $a1="5c854940114cc79363911683ad83bbf9e967dc613eeca7bf03590d8ef5da38e4bedffa091132c0c68effa6c51ba6db11a0fc712f8ab73bd5d511c8d36dd861b6"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWNlcg=="
    $a1="YWNlcg=="
condition:
    ($a0 and $a1)
}

