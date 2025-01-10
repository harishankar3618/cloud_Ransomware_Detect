/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_cisco_systems_general
{
    meta:
        id = "3VXFWsRpJKk52xxwHMPIAr"
        fingerprint = "799e9ce3b165bcef447378574745531cc1c103cedff87a7fe53277248ebc14c7"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c800f13a3ce86ed2540dd4e7331e9a2"
    $a1="5c800f13a3ce86ed2540dd4e7331e9a2"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13304f67671f2f3c"
    $a1="13304f67671f2f3c"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*310AF8D67AE450FB86125F07FF75D1583528B45F"
    $a1="*310AF8D67AE450FB86125F07FF75D1583528B45F"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}3+rxA5DlYK6nRcy6U+BE7Q=="
    $a1="{MD5}3+rxA5DlYK6nRcy6U+BE7Q=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}eveMkR1bSL6h3CRJ2diVE6vrS+U="
    $a1="{SHA}eveMkR1bSL6h3CRJ2diVE6vrS+U="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dfeaf10390e560aea745ccba53e044ed"
    $a1="dfeaf10390e560aea745ccba53e044ed"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
    $a1="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
    $a1="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
    $a1="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
    $a1="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69"
    $a1="e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
    $a1="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
    $a1="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a1="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
    $a1="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
    $a1="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
    $a1="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y2lzY28="
    $a1="Y2lzY28="
condition:
    ($a0 and $a1)
}

