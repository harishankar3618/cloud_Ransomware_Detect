/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_gonet
{
    meta:
        id = "2WvvwMkPpsBt911CBTHesi"
        fingerprint = "d005ca495c92865c754640a9b5ac602446a8f112e3b854ca882a06cd08a886d2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a957d84dd117cc939f22ff7fa4a6faac"
    $a1="4b8bb0dcada9b1b46885b4814984b4b9"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4975973e0dadffb3"
    $a1="0d862a5c3f321f89"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*91B31686FE836F4E98364EB069D6855E89711974"
    $a1="*FB917C40992DFC9F92C5D28FDA7AFEA6197FA424"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gjvzbOJhAocgn6XU06Nb/Q=="
    $a1="{MD5}MdRUG46SaiTwybg1toz98w=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}DJaTs4Nk+nogewz8IXLfFrPqZpM="
    $a1="{SHA}Cv3lZpnbmcQ8YlTYHMwW+7cJatM="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="823bf36ce2610287209fa5d4d3a35bfd"
    $a1="31d4541b8e926a24f0c9b835b68cfdf3"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c9693b38364fa7a207b0cfc2172df16b3ea6693"
    $a1="0afde56699db99c43c6254d81ccc16fbb7096ad3"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d55914d9b903bccac281e27932575a1b44e03aaa62dcf3a965c5c47bc528a707b7281620812451cd04802d749cf6d385"
    $a1="5ab17954fa5805a49d61b74f9cd402a4391438da77b04690175d423a018331d7dd93c0fa53daf525a53d5a97b7e913ae"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7ffdb4717991146d9a649464f37194f803d6ff39479eb37aedd4d6f"
    $a1="38750cc6599f8a257b9c7332c707b8f10a75d7efa416547fee31cee7"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b92d2ce65fc0503e90788f7ca2f8b2cb06a70971c3e13a6cc73c4b6d983760d482228135687a0c6d752d33ee398d2aa93cf70a030556ae6ad7ddeceb0d00ec69"
    $a1="ac9f96315639dc998ad7892e5849058d594ef535c5a57f530f27b20b6a571b5ead945e7b304abe4f922eec7d335cc068da702eb4273e3fc9efd8ac7446c1d90a"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c04ef5da8feac07a4ce62109c0be500e357e732552a5d7a1049334c0fdda90e"
    $a1="115dc3606fbf8691fb69f2aefec86f2ecd302362a0502b3a9648bf2c4dc8290f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8770f3f7909e76148ddcc756c3f6e76742f4b5099fb3a2ead91d4e28527194f4384ef8aa4aae1eb8685001282b577df12dc17def7f6544f6d2f8af54ee97fbc"
    $a1="e5c631f43d4c8ba14ad32c3bdbf4be11a76c7dee9845495e81a9aaf4fb3ada0380843c386f7a4510edc834f79ac658706677c8a0c20c82c42fb6c33243e111db"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26a6fd7063309f44cfa64b4752d5f84ab116c1e296db1c93b462c5be933d465a"
    $a1="fb3e4d0cc8bcdcd2ba9fe50ca1d80ec6972557182d4bcbe20c63ac8394947967"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed683fef3064c52ff9d511bfb2145a274599082e324499a238d71038"
    $a1="7727feb00ed156546949bc0e39909c4011b7d6153de06cd656686542"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfeb3a14a2b4d4796b2fdc5cb3eb0ba16a24a19d11df4316bf62125349e89cd4"
    $a1="f1dcd042f3c4ec914ac7618e514cca24f5a1854abfb282f455e268ae30d09264"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="102ca1d60a29775858edb4da0c35c174bad000b415fa0053adfc9ffeb4fa53bebcee75ce0f5d8bdd2d28d7ed9d1930aa"
    $a1="b36f73c12d63501af37e7a2accc87cae533b760ea581f43d21cc246b8a428bebac8bed747b266b00569df79b6a5413e8"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13660c9bcdee30264a732cd1939515a21f5680ddb651af51b6bdfffd342d5b38ce6638e914ae3191e8eadf5566974a052ef79b57fdacede1eb691cacde5ada1d"
    $a1="62c809d154aaffd4d15327c159a3f4c319f6617aea1386a9027dd84289d59faac47e61d22d0a76139b7b558c6ba344d2143a906d930076ca63162183a97c7f83"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZmFzdA=="
    $a1="YWRiMjM0"
condition:
    ($a0 and $a1)
}

