/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_openelec
{
    meta:
        id = "6mgC7yNKLKX0PxgqVYwjBg"
        fingerprint = "78db707ba2b017ea79f0a81e0fa3500b5129fdf82d07440aa4322d5f58d20c51"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd1de9881cd4e0f7bb8427de3c989523"
    $a1="e2b52fdd7824828dc277e4454d26f155"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22c5bb391e322aee"
    $a1="67457e226a1a15bd"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5DF1EEE508934ED70B9F3C5C20F213EFA8A7A44B"
    $a1="*94B47726674538CB8CE85BA81CE111972696111E"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}F4UCm/H+ZwEThaaLEyctXA=="
    $a1="{MD5}ZH6dA7ykaM2ZZmGqiubZbg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}DtHxha5oHhvKb0qPmkuFtp5xxEY="
    $a1="{SHA}tkAtHSdTIxRpLjNJJbizTwzfOyc="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1785029bf1fe67011385a68b13272d5c"
    $a1="647e9d03bca468cd996661aa8ae6d96e"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0ed1f185ae681e1bca6f4a8f9a4b85b69e71c446"
    $a1="b6402d1d27532314692e334925b8b34f0cdf3b27"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c4833f76f4f6d777618974dd06ea9afcb903b9a5babab74de3a9bb841dede4b493f8b8144f68cd10d702f57682709fb"
    $a1="5760f1c638d78b33bd719ce3c50895706db638cd9f98201b0682cc0ef862424576c6eed870613dad65a3e388d222d816"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e92da0438ab0fca54bb6a0c43adcc280ddd70f488def36d26dde7aea"
    $a1="978fe4c5581e62dfd5d5c537a1c5e6c7387c2b6e2b483f08739ec4db"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="55e91c3cffcd5ac54a3b3b920f344fe0367e83ed8da0bc8a75ca7c3cca39a052866f3bb451d2ef98b5dc2ae8ac03061f82c87e13ac9009a5bb43ead8541a5a47"
    $a1="edc03ae04eb1df672c5619ee07c59c0e24833e8298efcb9c523eb7ee2c9d71ed6e6a61d820019af115ea0e6897768ccfbbe915ac755d4d0a9427e4a71a5eccab"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f6ae74f84b4213f16f22dbf21423cb7b9af26e881109b65f83b2903a391b39d6"
    $a1="24c30216b298744ccc2ba61ab433b71143d2838d4d8ed8bccdbe606cc76ee8e5"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aced3c4754f990dc167276adebd5c870ba464e602b091bc3d1d3ee90a5ef87143c60db283bef5ed42f85ebc727cc9adfc9191da9a7895be3dbe8440342f7345b"
    $a1="1febddcf161e79399c32859dc9664bbc20423f2f11ff1e95884e112a253fa65b2dafdd15918512a58686a0bd7bb84b4afb9322f6945130fd6959c2091fa27b9f"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a79dc1d44507e66e4e9a56ae92a06f035e7fda8a197fefbbfccbbc588f0f4968"
    $a1="979d1d208886c99c92d56c331571f1c7e6662c433148cc36d42ce63a4dde11b7"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="289d31c6727fc07bcb8ff04a6c235da9734df33322bd37fa86c70fc3"
    $a1="d6683748c1b64905e264146ffc76eced7e3a0c62afebbe552720b94b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18f960752cce9c8e492cd445a44e8ab5fe82f180790c17fc76437886d76ea081"
    $a1="423bf59865b7a81163719045708e050e7ab8d80222442c5af870786e1b7abe50"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c035798e4887db35dcf7fadeef55d6e42b298572856e565f6c94e1892f03c0d09ab118b278b595dc8597429bef7b7adb"
    $a1="d7dbff373926d907b4027238e58cd9f3133c5b49fd6f533d21f8a2e14abf757982cdb82eaac87e6f7e8310cb2b4ad57d"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6ff7178d9d9dcd07a656415a8866c798d259e54a8dd3b46770fc23608c20667a74ed4c2918e4e86f23851c72bacc95eef1705d0a9939d657cf091e25e7b7af5"
    $a1="ccc1420b92cc69530f013b124c71d724e95f964ad1860b8b189f8f9c7dbd0e0a98df4ffb36afe67ccb6c1d292decaa4482fd3180deb950aca89b58f27ab12a56"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="IHJvb3Q="
    $a1="IG9wZW5lbGVj"
condition:
    ($a0 and $a1)
}

