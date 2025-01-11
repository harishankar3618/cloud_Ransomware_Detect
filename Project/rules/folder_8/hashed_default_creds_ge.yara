/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ge
{
    meta:
        id = "1nZKEgy4FkGBm5aV9IMHH3"
        fingerprint = "a3502ee99bca352cc36a5137e43c5537fe86659424873a159ccbb394e0bd7a6f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8474ed2bb7a35bd5135685838b87ea34"
    $a1="0f3c21d56b6c662ce8f4472d993a0c3d"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="41484b9a24f1bbbb"
    $a1="6fabf0f5121a5991"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*88BA4B56C399E697AEDCA0123281D0EAE74D59BF"
    $a1="*5128D9CE898A87718C55E1E71DFE3E2BC27820C0"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}wYBT4UzuFnrgjmB/MCDPvg=="
    $a1="{MD5}FaZ1kbJR52y+W9iHjlV16w=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}vgxvHcr/mt9S6zvQjvp/SA1+uuI="
    $a1="{SHA}c3RBcgRhZBx4wCY2hycI6R7BuXc="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c18053e14cee167ae08e607f3020cfbe"
    $a1="15a67591b251e76cbe5bd8878e5575eb"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be0c6f1dcaff9adf52eb3bd08efa7f480d7ebae2"
    $a1="737441720461641c78c02636872708e91ec1b977"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7ed8b88fdda5ad3b407efa1d7770782465225747d724de2919032054f4af875e5459f01f50570be0b4d16b3ab6a55d6"
    $a1="e4043b0a496de333decd2f4e73aa8b10120ae24fa86ed48879ee4beeeeca9631b7cdd17d668187780c8d23db8d40e609"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c7c7018f6e341a1a8587d2bd0568fa57f0828f4d495d78f1560f41e"
    $a1="71c634a9ebaed1ce7b347ced5a1f71047da0bb1fe2163d9ad8d2a1b0"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ef0e70b6323d222ecb08a092967dbea8c15080ae7df565459f23eb80863581b821ce9e084b3de6fe4ed0cc5300c69e26fc3171b9da9c388e024fc5ce2762fd2"
    $a1="b63c0df879111f6ab1a8432ffa84e1adf0da3a995483fbed364d9b5395c05097cf5f1deae4426478fa7fcd124609c7ca59ed37ca75f9b99af990aa04d332e1aa"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c9c0ad3d9c726a92479802586b324421fa60b7fe37789c45a2b9f896f353efa"
    $a1="65e8bf0efff22e38f40cde441f543f3696680119a335df49641a347ab43e74b2"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97a53718a17fdb5b4e4a3dcaa3300cfdca331dd1b3fa04fc6dced904d8f143a6eff758f6dbbb358e73cadb956399f11242a83030a06a184f4efd0c36804b1c4b"
    $a1="8683acf26a7d208a18d9ec55625c6e3f6daf8479017225334bf03bbb2b3995ce2f50d576611c280358f9e3c9028aba2a47150bdda260b2587c14c2deb59ccfb2"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="090f0c84bd4719f285aaea6035a15d326258f9e58853de1727d005d09f2d8a64"
    $a1="04ea89e999f975644ed4e6ed2de9d32956ed12ec54e91024689ac8ba0382243d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ef5d89bbb08949f8f27ec72cdf1ea2bfbf1802d0692eb6364c4f2fe"
    $a1="ad5963666585f7f94bfc5531ca8e0cdc0f3f658e81891e7a018870c8"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4230a1aed6a63fb2400485a9dc979e5fa4ef641c1617c524e28c8ed92683c19a"
    $a1="1795d85b45233f701b8b0e97d2c9600e0ffb0b5e445bec0da3892d2d11b0e604"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3cf17e66e6ca7f00b3e7da8efaa5db4ad65eb292265b6c0a6ad2cf22ecd93aecc0a09fa40f88492041539a854217c598"
    $a1="c48349c787469982a2d5bd2510e3d4f3481db7dd8c523c3defb730ef0b1831a703d530efd63b04baed52a8abfb8eb4d0"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d28a3e47d736f7bc60a967d9c37b56c0fa00d823a5c7af0d1c3aa784bd7dfc79c728bf8ebffb5bfa16789900d7102428469e359cf907c35cbab75f14810c1e0"
    $a1="cd4b7fbc72046b18c433d03be47772154b1649702d0a9edb6870391166f7a7da66b6e83333a3969450c06cbf3ee2d3a2c95a5f5997603f906711e126457001b5"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bXVzZWFkbWlu"
    $a1="TXVzZSFBZG1pbg=="
condition:
    ($a0 and $a1)
}

