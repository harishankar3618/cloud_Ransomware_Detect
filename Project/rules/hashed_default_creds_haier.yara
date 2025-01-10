/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_haier
{
    meta:
        id = "2eZ4ghxZOKxbEOt0bht0TS"
        fingerprint = "eb245e8208a99ee4fb6ee22ea5a257e60d407d131cdcb8e4373be03e2f0cfa7e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="932c88d8463ae986014d4ab6e878befa"
    $a1="3168ada32b86ed226da91faf8667cb24"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="138c22fd1ac0f5cb"
    $a1="3009dbd22588d288"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7FEF17ED6266D83F24CFA0C5055DE1B9893ABB6F"
    $a1="*6BCB2C05FBBAC8F8AE7A174CFC8D2FAA87E9E3E7"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Pspp9NaOgiwzGtu7EXfHxw=="
    $a1="{MD5}UpjJ3OS32FoRK+CwSZKppQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}PRyi7vhWfYLMG7EEJJVmFAECsfA="
    $a1="{SHA}OpVRY7MIjC8uCJET6flqSuYVVkY="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3eca69f4d68e822c331adbbb1177c7c7"
    $a1="5298c9dce4b7d85a112be0b04992a9a5"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d1ca2eef8567d82cc1bb104249566140102b1f0"
    $a1="3a955163b3088c2f2e089113e9f96a4ae6155646"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b4b839c80b6d677ed9a0fb6b073d1a7f0568d12b996a71fc4988a0a5c388ad65ac81da1f82026991bbf3c833f355dac"
    $a1="730702cb5e06928726253b2c46e87d6c561e347fd9da67e981af3ecdc18497a02d5d2a618241a7bd815ae12326c66f24"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3af43450d73425c6bcdd4daab241667f459f0619e60c478f7a436b40"
    $a1="3c2e31f409e2358527641fc4dbae30328135ab49b5805cfa9506dbf9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b219732ab627ffa521fdea8f9adb17a56a1fdf75ca01ae5196a439cfa34bb1852c47e832f5cda7322e8176559b6ee072db0ad7d9941f270253dff4ccceb81b3b"
    $a1="6d41530a870f29e808902d51c4c6dd83c98e37ced7680ee3de93a6439f65adfdb6749fa13b652f234d72a43bd0fc158dc84380b767b1a3c84c5149d451333b97"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1dd40ae398e2e3f5e55467c3b0e189bea1c8b0f0bded7b08973ac3779c40a30f"
    $a1="704c886409ad26cb37f4df84782494a070b60c4789a6146c2a899577236d37d4"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5880c3f3e5faaf40a1c27b578d29f005643827ce8991fcab9021fee5e351e239d66b8c8261f2c81043a6ca374b7ae627e6fbf8014ca4eb9577931d28df907385"
    $a1="166469e6e9166d1506e50e6b92faa113f3cd59bf444151cc35f916e7016939a54dbb399f7aeb1127eba4ba043bedfceb01db0fb5041b84d7a8b57cd30a738d2f"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e962df329fc4dd7000e38a32a881b2d3bed695e1601fc16cbd3cb883fc4a7c68"
    $a1="c300306bdf9cfa241e7aff1d344bef6bba7f8dedf2693f6be4e0912484d440ab"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="801c8b0002aade61eede86ff5e22f4c7136b08548b276b7ff66d65df"
    $a1="edea7218c85e3ec15881b92c506b552c59604e0b8814fa3101e80162"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5c729868c7decd3ab6c9dbb6ca47d70044cd4a719d153f9318f974f8508a17c"
    $a1="a1e92832dbcb143c31095d19a132678a386d6b9663f3965863f391dc4608916d"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d2f2b079e688a30b4c5f9c141f4e12f23c227ff9381b979645cc92194c29d42eb1eb8c4e116e6939c6f8c27a89c9cb4f"
    $a1="cd108cf2b457e1bc09bbe0a2d513748d9be05f4b392c8c5db53512557fd34588e030cd91e0518a6e4d31e1444c889999"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dbfc165713dc3dd994b56a7caec60d20d3edde2d54f5b49dae697b62821b6f2bffb8d08a3d3ef9e242900988af54d7ded269a55dc74ca6604e00b7785d7e4143"
    $a1="ed65f17a088f5e43ef6abda1324caa8a67bc83be94ece451b6a36bb5063c34b595deca0a1404a8401185cf6b39ec09b3855ca1db07975761e2eaa86d533e95cf"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dWNlbmlrMjM="
    $a1="dWNlbmlr"
condition:
    ($a0 and $a1)
}

