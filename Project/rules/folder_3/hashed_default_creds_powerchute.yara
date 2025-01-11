/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_powerchute
{
    meta:
        id = "3OmJcgcPH6Bg8XDHNuN3vx"
        fingerprint = "c219389ad2d560d9157f09bdc1df1ddaac4c8d587292d51be8c63c2fdace42ee"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b1a54b0f7c7dc6fff10b6c2f5fb9560"
    $a1="2b1a54b0f7c7dc6fff10b6c2f5fb9560"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0041e1800946c984"
    $a1="0041e1800946c984"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*F0E9B6F452739D92FDAB32EBE6768FCBAA44DC45"
    $a1="*F0E9B6F452739D92FDAB32EBE6768FCBAA44DC45"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}fTwln2e2T8nqqVKpes9ikA=="
    $a1="{MD5}fTwln2e2T8nqqVKpes9ikA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}gu8DemW4+dwzBvgXfq4EvRWagos="
    $a1="{SHA}gu8DemW4+dwzBvgXfq4EvRWagos="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d3c259f67b64fc9eaa952a97acf6290"
    $a1="7d3c259f67b64fc9eaa952a97acf6290"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="82ef037a65b8f9dc3306f8177eae04bd159a828b"
    $a1="82ef037a65b8f9dc3306f8177eae04bd159a828b"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eae8b4a8fd1c1b1d803368c19b8ab175561f65b06378c1797a61aaca69a516a103e03a2bbe2475c66650a9d87d26e1a1"
    $a1="eae8b4a8fd1c1b1d803368c19b8ab175561f65b06378c1797a61aaca69a516a103e03a2bbe2475c66650a9d87d26e1a1"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="854d95544714051aa1c86ef5c64bf3a218bfdbe2d4b0befe9579cb0d"
    $a1="854d95544714051aa1c86ef5c64bf3a218bfdbe2d4b0befe9579cb0d"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5079550339bcfce614f45c1628d28dd013b17ebf3bee04f5da63c3eae4d57e46d35500a0f8e00f16a3ebdf001a01517f8481737c54f02d545015e29aa41dbfd2"
    $a1="5079550339bcfce614f45c1628d28dd013b17ebf3bee04f5da63c3eae4d57e46d35500a0f8e00f16a3ebdf001a01517f8481737c54f02d545015e29aa41dbfd2"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97ff7d2d2520ef30b9c0d3c6b2101b69465b76ecc41db4534200e86ea5381831"
    $a1="97ff7d2d2520ef30b9c0d3c6b2101b69465b76ecc41db4534200e86ea5381831"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc7c95e44b78c6f022d0a94d6c7c07057eb3981f6cccb69a67a2fb314c29525c5923cfe941018d3cf2ebc1676d947bb96092e8293e2d42a4d66dd7893fe181f7"
    $a1="bc7c95e44b78c6f022d0a94d6c7c07057eb3981f6cccb69a67a2fb314c29525c5923cfe941018d3cf2ebc1676d947bb96092e8293e2d42a4d66dd7893fe181f7"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2fd8220eef3549107072fff7ad9b61d609d1e616e603132170fdf50487035ef7"
    $a1="2fd8220eef3549107072fff7ad9b61d609d1e616e603132170fdf50487035ef7"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="02cbcfd415c8cce718ec2b617cbcc69faf209e3da70ec8d91add968f"
    $a1="02cbcfd415c8cce718ec2b617cbcc69faf209e3da70ec8d91add968f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc90edd77ecf797950f94e6a1448365ff352beebaaa3f99925bd78cdc3963d9c"
    $a1="fc90edd77ecf797950f94e6a1448365ff352beebaaa3f99925bd78cdc3963d9c"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6f93b8be89cba6d606a191f69b5cec489dddeccc706583c6fc74e580e86e055c784e8c01993302fbccb8b0c65548f30"
    $a1="e6f93b8be89cba6d606a191f69b5cec489dddeccc706583c6fc74e580e86e055c784e8c01993302fbccb8b0c65548f30"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7c9f84a86b7d943758a387a2c3229cbcbb8053994c3539d0161f503ef9bd4c95197bb6adc6582da384eaf2c6e4b7c8fc0deb4eea6da43fc927f3b83818400bd"
    $a1="e7c9f84a86b7d943758a387a2c3229cbcbb8053994c3539d0161f503ef9bd4c95197bb6adc6582da384eaf2c6e4b7c8fc0deb4eea6da43fc927f3b83818400bd"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cHdyY2h1dGU="
    $a1="cHdyY2h1dGU="
condition:
    ($a0 and $a1)
}

