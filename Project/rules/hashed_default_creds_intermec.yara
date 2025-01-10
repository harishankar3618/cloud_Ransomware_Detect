/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_intermec
{
    meta:
        id = "1FckVwGyqTZeBRndBzI6kG"
        fingerprint = "c1250cc5deeccb6cd5dcc8c9a6144629bdabc287a8385ded984db253c50d320c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8ae861c7a35cfac92f4ee90719b6c05"
    $a1="e8ae861c7a35cfac92f4ee90719b6c05"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59e15a553b24db72"
    $a1="59e15a553b24db72"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*9E9901B897825B82E01A6FFAE5AFE54DBEF113C7"
    $a1="*9E9901B897825B82E01A6FFAE5AFE54DBEF113C7"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}FDB/do1iG08hIMrrXEJfrw=="
    $a1="{MD5}FDB/do1iG08hIMrrXEJfrw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}EIsJGSYzZD3phwzIbmkCN9EMUUQ="
    $a1="{SHA}EIsJGSYzZD3phwzIbmkCN9EMUUQ="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14307f768d621b4f2120caeb5c425faf"
    $a1="14307f768d621b4f2120caeb5c425faf"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="108b09192633643de9870cc86e690237d10c5144"
    $a1="108b09192633643de9870cc86e690237d10c5144"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9983ad0b945fd130fc105233ca24fd32bbf936eb5196baa6c74454d7e4225fc7225a7fbffb8d5a7170648af34b171a53"
    $a1="9983ad0b945fd130fc105233ca24fd32bbf936eb5196baa6c74454d7e4225fc7225a7fbffb8d5a7170648af34b171a53"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="557801b03af8b366efd23ed0055b05ad52757a4ae0d902b04090098c"
    $a1="557801b03af8b366efd23ed0055b05ad52757a4ae0d902b04090098c"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bf076296b675c1dccd2616e8f3312fa2c3de539d7e1278bededbb09e008206e33f3c8b20c77fa323aea9636e03634847c142d7cbbb37263bd29dee98da568120"
    $a1="bf076296b675c1dccd2616e8f3312fa2c3de539d7e1278bededbb09e008206e33f3c8b20c77fa323aea9636e03634847c142d7cbbb37263bd29dee98da568120"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8d410cf1342a13c16a52206fc720a46b48c07d14b15a584f5e4927dbca04896"
    $a1="c8d410cf1342a13c16a52206fc720a46b48c07d14b15a584f5e4927dbca04896"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0fd4eb614ffcd4399709a0796a335aef4fb0eff065d7688cb8b827bfe6b1bbbae6715b72515f61557b1cac2126bedcac5dbe51de372e2498fd533b001805e737"
    $a1="0fd4eb614ffcd4399709a0796a335aef4fb0eff065d7688cb8b827bfe6b1bbbae6715b72515f61557b1cac2126bedcac5dbe51de372e2498fd533b001805e737"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="25a9e5c6b8fb76bfc981f3a6c5365593eae0db790174b82740d2535241d15815"
    $a1="25a9e5c6b8fb76bfc981f3a6c5365593eae0db790174b82740d2535241d15815"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa5853427d8241a235fe881a298d29d3c0654eccc2be64f9110db31f"
    $a1="fa5853427d8241a235fe881a298d29d3c0654eccc2be64f9110db31f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e32c206e6c2e4740252a8e171814953fd7014384073a91eb75853cc18a47f3dd"
    $a1="e32c206e6c2e4740252a8e171814953fd7014384073a91eb75853cc18a47f3dd"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d9d34b9b1ae143524caa90db6ba0eaae78edaa36a6b6fa7af4a18ad505d075b5b688f140f5d163a08c561a36cdeea4c4"
    $a1="d9d34b9b1ae143524caa90db6ba0eaae78edaa36a6b6fa7af4a18ad505d075b5b688f140f5d163a08c561a36cdeea4c4"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04dd4d7bc62495261f16c4aa2f5315a2b684e7d232a02fa4376c79fd2102c5f102c44008a784bd538d9cfc2be18a0224a118a74b71e10f4f784c8029ccfaad12"
    $a1="04dd4d7bc62495261f16c4aa2f5315a2b684e7d232a02fa4376c79fd2102c5f102c44008a784bd538d9cfc2be18a0224a118a74b71e10f4f784c8029ccfaad12"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aW50ZXJtZWM="
    $a1="aW50ZXJtZWM="
condition:
    ($a0 and $a1)
}

