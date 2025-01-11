/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_barco
{
    meta:
        id = "3HwDK1sdd7ekff2MQ1eMCR"
        fingerprint = "93d65e84379cab59465b07d66bc2a6a2fa13a67858c1ff73771d0106ce241a40"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2ce527b69ffe029132dbd5b1260988"
    $a1="9954cc0d55d5d8a131a6232c516eb29d"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ab3173433843ed7"
    $a1="325cf1541cf121f7"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*48416765ED6748B0886FDFEDC369D3BBD601B3CF"
    $a1="*BD3EF2CBFA3DD47D06F8A1070415FDF9159A1393"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}N8NFC2YYo0nkiQ3K//a1BQ=="
    $a1="{MD5}m2VF5M6ptK1JedQbuRcOKw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}5ihUNpGZ1ltqZs2Q/oIDrE1b4mw="
    $a1="{SHA}TQZHJpVKF0h/lOkx9bFXtzPsIu0="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37c3450b6618a349e4890dcafff6b505"
    $a1="9b6545e4cea9b4ad4979d41bb9170e2b"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e62854369199d65b6a66cd90fe8203ac4d5be26c"
    $a1="4d064726954a17487f94e931f5b157b733ec22ed"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84fb09de18d99afbbd5310644c294c55ad1e111e4fbe0342b163a71b68cca35910370cd1243ce57112fc9ff4b0d6b873"
    $a1="cc8c8df4102a6d0dc7d7faa34d839282d66fc247564b4ca9f89a3bee928133cb5ab04d6ec710bf1caca34655af6a9abd"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bb36f76d5dd7ce9fb5d658f3c9b8a64c1dd23a6cb90709ec3dc5380c"
    $a1="78b54c128abb67fb08761f4200c3fe47f07e15be91efa0cd29343d9c"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6957d074e9fb020da977127a605a641ddfabd59a2df0a76fa316ce40659f614de904acb82970ba98aa44131a58431577c314f7040eb2da4a7b1c86dfde177a"
    $a1="dd1c7a428d71fb57f9b0f39a7173cca278e0ddb38ef95e01867ecb6ca537d361ccc9cb3778c0dcf82ff621f9ca65c61cf2852581e571e5de38ff1ee556a0cfd8"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d21f85ea38166303ce58e06134b5cc4a5c900c409ab2a500ff7c9225109a09bb"
    $a1="9f088dbebd6c3c70a5ddbc2c943b11e4ca9acea5757b0b4f2b32479f0dbb747e"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fc8fcf6757b0caa9ee0cbc5479e362cde34b48093c723014bfa93c30879f32c5cabda247d8b1bdf13897fd62d413d6f64c0367b9ab7997551a1ef66368e3b20"
    $a1="19918f956da358f894e24fefced570153b0be8dae0b7e189461852211dff503e0c77b7049bd48d1d30cd9702c21e5c496017acbb062edfd328f250ee05792ba0"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="256968d2ce18c311051107edb3f5a28ad1603d844ba99d2c90f7fb98e35da3f1"
    $a1="1e724e738142eb65f0b469601457c93477e81f3ce8dbb78bf0af059ce229aaea"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b8d32f82e26ed557d94b2d77f99ffd72bc7d8c584f88cbb5eff6a15b"
    $a1="0f994a2caa65453ef2f4a8761a99a14a48397f15ece6443689059931"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9b8ffc48ba0cbc8ba2f5025d44d4cf026b5e6d3150de6962c5aff59054b8124f"
    $a1="e92559e9a890b7ce627e2e92aa4438e8599a8ba46334ce0f08f67fab1e425163"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56fa4cfcb68c5a83273df740d3c78e7eb406aaaf35f090c46aef47721d0f2d82c80ba150e457ec35cc2a08e196f0b19d"
    $a1="da48d90385ad4b6ada027c0a243682ec89f07e4de5852ee0aa6babcabc3053386b33f92a3b0d1d5c45329fbce009ec99"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6bcf20448e4cdb64bb38c660819f9996fcf687be9533659412767367d6f8ca628774597eab95ed7eee8835de99f3c056174d67b393892adae8e936a8defb2d5"
    $a1="36f95e0cffeff5c84398e9587112976d67baa79cd791103a0c921a898dde614ee74c04bc2b4a80e80cf164481b54f471d440b4b094ea61279a08c9d1f50cf7a1"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWR2YW5jZWQ="
    $a1="YWR2YW5jZWQ="
condition:
    ($a0 and $a1)
}

