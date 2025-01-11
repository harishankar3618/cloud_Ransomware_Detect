/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_autodesk
{
    meta:
        id = "49QYdIIchrkqJMMFi44lev"
        fingerprint = "a17f2a6e16a8dffbdbe877db5692f0c996264d8937de3a56ff32764f881a0e40"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb0a7a182f6ad89b67ee47fbdb65a2cc"
    $a1="eb0a7a182f6ad89b67ee47fbdb65a2cc"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0706850b275cfe71"
    $a1="0706850b275cfe71"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8562186C9D7B7F0E7FF8E38962CAA1AE9B73C1EF"
    $a1="*8562186C9D7B7F0E7FF8E38962CAA1AE9B73C1EF"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}s91J+74aYSEKjB8mEXaHRQ=="
    $a1="{MD5}s91J+74aYSEKjB8mEXaHRQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}qbH5nKwl2YGb3QLa01sxECkTNXI="
    $a1="{SHA}qbH5nKwl2YGb3QLa01sxECkTNXI="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3dd49fbbe1a61210a8c1f2611768745"
    $a1="b3dd49fbbe1a61210a8c1f2611768745"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9b1f99cac25d9819bdd02dad35b311029133572"
    $a1="a9b1f99cac25d9819bdd02dad35b311029133572"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f9b09b788ff42918863820a324339dd6029b044f3ea3ede4f835581783273f3ff0c6e540029a6f3b6a10164767b4378"
    $a1="7f9b09b788ff42918863820a324339dd6029b044f3ea3ede4f835581783273f3ff0c6e540029a6f3b6a10164767b4378"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="376e729711d25661b81a3a8ad20d443ce838d2bfafb5d99f8a0bdf7f"
    $a1="376e729711d25661b81a3a8ad20d443ce838d2bfafb5d99f8a0bdf7f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2edd680c41415d407530aa382808d33cb2fdc7fd43915831eea4a5177cd1ffbcb884cc1488ac901227aaf7e893654691b8949f8a7ec6e89592c14f8c09db8d5"
    $a1="c2edd680c41415d407530aa382808d33cb2fdc7fd43915831eea4a5177cd1ffbcb884cc1488ac901227aaf7e893654691b8949f8a7ec6e89592c14f8c09db8d5"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50f08e64c5a6192c58961a72ca0b5fcb06f1a09d49e3d012619c2050b84c9b00"
    $a1="50f08e64c5a6192c58961a72ca0b5fcb06f1a09d49e3d012619c2050b84c9b00"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2171bf606e24b72f3b16075240c9e7c4b86d4b5f99270c9ea4e1add1bdf90c1aaae0f335d47acac508e07bf7bde0fec0e10abce3cd1f9086746fe510d6499374"
    $a1="2171bf606e24b72f3b16075240c9e7c4b86d4b5f99270c9ea4e1add1bdf90c1aaae0f335d47acac508e07bf7bde0fec0e10abce3cd1f9086746fe510d6499374"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce8c9a66fcbd3377bf1b92b53d94395ce6c071647b603c93381305aa41fdadca"
    $a1="ce8c9a66fcbd3377bf1b92b53d94395ce6c071647b603c93381305aa41fdadca"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3010a194d11f71ad637efdcf99dc050d87101eed87d514bd6c8c3812"
    $a1="3010a194d11f71ad637efdcf99dc050d87101eed87d514bd6c8c3812"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="498b54202d1b957236c7519c3f99e7199793118b0fc7a3460dc527c655a22f07"
    $a1="498b54202d1b957236c7519c3f99e7199793118b0fc7a3460dc527c655a22f07"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e69c161e617d31ed1f3c20de204702fc5a50ea0c407e8694cad97f9031c58b205089d186d1b04522c441b6d22a87dbd6"
    $a1="e69c161e617d31ed1f3c20de204702fc5a50ea0c407e8694cad97f9031c58b205089d186d1b04522c441b6d22a87dbd6"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ade0b0ea8c2b24e383116cd15713284b90e31b6099358a148de7a7ad4937b4b6d35584a0fd66e2bdada1f9169b0d2591fa71a4523971f57ab6e4a87831d093c"
    $a1="4ade0b0ea8c2b24e383116cd15713284b90e31b6099358a148de7a7ad4937b4b6d35584a0fd66e2bdada1f9169b0d2591fa71a4523971f57ab6e4a87831d093c"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YXV0b2NhZA=="
    $a1="YXV0b2NhZA=="
condition:
    ($a0 and $a1)
}

