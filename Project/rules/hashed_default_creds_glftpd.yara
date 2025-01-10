/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_glftpd
{
    meta:
        id = "hyNEmDOmDkXCVi7WL9Ol2"
        fingerprint = "a2c0e42379688694aa3719a8f45d4178f637cb291da989e34ee46f0adc422043"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d22fb8bfdb4097c43591e76812c6618d"
    $a1="d22fb8bfdb4097c43591e76812c6618d"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5b467f7f03a79f7b"
    $a1="5b467f7f03a79f7b"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*9D4F98AF378DE76EFB669C86F63CB5D48963880A"
    $a1="*9D4F98AF378DE76EFB669C86F63CB5D48963880A"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}p1OjIlPFVwA455tBHfE8ag=="
    $a1="{MD5}p1OjIlPFVwA455tBHfE8ag=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Tzp8Ae5tCKjS0t9az7+uSsiR0vw="
    $a1="{SHA}Tzp8Ae5tCKjS0t9az7+uSsiR0vw="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a753a32253c5570038e79b411df13c6a"
    $a1="a753a32253c5570038e79b411df13c6a"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f3a7c01ee6d08a8d2d2df5acfbfae4ac891d2fc"
    $a1="4f3a7c01ee6d08a8d2d2df5acfbfae4ac891d2fc"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0011829e5362892111f498c20efa1fab746af43c3fd27256abf6b453f979fe7e4b822d9aefceecc8e931c6b8c3a47d52"
    $a1="0011829e5362892111f498c20efa1fab746af43c3fd27256abf6b453f979fe7e4b822d9aefceecc8e931c6b8c3a47d52"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e3cafd232d07f28178ec9e1e92e2ebb1c03ecc24e2f67f81079f891e"
    $a1="e3cafd232d07f28178ec9e1e92e2ebb1c03ecc24e2f67f81079f891e"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6852e9af659a13636332123e10540146cd698da28872236d08ce49c17cef98d2e45e58c3c8cacf2767215b0753c23f85186e1f90149894a2579471c8a948648f"
    $a1="6852e9af659a13636332123e10540146cd698da28872236d08ce49c17cef98d2e45e58c3c8cacf2767215b0753c23f85186e1f90149894a2579471c8a948648f"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ada88f7dafa9a39f45effb94631ca6887752dd046bc110cb3c86ca6b1030aff3"
    $a1="ada88f7dafa9a39f45effb94631ca6887752dd046bc110cb3c86ca6b1030aff3"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="045237964ab8999e285a4a2fb4c64a5cc4835805245d68643378c0e4f6076404bd582c2d17b03e6cd5eb22bc562c9203d0d46794cf995a6877a67676e70680e5"
    $a1="045237964ab8999e285a4a2fb4c64a5cc4835805245d68643378c0e4f6076404bd582c2d17b03e6cd5eb22bc562c9203d0d46794cf995a6877a67676e70680e5"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a386507813b3bb08ebf46196eebd9562867ce7580027661e67438832819b0326"
    $a1="a386507813b3bb08ebf46196eebd9562867ce7580027661e67438832819b0326"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="205471afbd01c7e16fe834ba867745730e18e2f3faf16c6a631b43d5"
    $a1="205471afbd01c7e16fe834ba867745730e18e2f3faf16c6a631b43d5"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1df606b7908d7f8f7210d14925749f59442da1ec5197f4589efadd69c8f63eed"
    $a1="1df606b7908d7f8f7210d14925749f59442da1ec5197f4589efadd69c8f63eed"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d01446bdf713e473c53a6f7ec46ec2416fa7b4e79d7fce948e3fedd9fdc17f1a17d5c66db2be47b6071fe0d6f80bec6"
    $a1="7d01446bdf713e473c53a6f7ec46ec2416fa7b4e79d7fce948e3fedd9fdc17f1a17d5c66db2be47b6071fe0d6f80bec6"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d98b1b5fcb844e838b3e56ed62789c5284f76be2ce82c96c827c57457dc9fd826bda545f43c6a63d4c73554b8d3386592f8d38d24f811ab26ae4de8fb8647e7"
    $a1="3d98b1b5fcb844e838b3e56ed62789c5284f76be2ce82c96c827c57457dc9fd826bda545f43c6a63d4c73554b8d3386592f8d38d24f811ab26ae4de8fb8647e7"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Z2xmdHBk"
    $a1="Z2xmdHBk"
condition:
    ($a0 and $a1)
}

