/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_topsec
{
    meta:
        id = "6C5itZfBtMLVuMADySHnQT"
        fingerprint = "adf708a9f64d621eae89ded22aaae4cd34db440f1a15192c6d818858bcc5fee2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f372f5f7f0cdf604699e0154d1e3fadf"
    $a1="72f5cfa80f07819ccbcfb72feb9eb9b7"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1949004602895388"
    $a1="6f12b8fd4d9f0334"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*74251E86BE0198C0E64F832F82E41C103EAE66A5"
    $a1="*AE9F960F8FA0994C9878D2245DA640EAFF09BA0E"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}iGJ9H+TV756LNB8NvwNwtQ=="
    $a1="{MD5}hNlhVoplBzo7zw6yFrKldg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}uELVlnAy641YwgV8QH17i1DClps="
    $a1="{SHA}GMKGBN0xCUqNadrmDxvNNH8a/Fo="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="88627d1fe4d5ef9e8b341f0dbf0370b5"
    $a1="84d961568a65073a3bcf0eb216b2a576"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b842d5967032eb8d58c2057c407d7b8b50c2969b"
    $a1="18c28604dd31094a8d69dae60f1bcd347f1afc5a"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64273dab139fa4eb8926cd7fe0a81c4c1d901d46f4c4ebd9b03eb90e3eacbba9d12ca377ae4054ef860b4520cb1b70b7"
    $a1="584b3ffccb64d43929696d4023daefd6a92c9744d8c56a4e1213704692cc02078f0c27f73dc975669ce1922da0a5e5d6"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="191bdd6c5a643071a5ad50282c0e52f0a786f7b1ce4b4c01142f6904"
    $a1="0d452daf51ab8ae21a4e75bb181042b774e61f418b7caa6c5dad3f83"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21fc367a8c45f77d415c9fb4612f333a69b21a8e0d4da3a73a9b20da90dd5b87ece951db51123c642c9c217abd14f0fc4519ab35c495fb901a6b26a6b7016320"
    $a1="9ad0d01d1766bb60025ba3403e851d1493a1ce2f14bdcf14d198f4a49e083f4547a6e5f9908444aad02d8d2383fbc74af021c7ee797ea13254c6603de76291b8"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50cb3d000873ec971dad66e68eccda26db73d5d1508e3a2a5e455451350061d5"
    $a1="73cd1b16c4fb83061ad18a0b29b9643a68d4640075a466dc9e51682f84a847f5"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73efc681de8ba9dc54a5f8c9f3ab5ff18fd4b01f21ffadd4a3e4ac616f76dceedd4847e87c89210bfde23382dbb16bafc6605f0dc7c02c8ee97e3ecd41027f6d"
    $a1="8eaad423dd736e736ed555d895ab8973bd6af729b4d5181cd96cf4c866e8455767fa11dd6a2632090c61f3df15f048b459e8e4e9af7c2436e13bb4fd2ad31f7d"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fd7c852306bc9e7c6c59441be9980367fa8f65c6ab908ad7ddc416ad49ee2a1"
    $a1="9495af2bfd7926e8a8cdb642728a3b728f9500dd99343995c7262d37b023884c"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f41d2b09d14affafec1a0f46b4cc5f918a4fda59aa0284bd28abd70b"
    $a1="a8b9c397c6c27af802af87d16af4dbb5e8cbafe74e3f5a8fee8ed718"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6ea741e4dda4dbb7c51e643995afe2c08d6848e77f2d17db5fd8766b4d87387"
    $a1="880791b8f62367c22a2c09001f555136adb7e2d307649512f57d93cfb4e88607"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a97d23ce5dff1255f2c4d340f80508949b68f11a3e6840207d9d827fc617d15126adf06e366a123c4e32e5d090a95ca"
    $a1="c81746afb91c4f6e777e197e2534d80e345ea73820c148dd5b7ffc4c30482153e85c1850f7c93a15d21319edc7b7e03e"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e63615d49da92d21fe3cbcd3289b694f7f90cd4c4460d6f0ef407fa8fd83dab803096a1c1111ccd1f0bc2c0795f15e1685199926285341a30b1035b8454a5584"
    $a1="dc8734ec38acad7854cfac66c0a1e2c342ade4a2a0ebbb790cea8e0a09753142f3b3d490e4f80276710a790a4b451cfcc02fc35f11c75b00ec03a13f55d6f407"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3VwZXJtYW4="
    $a1="dGFsZW50"
condition:
    ($a0 and $a1)
}

