/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_emachines
{
    meta:
        id = "1trGeGEZw91jKQbNvTtrbu"
        fingerprint = "5196d2d55f352abc4c8444fd105e1dd32ed526deb2d6acef914172283179d3e8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a84d93ab4e65b1b051ec624bca3c6096"
    $a1="90c6636db0d310f5f82ccc19ec04979d"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="002aba1918c7519a"
    $a1="4de382da38d5a265"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6750089E52AA8F2AFCF7BA0647C6AF1773058AAD"
    $a1="*3FD8B513E981B33E3705E4AA0A4F88C07334438D"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}sjMPxFMd4TUmbeSQeMJw3Q=="
    $a1="{MD5}o9gd9LYavjosjFHEDT0PXQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}hmmMLhllvAwsrq8/CzTAvYI2yhM="
    $a1="{SHA}64qShqQXiKpI6A6V4H3TQXT+LBo="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b2330fc4531de135266de49078c270dd"
    $a1="a3d81df4b61abe3a2c8c51c40d3d0f5d"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86698c2e1965bc0c2caeaf3f0b34c0bd8236ca13"
    $a1="eb8a9286a41788aa48e80e95e07dd34174fe2c1a"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d4806e5e71d6ad488f20da6a5b79c02ff89dbf2ee8df8ba2748f15c97d72b312548eddff67ae5478c197fe9b295ce4a"
    $a1="9a260a075db502a616c8540ff431e076c95172249f5123b2aa8103e3a36c13da5fe0a28c5ce9d954e1d56bb24fcf3185"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="57004bda1bec239caff1bed900dc69ed4eefc3e56a0fe6faf4af6f6a"
    $a1="5dbb86b08b36189e8301abc1355b122e1bd3a96c8728ce6b23c3f9b0"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fcfd7c8a306a34d388c4d6436224221738902ae7021fab7c597be77d4b51ce0455901b288c75b7fb916e83c59d11d82bc8a833a9577e17cd85c22d27b446d666"
    $a1="162086dbf1fc8beee5e8f625279a9620d782c1f6d16e1fba27ac01a02703e5f4588116c866f94f7ee07cc72740b8a32c1822695a0614ec9ed3a75ee586195cab"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a07cf27590e57bf851029cada1b752019189ba52defb3e43401887fcb2489b5e"
    $a1="a61f125e972aef2fbd9a00f7c8e2fbf9c6fab4889821742d76789826d1c1f9b7"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="687549276dae445405f821f9a1d3c2a886bba383a0efecd0e8f90236e9c4e5b80b0d836ab8223c1f0beef263eaafe146996822fab57489d35fdd530ef027e77f"
    $a1="4c04d5b478474dedc75b5af52560718ba9a30f64e558bc4a1a91630d11bdfd6b85f06e1ffcfd7143692c335f8e9765eb67d5250b82f6e1fb7c313e5146fd2da2"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2d4ce46fedb6a35900e262eeacf69e4791e72aea74197c21efb239386c238b02"
    $a1="aee78f759dde4c1a14d6d54a2e42a78cb3fef9924a2db42953a8799b90ce8335"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d9d13ac56c510a6821eb764f0c7df7ea29fa5b4d2aa99f50af426eb2"
    $a1="0a269f3ffd7b23936043adb3b7d6982c40053467a94da84ddcbf6d6b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af150451dad13e62e51a5013f1251b0036cab8c2be852ef6d1ad3a9dbd880a13"
    $a1="9aabf55861738adec39ad8c97b79b5a5f4f702242e4eb5d8f14c2842d5a6ca77"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37c2b4141680be6187b9b40d80f5c03466c5c0627a193dc2587b7dc27444fb0e1e270f85c2002b50aebdc6f633416ae4"
    $a1="0a7454e6283787a6094d5d18a41ae5d9df58c6923bd483182d391a6fe6f5e177ff0004774c5e341d32b07e5701d89528"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b9202aab55055d296965b3c0a8a590bf58f8727d5f810ec3f3322b440d5f7c03517151ab5cf9a9bdffbaeaf01a74376e6b7b8306ddab36311238928abb8a35d2"
    $a1="c8fc64cdc6ad7e2223b7410f869a0fb0715b43bdeb4ed6f6d85d4971064ebabdbd54edbed500b07eb3fb2f4b6948398311bd963761d531085b35ad508e4083ea"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZW1hcQ=="
    $a1="NDEzMw=="
condition:
    ($a0 and $a1)
}

