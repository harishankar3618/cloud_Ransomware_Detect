/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_pentasafe
{
    meta:
        id = "36DGG27mlaMHlEQU2BAgxw"
        fingerprint = "50ecc52c512b756317bfb1eda66379a7b69db90d84f0f37075724fbaacb15c8f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53f7294c5b0555d0235839aa7f1106c4"
    $a1="7f93957f8a61679512bfb7fe4464af88"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="555dbbad3c3ddcba"
    $a1="21f3b4b34b7a4913"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*F452EB699A429536F28373E0AF007D362448D71A"
    $a1="*076B40275B2A6D338989BADC7026D898CF8BFB95"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}hTv6gyay4hDNBqIrkw717Q=="
    $a1="{MD5}odx8EhMmdns/oZL1/Poo3A=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}q5c2Jlj+sMbjaiWTWEfAs+egIrw="
    $a1="{SHA}wNu71/oUdqpW/89fxoVmh/QXsow="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="853bfa8326b2e210cd06a22b930ef5ed"
    $a1="a1dc7c121326767b3fa192f5fcfa28dc"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab97362658feb0c6e36a25935847c0b3e7a022bc"
    $a1="c0dbbbd7fa1476aa56ffcf5fc6856687f417b28c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e67384b0ddcd5d516cc517620d5a4dc2442625c7e42ca906497618256c42ab1fd2a2dc4e3cfdaf7e5f9f610994275528"
    $a1="0784ddfbc58bcf94b03148c9d1bc3464b127130496e7cf2a9bd3b14dbc9bcf7337970b58299611b81575398a922d8a3f"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="55c9f49baad49f1bdd9415654f3ff31e8903900d33a5564940d029ba"
    $a1="3c1b886c848af7694daa1bfffbbd67d24d0849fc6de995130b25b077"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bbb8c28d14e3fca965ebcdeac99f21c20aa66a3eba2aa8011f3428c00cd3bf723cac4ba7ec2593f4b398aeaeab53d7faf31e00d900d9ec8f0e7974b4259e208e"
    $a1="ddf008606d4eb46085ed7f482458c446fe9a948e8646c52e4cd91eb3f7dbdc55cdb40c891cead818f3cdbe4ad41e90c24cace8b4e9c56bfe50095dc84e0b2fe3"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="191cfcb01608c78c79ec7930a94362371425cc160bdeb49514979bf0320c7c83"
    $a1="81a9cbcc4d2d6d67ca4fe9fc94b0951a053413bd35e5315c5adaf882f4071c10"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61bf23f0df01a47595974a1ca3704a5fb3011d2b90813d0315e3f3dfbd4d7fbbe28bef6d0a5de61c41de419ef6211d7022930ced5988a3e1ee11cf06e51c65dc"
    $a1="4db09a7e6bdf4bc7c98f149aa63e43635da9f9051aa622585aed3cf5ad4c521717a9587c1d371e0b3c495f70077178ae7b7a1e87b0076a28dbcdb014744c63a7"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05fcbec413a532110804f8287e59c0a2947c42ea4d40d1b798842269b3d8fa86"
    $a1="1937fdb63b6559ea4df8468303290fffbf1e89bc597f7a03fa915d368c1d31f4"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1599a41ef24b84e81d72e5ffe03f5c46cf9a8b57f69028c5693f81b"
    $a1="cf477bb1d3037f2f398a5fb986c5755ce421df1f6541e5cda9a81904"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e277b0c159eecb6f5b182f7add62825c634d440a232791c74c53d9d884df8e8"
    $a1="4f55dd09d3799a5ae817e1d5fb5ad139c414b62fc0a3d8d225444042c377e25a"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="289b191ef2cee28776b6f53c49602880724c18fb0e5c054f172704d9a34bd066f06e8cd672f256c2bd875b432be0f011"
    $a1="afee720e06b2a5afd21a8b88287283a920685cbb6969c1d18c47283ba95b6c6d66e3c1d7ad6535205c825d0e0e757442"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="648c1a777cf9b02bf3747c924f13d4667abbbdc66f1d0623d13f4ab477f185bd3010962322dce1fd5fb853a8b9a5df90cde9b4e14e81a7d5ddf3468f196b03b4"
    $a1="7b6195df2506e822a6d321a6c564f6be238a28e41cc7b7cc7477b11b552b004921e1b38d975629769b55a787b31748e0b5339c92ad8db535aca5f9d88c3fe19f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="UFNFQWRtaW4="
    $a1="JHNlY3VyZSQ="
condition:
    ($a0 and $a1)
}

