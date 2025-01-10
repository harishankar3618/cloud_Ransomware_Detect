/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_fujitsu_siemens
{
    meta:
        id = "6qfQ2PIGKDk4ompMNPmJTU"
        fingerprint = "10b37e0a99589aa80f4200eb1d368537d3b598b70421fac11b3a2137860580bd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f9f7a4752abfcdee30587cfa4c2d803"
    $a1="be85ca9e6c44e05c9b2b50d681186a35"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4dabe5d8230f3da1"
    $a1="5784b14303c3e63c"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8A3E5C2BB0119581EB39CE4344D544910AA0A8C2"
    $a1="*CB59C78E3CCF87352937B994B0AB8B70B39E4659"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}pee2LSqW09wAZ/b9cg9llQ=="
    $a1="{MD5}cGgoluJCh7BHbv8qFMFI8A=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}lWyKnF3OQ8GQH2C9b4f/ANyz3tU="
    $a1="{SHA}Pygvy6iTPgOmWm3JKifeg5aWHi8="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a5e7b62d2a96d3dc0067f6fd720f6595"
    $a1="70682896e24287b0476eff2a14c148f0"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="956c8a9c5dce43c1901f60bd6f87ff00dcb3ded5"
    $a1="3f282fcba8933e03a65a6dc92a27de8396961e2f"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f93d97d9272a03709b2ce929322f0b40454b250429fb2fb3915b2af17c5385008c4aba82acc81e2223348fa7d3dc224"
    $a1="e36acd1ea702a6d1ad8778fd8bac520654e687acb68c19c6b4520d984fd67416abdefc6a2ef6535184e4a29381b9a7dd"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80b7bfbafd6f1e45393c72bc0351c9a6fc8258c02d559ce24b37656f"
    $a1="879f72dd8c12cb2e03273925d27d23a21354668e9917048b17fbcb7b"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31d76799e3d86137c1b9554ba3252bcfeaf44496e84bd251a97e909e07aff3b1fa91c7deb7dfd3c6534c1b4c790d18949c742da853165bf7e2c7c15abe1f85fe"
    $a1="38b6664d0f52faf6020a6959f21ccc36c03d322f61cc6e23d644b6fe5444551c59bf2610ff6acf12a517d2ae18d53db088ec3774bc75cfbc677ca8b5f9ae2fd2"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="45f28ade5d260ab2977678024df5c1b01e6ac2b3b576a99280f45a3e31e3761c"
    $a1="181229424893bb65d94a74c2132b8b9e5adfe851464fdb5cb9f49e8a8204be7b"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a14280a57284b16718c10ba0a699ab2b30c2d32b3dbff62d08c31627c1ec61b6d81d12a6c21806b1e47718af7321bd7d7019d96b8e5f55ec7ab5a7db1b8dbe6f"
    $a1="bdc242cf50e30b58e26c2d8167cd1c3a3cc9b6caf11d44767e77f3f74bad3ab9dbbd2b8ab496ee34ccca381db17c80dd30b38701fdf2e3ebb106afcabc85e260"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c88ee87733fb0e80e02fea1ebb1c247eb24b852d918c8d10f5f0996c37f5c1a2"
    $a1="4c2888149c828966f2116ca786c6b7088806f0d5537944f296afc83330bcfd32"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af27bab819ef5d6366fe52acd4f03a692e11f055d00194f89ff777d3"
    $a1="43fd042a7b13132449c9d8b23c040c2fe030b8447df1781b30cf70a2"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="890da150f32d2db6fc8f1254b1671cec94e3114a453cb98ef67ec942ee744367"
    $a1="03789d1aa662b7e4e363b211f026f6d840912607b7ccdbb5210322d378ce1f4d"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c55252fb45db32e4e921369d697a018eb47d8f11c98b3bc6889fcdc3818557d3c18469bddf61364e06b05b4524a67130"
    $a1="1bc849b02bffdc35def1bc15ff5d80246a34cc2f4ace9baacfbae2888c8f5abdc797b5a46b99dea75b34680cfbeae169"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea25d8aa99547f51d39d88f61528ad06f3d633d73adc03f5a5e4552a5fd4fd67a084644d4983b503632048c508f02909d6c0fd757e37431743a0a8a130452f74"
    $a1="9dde8fdbe67cea1d807f4185e8938ec259b2f1b1cfe45149f023476fcedb4badd97241109ef77130cc4048fed73129e3cf8404a728b2a41bcbc47be8215fa8a3"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bWFuYWdl"
    $a1="IW1hbmFnZQ=="
condition:
    ($a0 and $a1)
}

