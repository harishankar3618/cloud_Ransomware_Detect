/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_deerfield
{
    meta:
        id = "17nYnChq9sIrOf3diSKx7F"
        fingerprint = "31f3537f03578fc11b79e8ab987b78ae61fbe8dff3fd8769d78c3adb5af8ab1f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="218ac6d99e55eddd5f62c1d2ede91569"
    $a1="c25c6ec51b15bc7c611faf8f0f7424e4"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11f90232379c898d"
    $a1="085d907b79d9f1ca"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*845F5188B2D48E6D34C0EF9F1009D9645375D4D9"
    $a1="*238E6E3A567B6BBAEDDBFFCD3C25DFCE2ABC2410"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}YOJWCDwe6vXRq5cuLoboYQ=="
    $a1="{MD5}srQQJeZRddrK1B7jz503xQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}/F6D1MVoVhFPsl93GEjoyFrXB8w="
    $a1="{SHA}TuIF/+ufCZjZ4wwpH1qXzBFNuFs="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="60e256083c1eeaf5d1ab972e2e86e861"
    $a1="b2b41025e65175dacad41ee3cf9d37c5"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc5e83d4c56856114fb25f771848e8c85ad707cc"
    $a1="4ee205ffeb9f0998d9e30c291f5a97cc114db85b"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d61ab9c533623038e3f3fe716e6bac41a554d68dd4539aad767d179f3765b920309c1982e1c6896c303cd4b021ee52b"
    $a1="94833b9499a681bf49149832839a81e40b1b3d7cc0f61f0ebc52ee8483fe6c2e4727b4aeb83c147bffec4ef628996ac3"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cb77fbb48bd8f3269218d577d34e108724f242e630617c74f3a7a4f2"
    $a1="f95105ddbab16e472acff5d0276e0a95d61b5b98c065f2740c500a36"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="969007cf547f17098c25450f246323ff75f1f4d9a97c4c06d7e699a8d550834e64532ae64e2d9430d89f2908ef8e1855c9313e3bbfb464dc6a5df4e6a491dcb6"
    $a1="4f592225c67285e75102b2b3bbff9b41733a69929a139658b4acd846fea9c16b8d6c1de3696d46dd1a08bde89e441e7e7399fd319dc85d975215b21016bb85ba"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e2154a35f651ffdc5e041561b49e5ab1da0c9df346b7424c2ebaa9f09dbec805"
    $a1="2df53f17c2a6dab088a618a862f77528551344ec2cdcf5c3965eca8e070f5717"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a17b959819af7afcb478a1962965f59ac90a464ac075a72ffdebc63c97b46f2193b9b6efc5dd7e5a19e08a3987292dd221479578ea6272695a84c31fd2fd032"
    $a1="89b83c415aca676c403c3214115b1a42e181c09d9373e4344bc13a48b253c1bd46b44de36b156eccfa4fc992794fe6820e10f027f4808dfc190e06ef13097cc1"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0cc3a9f807ee07831eb33d0c2ecd69baa292360e1327f9b661e7749187b91738"
    $a1="15c1e0c8b23f515c776ad050607c905477016919d146eda236a0a965af9f3e09"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86eb0ef06720d02e3498575543615265b299901ddd0371214f750d42"
    $a1="6f7192570d7e8585d0a3fe6356b0025c70d459a494443b21c7867e40"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ffddc2231ea407832935a105535bce20dc28ce26fd1c0812e6b47f004b5b0581"
    $a1="00e67d3fef5c31e9318181207e10be6c6b84d52d949f809e231ecb9165cf3e26"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="942778443c50a9adcae42c5ef6ddf0e3364f34be60092bb2058242d6582fd785ea12c6dfc612594a9efbf95c59233645"
    $a1="02051756a91cfe4d2602f7be1b2ddb7dd30add4ae84fe6d9902532b0af9008a03651510afa54fc6b22e004a8c2689e9c"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a79e6179d0dfc10bfd3b7c57077d4512fc878816c8b44e2a3a52dd7f6db18a29c0149c087d9915bbce49f013bc5ae143b9fefcf17bdb56d6215a0ab69abebdf"
    $a1="08ee6a08899afacb95d318e1c1b65963826e12e4a07830a38259c492ef889ba48d8f537b2fbc44eea8e4921e29fe9ff6c3e08c55a416f0182dae3ec3529329a5"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="TURhZW1vbg=="
    $a1="TVNlcnZlcg=="
condition:
    ($a0 and $a1)
}

