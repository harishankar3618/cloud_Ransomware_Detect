/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_trafficware
{
    meta:
        id = "3BQABCgXvKVJoy8XJmNrOp"
        fingerprint = "aaa4648d9b47a651741f916fab6a3e30caef402705f9feef79b1d280b4cbeedc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d9f418b2c1c2f623b4720d02d556bef"
    $a1="8d9f418b2c1c2f623b4720d02d556bef"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="223d8fbb694dac56"
    $a1="223d8fbb694dac56"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*86A35E894FB4467BEEDE5C2F053201600B0555D6"
    $a1="*86A35E894FB4467BEEDE5C2F053201600B0555D6"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}qXglER6Lx8nIoKUo69QDAQ=="
    $a1="{MD5}qXglER6Lx8nIoKUo69QDAQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}YS1vqmscEKmDsW5UKFeDx8U6PQ4="
    $a1="{SHA}YS1vqmscEKmDsW5UKFeDx8U6PQ4="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a97825111e8bc7c9c8a0a528ebd40301"
    $a1="a97825111e8bc7c9c8a0a528ebd40301"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="612d6faa6b1c10a983b16e54285783c7c53a3d0e"
    $a1="612d6faa6b1c10a983b16e54285783c7c53a3d0e"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d98035438b2214ab2b6caafd49b589917ffe1a28d835cdfcc74233671cbff458674f68be22da5981816cf01851e10dfd"
    $a1="d98035438b2214ab2b6caafd49b589917ffe1a28d835cdfcc74233671cbff458674f68be22da5981816cf01851e10dfd"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="373721d53ed5466f9cd82ba53f0f16768f062c89a29193a37c4ad2ba"
    $a1="373721d53ed5466f9cd82ba53f0f16768f062c89a29193a37c4ad2ba"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50b811112b2d418b9c2f2270a4f97e4947a4c0aa1ec92ae4d78c71f6cc74a1837d6a6bc129ac95f114656f0152678a0ce29070123517e4b1cac2cc8993246786"
    $a1="50b811112b2d418b9c2f2270a4f97e4947a4c0aa1ec92ae4d78c71f6cc74a1837d6a6bc129ac95f114656f0152678a0ce29070123517e4b1cac2cc8993246786"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa261cba4de96577d8568f3807e73a28389fa42cf0146bd40fc4273185653410"
    $a1="aa261cba4de96577d8568f3807e73a28389fa42cf0146bd40fc4273185653410"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="beb79815dac210945116b7a33b33521f8981f6f615fc72865d8a51dd7a5711f9a8c895a8d849b3265b6e9cdffce2cbdfa9cc88fe89a7a5ba923a84718ea3f14f"
    $a1="beb79815dac210945116b7a33b33521f8981f6f615fc72865d8a51dd7a5711f9a8c895a8d849b3265b6e9cdffce2cbdfa9cc88fe89a7a5ba923a84718ea3f14f"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dce4c0bc28ebe91daf7cce528339b1ef6339fa012f4510b4faaf20a14d071edb"
    $a1="dce4c0bc28ebe91daf7cce528339b1ef6339fa012f4510b4faaf20a14d071edb"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d84c4fec1a315809b5176d3ff4dd2d50683a684414956295abe936f"
    $a1="9d84c4fec1a315809b5176d3ff4dd2d50683a684414956295abe936f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f97ff344ca030efffcdfdbb49eb4dc63ba28b63ee98cebc68a4655f790b486be"
    $a1="f97ff344ca030efffcdfdbb49eb4dc63ba28b63ee98cebc68a4655f790b486be"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc0d2758f237e31a33ad470e0955291b32811288dd6b3d7331d476920fb8ae38a1fb59f7ad07b0bc598f1acef93f4c48"
    $a1="bc0d2758f237e31a33ad470e0955291b32811288dd6b3d7331d476920fb8ae38a1fb59f7ad07b0bc598f1acef93f4c48"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76e4a5dce3971027fb573f48dec3cabbd3946f635c9bed91812d0f99a14178551db0999135016f8b03d9949f03f49b4f6f6aba120b178aae6d5aad38192bc4bf"
    $a1="76e4a5dce3971027fb573f48dec3cabbd3946f635c9bed91812d0f99a14178551db0999135016f8b03d9949f03f49b4f6f6aba120b178aae6d5aad38192bc4bf"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bmF6dGVj"
    $a1="bmF6dGVj"
condition:
    ($a0 and $a1)
}

