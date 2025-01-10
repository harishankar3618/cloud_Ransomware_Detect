/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_t_com
{
    meta:
        id = "nhA2gDqYAl4XZVwnSHZcl"
        fingerprint = "5a2021e9afbcc5f98a84609b004827c9b97bd0d9f5dea9a3ba3efc5bc1974491"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a1a58a99e7bf3ad22cff0ff981627f2"
    $a1="90ff121c8e498219861617c6bd7e6af4"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="293db20911086151"
    $a1="59a3d1da2be58782"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B7181D83DB671CCA235FB754B927809B2D97F2A9"
    $a1="*044EE488FFD3A45F4C5B44F6323D5114A5D6F255"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}8blSjV+1wnLS8FpbgmEbPA=="
    $a1="{MD5}8y7E01NjX1fkyyGSf1rfng=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}SU+wHR+xs6bPzKwHDZ7X2w5YJDE="
    $a1="{SHA}UA6hGD76FOLEREFeEBTQ/pF3C1w="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1b9528d5fb5c272d2f05a5b82611b3c"
    $a1="f32ec4d353635f57e4cb21927f5adf9e"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="494fb01d1fb1b3a6cfccac070d9ed7db0e582431"
    $a1="500ea1183efa14e2c444415e1014d0fe91770b5c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a25c3751cb99ed6a857e55fdee8bebea6cce9972bccafeba756925cacc73cdb0dada14d8ebb432fa00f54408029a59b"
    $a1="589d0f5f0de1765831ff140d5489f1374d0f388958ad525216e46cd04ac1e16254a5ce5b3cf6d33a7077d2f7ae8d6178"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1318ab868e38caaf8ba330f78c258a1d310e5463cbaf07fb9f76acb3"
    $a1="cf8549570c3ccda5a0e55701420a08cd93c2d1fd0843b66f074bab93"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8dffa78639cd41e5b3fb86b5953374babb75b429f83cc2052d653212972f969ca9cc45dc9833e7a97cfd4457ad09249dc607bbc09d315b33fa5ba556639822f"
    $a1="3d409d00b4f1463d40af7a9076cc03f1f427a8e5e4b04fe5bb386ce7d0aa3725d809b7135383d9a9432ba5c3debfc40f2699a1ddb510711e5de06ba6d55215a6"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90a2b51b1e75d226f56e57edf479e5ccb8b4d70ebb134ad2be772badfb9ea67c"
    $a1="6220b3e1f255f8e29b87488abab1bde126a6bbb44c62bf9b297b3d20347f8b4e"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97639409cd26aa0187e363502f9e8ac8c8df1d29d77e6b1e242e4d778c37de9a67c28ac6df5d06523d9e9c71d05ec4672a11bf22283c33eb1ef9d0a43b5084f0"
    $a1="f9a2525b3b0767c9cb99ee13e93935371017ebd3ccfdb23314a8b67aad425b720e3355c711ed32a7051299eb4a10a75a9951c72e59847e86849f2aa0d8d74e40"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4d76b8112a99322326d0b76c5c48a3bfdee46f46a4e1e40f61f62676395e245"
    $a1="5055e509ea344acb93ca6d3f8906b55081d50d353c179cbb9184063d37b9390c"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d9bb61e063ef4932a2b54cd0f43eb5d304c22595ff2f1399c8d4db70"
    $a1="94d80edef91197499488ff45f07e0a61fbb7d7dcb7110b3f2ba75a51"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="78862c046d1f4decfbb5d328419fc114056968458218e459ca691f77bfe2e901"
    $a1="93512196dfe5353417edb53da86a3feac1527163d07f32af13a9ae30707c48d8"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3585407605e2829c3c05bd9eeebbf1937964118376dc2ee7a80f526ad453d2c05be1fbcb94949a04e074392520b4ed63"
    $a1="48d4dcaa1018f1a9985dc15277b4df6148b5528ed6220fee6ab75bc30a7d996e4703532d5d5be61a00c3f8de676512bc"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c8a9532ba293aa52622af9eafc355033a0c338332dab40f7d2eb0d014e51e10fb9c59e6512c0ac2574429ecfb5004e1da0d45359b050d05e861c1b6730cca2a"
    $a1="87bafba4e031e3cf652e049c75c3975a1c822bf6573356a4a58c2945b76efe2c80c2b3f7490c35dd1b371cba158d995110e80713708b1b1f82f6fc523b0d3995"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dmVkYQ=="
    $a1="MTI4NzE="
condition:
    ($a0 and $a1)
}

