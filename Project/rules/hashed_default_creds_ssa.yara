/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ssa
{
    meta:
        id = "1DwgVBZ6YtskafkqKq6GoK"
        fingerprint = "e6662b99425688a714b0c7e8d5701cf5467c9792fbeacaae0dd4097108018d74"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dca72a6547c6d2321950afe9b0daf41"
    $a1="8dca72a6547c6d2321950afe9b0daf41"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f39aa2d26a4909f"
    $a1="7f39aa2d26a4909f"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C3BF5E643B3992E1928E947D6E709C16EDFB1645"
    $a1="*C3BF5E643B3992E1928E947D6E709C16EDFB1645"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}fJ1rABqH5JfWuW+9TG/fUQ=="
    $a1="{MD5}fJ1rABqH5JfWuW+9TG/fUQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}I7tqpgV7SVsApM8Hb1Ti4D14YnA="
    $a1="{SHA}I7tqpgV7SVsApM8Hb1Ti4D14YnA="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c9d6b001a87e497d6b96fbd4c6fdf51"
    $a1="7c9d6b001a87e497d6b96fbd4c6fdf51"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23bb6aa6057b495b00a4cf076f54e2e03d786270"
    $a1="23bb6aa6057b495b00a4cf076f54e2e03d786270"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ef2a64b67a399f73c1e5d12fdd259a2329ae2c6b403e432973b9c07c6f80be9238d940850535c30f74f254f037748cf"
    $a1="3ef2a64b67a399f73c1e5d12fdd259a2329ae2c6b403e432973b9c07c6f80be9238d940850535c30f74f254f037748cf"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d4fc2c43e8b403dd8b25f24b8dd85351fde69aa9f75efd1bc2bb3f47"
    $a1="d4fc2c43e8b403dd8b25f24b8dd85351fde69aa9f75efd1bc2bb3f47"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="211b0236d991cc0a1eaa6f76fbb5f16fb3a828e943420ce003ecfca4309028697fcb47f55617bdd26b630a9b066d994f25854515ffa399ceb83a3cbeede4f8ce"
    $a1="211b0236d991cc0a1eaa6f76fbb5f16fb3a828e943420ce003ecfca4309028697fcb47f55617bdd26b630a9b066d994f25854515ffa399ceb83a3cbeede4f8ce"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db7fe17869dec0238836e15641f3236bc0c969dc822d251acc5ee469778cec3d"
    $a1="db7fe17869dec0238836e15641f3236bc0c969dc822d251acc5ee469778cec3d"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b17c17fed5e20da9907f5c22daf2de2310758bb78b2479dc3278abb045426f80f945ce64911abd789fe4e14e981b7e9f38e89f4458129723e5f0041d98d5e81c"
    $a1="b17c17fed5e20da9907f5c22daf2de2310758bb78b2479dc3278abb045426f80f945ce64911abd789fe4e14e981b7e9f38e89f4458129723e5f0041d98d5e81c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8db46948d8c0f796cb6029387db6f3d7c4b98019c91598a1211e1f5833edc46"
    $a1="e8db46948d8c0f796cb6029387db6f3d7c4b98019c91598a1211e1f5833edc46"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9aafdf73bbc88a244d14ae8cb81183133a9de1f7aa791eca79d8d1b8"
    $a1="9aafdf73bbc88a244d14ae8cb81183133a9de1f7aa791eca79d8d1b8"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="864636fb9a29ce0369ab755c513affe71d3430404661f5be2d6f3f2cfe6283f5"
    $a1="864636fb9a29ce0369ab755c513affe71d3430404661f5be2d6f3f2cfe6283f5"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8351f9f52ec352d4d182386e39ca40740290c6fe714b274d9f108764da5e722b40cd48de773a061c4ecffd6868558501"
    $a1="8351f9f52ec352d4d182386e39ca40740290c6fe714b274d9f108764da5e722b40cd48de773a061c4ecffd6868558501"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f13ae629d2f18805bac5f213695962fa809736ce19af84dfb3370dc5c7bac5d39d076533c0d8d30a238d58cc250f680948a7c6728b5c7eb0ea68aaf4eeda2714"
    $a1="f13ae629d2f18805bac5f213695962fa809736ce19af84dfb3370dc5c7bac5d39d076533c0d8d30a238d58cc250f680948a7c6728b5c7eb0ea68aaf4eeda2714"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="U1NB"
    $a1="U1NB"
condition:
    ($a0 and $a1)
}

