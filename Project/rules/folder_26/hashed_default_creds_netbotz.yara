/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_netbotz
{
    meta:
        id = "7k4nw3NyTipo33aJVANU2o"
        fingerprint = "d3c70ff8508ee355f3d418b35a22b8f58228669402f3a3806916c6602663bcd2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d965caef1b124adeddaa40dce50e6f9b"
    $a1="d965caef1b124adeddaa40dce50e6f9b"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29f193a8119c3239"
    $a1="29f193a8119c3239"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*DDD507BCC98608403408A1A75ABE3D9E5994D949"
    $a1="*DDD507BCC98608403408A1A75ABE3D9E5994D949"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}xjvslR0phhbiF6G1qG4saw=="
    $a1="{MD5}xjvslR0phhbiF6G1qG4saw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}v8VqhPkhLvHhiH0MlWWglOn/b/s="
    $a1="{SHA}v8VqhPkhLvHhiH0MlWWglOn/b/s="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c63bec951d298616e217a1b5a86e2c6b"
    $a1="c63bec951d298616e217a1b5a86e2c6b"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfc56a84f9212ef1e1887d0c9565a094e9ff6ffb"
    $a1="bfc56a84f9212ef1e1887d0c9565a094e9ff6ffb"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e4cc99dea57495940c4bee645c016f3088560c42259cdf8fc7edc4db43a0190f5e60c84023802b7797cb6ceb0f7aeb3"
    $a1="7e4cc99dea57495940c4bee645c016f3088560c42259cdf8fc7edc4db43a0190f5e60c84023802b7797cb6ceb0f7aeb3"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21616385c30d1c51a7b5ed11c042503adf2d2b374a9cad0cb8b34417"
    $a1="21616385c30d1c51a7b5ed11c042503adf2d2b374a9cad0cb8b34417"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9726a7d64d06944a70e07628223540ec86534ed18f8332990e60fa8deada98046acefbcf7e9c3e54082a00ac6ec499b264f0f77de6601a1fc170b57ea2b479d9"
    $a1="9726a7d64d06944a70e07628223540ec86534ed18f8332990e60fa8deada98046acefbcf7e9c3e54082a00ac6ec499b264f0f77de6601a1fc170b57ea2b479d9"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56ea8a8c7bb638399b7fece5e35e9e2a68933d021f1ac153dcf3fa448c4a2238"
    $a1="56ea8a8c7bb638399b7fece5e35e9e2a68933d021f1ac153dcf3fa448c4a2238"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="461bc42bd3e2d8bdd1a6df215eb8ea1dd9d1f0077615bba69c5cae5d449ad066db0d1b88c3e5d343eb01625ac324c7cafa724e2c0ee6072cd2c917a76a3ed959"
    $a1="461bc42bd3e2d8bdd1a6df215eb8ea1dd9d1f0077615bba69c5cae5d449ad066db0d1b88c3e5d343eb01625ac324c7cafa724e2c0ee6072cd2c917a76a3ed959"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="07fdd99d5e44b5cbbd0a665c2fe9098d4adea4c9e01a20979518eef220f0086c"
    $a1="07fdd99d5e44b5cbbd0a665c2fe9098d4adea4c9e01a20979518eef220f0086c"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8fc6bdca98e7dd15834e3f50b203bc92be7f79c48d5eab77a637885"
    $a1="f8fc6bdca98e7dd15834e3f50b203bc92be7f79c48d5eab77a637885"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6e83bc505c8e3191fe09eeb207e7343681e33dbf258cfa3e2257bd33c6e2c29"
    $a1="a6e83bc505c8e3191fe09eeb207e7343681e33dbf258cfa3e2257bd33c6e2c29"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e081fae0567fcbf4c11bfa5d43e06af76928327bba6983185be1c2a34f7772a214921305504ae0ee0eeb8c8094811fb"
    $a1="6e081fae0567fcbf4c11bfa5d43e06af76928327bba6983185be1c2a34f7772a214921305504ae0ee0eeb8c8094811fb"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09a56f64f8710eb25238d72a7f0733f1794ec8e15b94a09292173103f10bf8cadcb07c026c09034f901ed4a461b5ef6bfa359545890bcdf89f4116df22e0ca2b"
    $a1="09a56f64f8710eb25238d72a7f0733f1794ec8e15b94a09292173103f10bf8cadcb07c026c09034f901ed4a461b5ef6bfa359545890bcdf89f4116df22e0ca2b"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bmV0Ym90eg=="
    $a1="bmV0Ym90eg=="
condition:
    ($a0 and $a1)
}

