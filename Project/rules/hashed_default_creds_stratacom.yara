/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_stratacom
{
    meta:
        id = "3ds2P4z7Y6iTipYJOl1utQ"
        fingerprint = "7231ae414edc2871f4ca48622c972301be2ccbe181712f30519c467480574e40"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fb1aaa778851d8459595ce00a412ee8"
    $a1="accf3448879525c02b72f9d983c9540e"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="52486b207220c12c"
    $a1="12dbb6c464fe481a"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8E79ADD2FC35B95DDA40D66AEA414408B0935017"
    $a1="*3E48893BA0EFF602B826835FBCA550DA50BCE1B8"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Cc8j3Hj23G5rFvfGeGrVxQ=="
    $a1="{MD5}68wRSkXOuMkxL6jCdekBOA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}paokjo7oAqlYJm3QM3YAwQ0/7+s="
    $a1="{SHA}yoT3s5cy3E5MrVhRTDUH7DNBChw="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09cf23dc78f6dc6e6b16f7c6786ad5c5"
    $a1="ebcc114a45ceb8c9312fa8c275e90138"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a5aa248e8ee802a958266dd0337600c10d3fefeb"
    $a1="ca84f7b39732dc4e4cad58514c3507ec33410a1c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e85d2fdb8cab77a9bac7a917af0c70054b4e912cd654abb679ca059157f386bf534a808a0b6bd2e0a00f99a9dd6d8d49"
    $a1="dac32cd47547c127b8724766d1f4b77b9ea53639e84c7d07268f6969aea80513134ae77aceae74a444deb3ad62db1f3b"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc05f990c1fd59d5205293b9bb7e27193e796d26baf4b5fc81921736"
    $a1="8dd6ba06f79ff869e7c8f1b339cda5a03f61cb7fa7f52ed2251680b9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d33938cbd0dac04f6e8e64917eaab5ef17c690939b0361447c5f70b8d2c8970e382104cc071452f3d00f7832a655aa5179a788fad06851cb5d4dd0e99da0c54f"
    $a1="353fef828b97f476d722500f1ea85dcf46107f789145b3854ce5c7a9a341da1d2c7a3d50095888d9d93f4caa075ee198a3a9d72353d5748dfadeb2b838c77809"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b007a1b653efca19ed81702b270e6cc94ac78c739c8e92b7636930fcea20bde"
    $a1="928dbb18ffa58ef5541af2eb6f134bccac2b5cd99c9c7bf9cf9415114d505181"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a73e624e5f1539e285c5913f236c6abe07863948cede2a29ffcbaece100206952f439bf5021c2ad3f2c1b0a360acf93046f04697c2943a920906549ffd5f169"
    $a1="45c70ac54f2bc07ee2f2ef6d5bfa419b73bf9d5d3ba10f5b046bb8802ecde33e4df42faab1ee3454213a6d2496a9a9eddabeabfe024b99a54730b853f8720e88"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4735e3cd0823bd8f7a686744446bef03523c0c998016ca31b6dd53fb84e15b84"
    $a1="9f72eab1d44d592baa2244a306e38d84ff14875bb768060c75832ce873a22cae"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3cc104ff0fb2fc24dca9fb070b345992f7dc937bce23907a694cdef9"
    $a1="65bf012c41d3550a376d4dbc8ad04708040c88f52150c02bb654aa05"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59704ae14dd3d4ad331b2e058426998cfb93d921adc38b61f3460d81619e0979"
    $a1="bee935851f51f5e0434b5b7fcd10dfe137ec896f05d0b0c24d84fdba6c228dc7"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="202310c64c6018f2d20bffca56af176e3f761f460a61239b979ffebbe0dddf625a1e0c0716b1acc5314738983dfe0e17"
    $a1="a36dc138cbce7b094201aa2e5b8b744d7042ac9e012df98a50c5e1c109d2ff4cbf8cc505b16ff5fa937ad17f13d164d7"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14f9a0c1b9a35eec9d6c4c6fe4c6def00413c26ba1f0e6b9efcddd51da084b7ee395be21a08dd7259a00ecd6b48abf520fd043d5efcf74ec08db30956c4497a5"
    $a1="bee5381af343c00b4c1747b4e5e64373fe2cbbeb53c6d01adfdab16ca6b5a3ffb1a3297fd7d97877f4b715621d2962188b1e100624482d80fd594f2ee762e108"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3RyYXRhY29t"
    $a1="c3RyYXRhdXNlcg=="
condition:
    ($a0 and $a1)
}

