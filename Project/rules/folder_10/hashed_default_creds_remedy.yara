/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_remedy
{
    meta:
        id = "6nhKdgJaX7xBQscqxBF5te"
        fingerprint = "2d54901f8025e37751f5280708b3f2e74122ca582cc0321cccdfddc0d78484d2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47bcaa29839fa166a62a6e98639da51c"
    $a1="8c79c0e8906674cfec9c9bd7ad13367c"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c4f07540556b6ed"
    $a1="258840923783b6da"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*07684B9E9AE43028173DAC9AEB998E68019CE691"
    $a1="*7713D2B0D459BBE104E880A885B70FD31B88776B"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}tIY2VF5/mcQ4V166K/VLWw=="
    $a1="{MD5}godW5iX/F52l/y9ITjEBVg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}VMviS8DzTjUMW0m0l2KgLzEBIvY="
    $a1="{SHA}Rz1KQn8/5oAhpN5T9lhUys8gObw="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b48636545e7f99c438575eba2bf54b5b"
    $a1="828756e625ff179da5ff2f484e310156"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54cbe24bc0f34e350c5b49b49762a02f310122f6"
    $a1="473d4a427f3fe68021a4de53f65854cacf2039bc"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99e25df9a9df23daf6c88b3d6026b406b0317189bc7b46d017aae3d9ea3f934747ed17c1b19d25b81cf75ccef57af520"
    $a1="e6578b5e0b2b7765deee809fdcdb776cc1887958830aad0894e76b62d56c1872a39252877cde9d8964fa8e00c446843c"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ee5ba6fb99f33d399a4cd309e53d985b64dc17ba10b24af85220bb9"
    $a1="ed3aa205763faca52666faa7f51e20d013f2f6f7cc4048dc1441d3c5"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1dfe7eee12f7ce4464aaf82ce5ebc0cce393942642a85dd40af57178479fe39674c06d4ca5bdfc9970396b5c12aa54c088095c7cdf2a8b7bb4b3f0e7e3b01425"
    $a1="f40435d34eddfbe0f417b8cf3b221ccc6a8cbd95dc46240bc1d6d8d7812efd3448184ce605ebeb621715307f51a017497cb33807306ad340e74d6dc910235f4f"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d70230cc4b3c134b818b70ea04e061b80c68515237ea687cf935e0fb2e747c4"
    $a1="eeb1de5e38399c53af776369808a9b6b8d73682a51fa39ff1363ba20cb4d5032"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="32acaf528294e9f37fcb1f1e147a5951e76ade3ee935d9924c228e29a21231b8e30f369a575512f38182d18760509431558a59f9a423f381714997d1b134346f"
    $a1="9e67456dda5d07395c38c8c8f789d830ab93690b1252c7a9cafbf4ae78853bd759b6f9e6da7a1a9fb8f57b3d49f1c4ffc749863a3871e8112643ef8b62eb095c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7de058acc11640629e1940d47348a03f2db90eb95afff99a824d53b949a7032d"
    $a1="cbdd5921bbd6372236e3d8ffc1990c1bbf2bff8f89b35a3726dfa15c0e47e5ea"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c91f674025e3bb73a507f7d6ca9c739408d531d738cc7a16fbcc9854"
    $a1="a9303751e638eb7e798d1aad0711df288906a1ebca2ef6f856bc741c"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a871cd4e7a17d4d7e77ae38f8b7d82c0b4857cf0b6e3647bc9f498f4fb191571"
    $a1="abafb3efd43be953e6651a13dc797d09e799e68fc6172983374d38ca47b4e4d8"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2dbc678d2b0ef9060ed75187c0f8262ac6111382096bd247571f75329d8c4da88aa75213d47794386ae2b4d0b64907ae"
    $a1="c41d308c572bc2aa6574a9fd8dc7fe268550ddeeb4e049b8508f6780198c13284f32b3a0cb1f91b44d6ab0eef22f4bce"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ef7e5953feeb9588e6916882e26695aff6cea2f442556bc25bc6603a95fc5efc1e58c6573edf215d296ee93a325925f7ee32eb64cfdf274be7670bdfe5d600a4"
    $a1="21615caf63a7252caecd365b3e538fb27a66bf184a1d0f79e2081eea0e03d5ab3b1e232e8d8295bd7aa06cfd295900f65004c55dc9e37a7a56c812293dd78fb6"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QVJBZG1pbg=="
    $a1="QVIjQWRtaW4j"
condition:
    ($a0 and $a1)
}

