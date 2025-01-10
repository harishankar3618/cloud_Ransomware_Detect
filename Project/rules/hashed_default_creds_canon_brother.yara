/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_canon_brother
{
    meta:
        id = "2GWN1QbHE4U489cszgu3zr"
        fingerprint = "aa9411e57ef3444083a5e46f8746a4ec4bc494981dcfb34b806b962304265ce0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8bb80565a55deaa6e1847dc1bc3505fa"
    $a1="8bb80565a55deaa6e1847dc1bc3505fa"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50b4d6d23d0d3d83"
    $a1="50b4d6d23d0d3d83"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*05EB937E16F9C8885963B8F1F2487AB5C94FED2B"
    $a1="*05EB937E16F9C8885963B8F1F2487AB5C94FED2B"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}8ImK+Umjc+cqT2o0tN6QkA=="
    $a1="{MD5}8ImK+Umjc+cqT2o0tN6QkA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}pKqGBWjY8hsBhkdN6rsI3a1wLoY="
    $a1="{SHA}pKqGBWjY8hsBhkdN6rsI3a1wLoY="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0898af949a373e72a4f6a34b4de9090"
    $a1="f0898af949a373e72a4f6a34b4de9090"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4aa860568d8f21b0186474deabb08ddad702e86"
    $a1="a4aa860568d8f21b0186474deabb08ddad702e86"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84ed03820e3111ad984790c0e4e9eb953cd3a3d078534f049f30a42122458edcb7946ac05a7170bd202261815b6d5600"
    $a1="84ed03820e3111ad984790c0e4e9eb953cd3a3d078534f049f30a42122458edcb7946ac05a7170bd202261815b6d5600"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91e9621fcaa79fd534a0dc88a582b8b3d291be88a8a642256c2dd9c4"
    $a1="91e9621fcaa79fd534a0dc88a582b8b3d291be88a8a642256c2dd9c4"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3e8882db900b2665c5fc925bd1ce97d28fe38788f78507c83015c05ead4acad6392ffc3e8b09a469a9769ed682d58cc790be36f64a2ec26d23dcd17dc2f9185"
    $a1="a3e8882db900b2665c5fc925bd1ce97d28fe38788f78507c83015c05ead4acad6392ffc3e8b09a469a9769ed682d58cc790be36f64a2ec26d23dcd17dc2f9185"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe68a21fc76bba7b3a3d8e454eca8cd258de68fd08dddf035f23ddbdce6fc049"
    $a1="fe68a21fc76bba7b3a3d8e454eca8cd258de68fd08dddf035f23ddbdce6fc049"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17d7776c04f7cec80d710a6100cb73b6b4297236a61d87c62afe091ca9778690d452e3b97695e2b85dd872e24e085ec5202c4ad8d527a8aa0f58632848a255b7"
    $a1="17d7776c04f7cec80d710a6100cb73b6b4297236a61d87c62afe091ca9778690d452e3b97695e2b85dd872e24e085ec5202c4ad8d527a8aa0f58632848a255b7"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e49b803840d834b33c71d5515de3271dc9037a78aa42b56e733c6414ae50d15d"
    $a1="e49b803840d834b33c71d5515de3271dc9037a78aa42b56e733c6414ae50d15d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a3f1b3ad11d4ca0f70879fae6039661fae7930dae6a82cda800b842"
    $a1="0a3f1b3ad11d4ca0f70879fae6039661fae7930dae6a82cda800b842"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="362d9bc29a188856d30b9c2fcfc4dde7dfbca9a22b415aee884d471bb4074327"
    $a1="362d9bc29a188856d30b9c2fcfc4dde7dfbca9a22b415aee884d471bb4074327"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fdcb5d0c3a29b9fa052bd1ee6e24a2f5d22871f87f8e655c6adb30e17d7a37601343c7a6abb41a7c126c64f81d7eaf35"
    $a1="fdcb5d0c3a29b9fa052bd1ee6e24a2f5d22871f87f8e655c6adb30e17d7a37601343c7a6abb41a7c126c64f81d7eaf35"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="210ff9ba45400c38132689d1cf71e3b077947830835ddbf675d59f3ef191e3ab89fe4687b43a08aefc7c029df5c9e711836dc7d2953c9b938b100deb794ce3a6"
    $a1="210ff9ba45400c38132689d1cf71e3b077947830835ddbf675d59f3ef191e3ab89fe4687b43a08aefc7c029df5c9e711836dc7d2953c9b938b100deb794ce3a6"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="NzY1NDMyMQ=="
    $a1="NzY1NDMyMQ=="
condition:
    ($a0 and $a1)
}

