/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_xd
{
    meta:
        id = "RSj6s06u7x63R1Tuik13d"
        fingerprint = "b7eab5469a8234dfbc9c6ee9a1c03583229fdac28325fa4fd0116ddb9b222037"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fdf549ed5be3cb67401a826e30af9dbe"
    $a1="fdf549ed5be3cb67401a826e30af9dbe"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="076148c549129c4b"
    $a1="076148c549129c4b"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A09093B3E7489C34BAE7B056A29FDBF5934E3A59"
    $a1="*A09093B3E7489C34BAE7B056A29FDBF5934E3A59"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}fzDu/lxR4a4JOdqyBR23Xw=="
    $a1="{MD5}fzDu/lxR4a4JOdqyBR23Xw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}d4I5FnfDbw8OdzY8fvGC5Odedmk="
    $a1="{SHA}d4I5FnfDbw8OdzY8fvGC5Odedmk="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f30eefe5c51e1ae0939dab2051db75f"
    $a1="7f30eefe5c51e1ae0939dab2051db75f"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7782391677c36f0f0e77363c7ef182e4e75e7669"
    $a1="7782391677c36f0f0e77363c7ef182e4e75e7669"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1b97e4e99e5007c4da5bc1690210ea7d2b3ff152db36b4d338d69e8b9269633df886b1f49e159f7d3386242fec82c3a4"
    $a1="1b97e4e99e5007c4da5bc1690210ea7d2b3ff152db36b4d338d69e8b9269633df886b1f49e159f7d3386242fec82c3a4"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fcbe451836aef8bc0e642fed70b8d473700247e5b61d893689899f21"
    $a1="fcbe451836aef8bc0e642fed70b8d473700247e5b61d893689899f21"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d16e989de5314f3eff5e0c4a24c2bf0fd7f8fe395e713ac839b325a10c4ed1191d1c972c49471efcaa197275b652464fc19007ea5f3542b798c6295b38a2b31"
    $a1="6d16e989de5314f3eff5e0c4a24c2bf0fd7f8fe395e713ac839b325a10c4ed1191d1c972c49471efcaa197275b652464fc19007ea5f3542b798c6295b38a2b31"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cf2283ad6ef0a3266059b418a73f8479338233ea2c4bcd3c1f51c39f13ae7dc"
    $a1="8cf2283ad6ef0a3266059b418a73f8479338233ea2c4bcd3c1f51c39f13ae7dc"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e34dd9ca8281b8dd5e586660dd2c6b69c1a41d6ef44270f34827147995d46150c38347df6dfa8ba36b67094711bff0313b3bc22e6d00282e122020e691ccf8e"
    $a1="6e34dd9ca8281b8dd5e586660dd2c6b69c1a41d6ef44270f34827147995d46150c38347df6dfa8ba36b67094711bff0313b3bc22e6d00282e122020e691ccf8e"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d23356eda307bac840923cb1640c7d3229d050f462b448d0df10bb0679a7abdb"
    $a1="d23356eda307bac840923cb1640c7d3229d050f462b448d0df10bb0679a7abdb"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5232560974d9a8393c6676bd7ba8f6d8477a93e76bcecca658b4a2dc"
    $a1="5232560974d9a8393c6676bd7ba8f6d8477a93e76bcecca658b4a2dc"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf2ad0f559e00f422c87db12b02e39ed0084ebb68b245c3c96b15e17f13d9d18"
    $a1="cf2ad0f559e00f422c87db12b02e39ed0084ebb68b245c3c96b15e17f13d9d18"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa39f78ffe193ce57a4e25068aff4df9ab776c0a58f719aa39d9f0a2fa0a916cb2c0edb6e1767764972fac1bfaeb3815"
    $a1="aa39f78ffe193ce57a4e25068aff4df9ab776c0a58f719aa39d9f0a2fa0a916cb2c0edb6e1767764972fac1bfaeb3815"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee9e942faaf50058e1a896eff24fa39262f08e52d003d2d2e090b9e719b78f1a8cfb8af5d5512dc905a5fc3299350159974fe0f853c3ddcc2eccdc4758cc94db"
    $a1="ee9e942faaf50058e1a896eff24fa39262f08e52d003d2d2e090b9e719b78f1a8cfb8af5d5512dc905a5fc3299350159974fe0f853c3ddcc2eccdc4758cc94db"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eGQ="
    $a1="eGQ="
condition:
    ($a0 and $a1)
}

