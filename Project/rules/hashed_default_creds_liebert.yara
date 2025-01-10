/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_liebert
{
    meta:
        id = "1ZJyDgoFH20mHHKTZPgcev"
        fingerprint = "fc9ebfad0b9b7ca6a1427916be0a20d620f2b4c45fb3402c812abe973447184d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bbc38d1937f4ad293ba6717fd4981e9b"
    $a1="bbc38d1937f4ad293ba6717fd4981e9b"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="533e6f413be2befe"
    $a1="533e6f413be2befe"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*99C49888FA31B274C76A8BA29CABC1EDADDA4FAD"
    $a1="*99C49888FA31B274C76A8BA29CABC1EDADDA4FAD"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}t/k8sX7j3oqUi8Ii7iB63A=="
    $a1="{MD5}t/k8sX7j3oqUi8Ii7iB63A=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}3MbB1xlCVJJ3i+GwuBdSFG0tZfI="
    $a1="{SHA}3MbB1xlCVJJ3i+GwuBdSFG0tZfI="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7f93cb17ee3de8a948bc222ee207adc"
    $a1="b7f93cb17ee3de8a948bc222ee207adc"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcc6c1d719425492778be1b0b81752146d2d65f2"
    $a1="dcc6c1d719425492778be1b0b81752146d2d65f2"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24d472ef95b6482dc059621f2e0f0526300195932f99146a05bc7d3a5b981e1407d3598593ed8f67dc6af5ee98328d0d"
    $a1="24d472ef95b6482dc059621f2e0f0526300195932f99146a05bc7d3a5b981e1407d3598593ed8f67dc6af5ee98328d0d"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="25dc310bd8760c5a1b6bf8bf105fb6e87a477cebdce5c9be6150fb2f"
    $a1="25dc310bd8760c5a1b6bf8bf105fb6e87a477cebdce5c9be6150fb2f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a1742fef019f9d520ce8eeb17d9eecb14735cf0e44518e2b8cc828760e8b8987139dcdb62783530ad4bee70057645539a6d7f366b123ebfd97c57f5f57cb24d"
    $a1="1a1742fef019f9d520ce8eeb17d9eecb14735cf0e44518e2b8cc828760e8b8987139dcdb62783530ad4bee70057645539a6d7f366b123ebfd97c57f5f57cb24d"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e015982059c8bc8e42fb8739200091343e3218d1c80b53f087a21f0780bfe38f"
    $a1="e015982059c8bc8e42fb8739200091343e3218d1c80b53f087a21f0780bfe38f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aefb7dbdda9ba4718c2cb6b0a795cdcbe8a2d77b3d58420e684c568815d03597f18d7012f5cbc356031d9eec0fb488c5da1a1ac6fcb50635c46202009dd1d229"
    $a1="aefb7dbdda9ba4718c2cb6b0a795cdcbe8a2d77b3d58420e684c568815d03597f18d7012f5cbc356031d9eec0fb488c5da1a1ac6fcb50635c46202009dd1d229"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95d539301bfc53cced586ddcd21deacd7409afcb10d2fe2137407110b68f14b0"
    $a1="95d539301bfc53cced586ddcd21deacd7409afcb10d2fe2137407110b68f14b0"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="35c85b10912bb4f466cedf877e63091c434812b66a0e6b34036aaffc"
    $a1="35c85b10912bb4f466cedf877e63091c434812b66a0e6b34036aaffc"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="46d7f9545447fb8d501ad7d20ce12f219993cd99be6856836f6a0245df155360"
    $a1="46d7f9545447fb8d501ad7d20ce12f219993cd99be6856836f6a0245df155360"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7322badae51ef5cc2401b9ad02938bd77b14d13a6ee75cc7076c8104f83d64392ee5de9157839556dce80246fd7fb6b"
    $a1="e7322badae51ef5cc2401b9ad02938bd77b14d13a6ee75cc7076c8104f83d64392ee5de9157839556dce80246fd7fb6b"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d95c357580759ddd936324a52d9027763edaea366bf6bd2a2ed39708ca5fbbd52001c38ce4e8d5f86f44faade09a576775d02c3c0876edf998d5b5aee9069c4"
    $a1="9d95c357580759ddd936324a52d9027763edaea366bf6bd2a2ed39708ca5fbbd52001c38ce4e8d5f86f44faade09a576775d02c3c0876edf998d5b5aee9069c4"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="TGllYmVydA=="
    $a1="TGllYmVydA=="
condition:
    ($a0 and $a1)
}

