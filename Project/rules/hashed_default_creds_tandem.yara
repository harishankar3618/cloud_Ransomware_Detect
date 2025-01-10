/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_tandem
{
    meta:
        id = "EWebKu519d1Sin2bpWRDt"
        fingerprint = "d67c5efa8fdb6733e0c14c50821e8554d71649bff39b3184c92c7b94796d5ee4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d3986e540a63647454a50e26477ef94"
    $a1="568518ec5cdf396aa685ae7099108322"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c1fb21a20d15f82"
    $a1="06cd67ea6c12ca77"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8D6A637F37955DBFCE1229204DDBED1CE11E6F41"
    $a1="*07CC00B5F21A330F9F1F50171AAD0B9A094A2B61"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}6woZF5diTdOkj6aB0wYSEg=="
    $a1="{MD5}HW2SlwgZc5IU1ktza/UsYg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Tyaur9sjZ2IKOTyXPt2+j4uEbr0="
    $a1="{SHA}lOHaSgOOUVFILX17GPN82kk0lXg="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb0a191797624dd3a48fa681d3061212"
    $a1="1d6d92970819739214d64b736bf52c62"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f26aeafdb2367620a393c973eddbe8f8b846ebd"
    $a1="94e1da4a038e5151482d7d7b18f37cda49349578"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="233a0c3b653358b1b07cf093e7b2e36a54bf4c66d5736db17ed145b18520c9108bbd9ed53bc74de041e15f1476013b10"
    $a1="fd88c1f70f595ea495aeccacd798ce98a25512843d8474948e3e56a4a0019dc142955a004d5fe8f780bbcc9f50606e49"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="79f95ce631a460dc2e3d220a5dffbb5616074375648e4a2212127ecf"
    $a1="f0eedf23e47ac86859d4b99acd76f763dedb98933915e927c3d5414d"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="353ba90f8c0b3e0f355a3d6c960b7caed5f2c1412992277c0669a04a62e7dfd35fba9f4631a7dc6d00fb44d93d305cc0b749c7501d9ce86f26148d05101b8324"
    $a1="dd149e3a20fb1561392aa5d662ac6fc27b172793c58545d4f41da8c3dda9a549e4ffe5cd4b402c4f98f2de3d4c53940921179600a08aa0f67313002703a6be87"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc613b4dfd6736a7bd268c8a0e74ed0d1c04a959f59dd74ef2874983fd443fc9"
    $a1="efd1943b938fbf36174676ee17e22b48fc1b6bb48875061ea2094f869202f2c0"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="33ace3eb11c517be804f516ab407838b51c6eb5baff3203ce3a320b6750bd1bcbf7091092555a332abc4d467ef3c13fcd9ff5312aa0036b98ff1b29774d55f4a"
    $a1="64405c714a7b80967205d987ab2fc9c81e58c5181af6423762574b141760b8d44a4d391516d16c32c877a9506036f99b8edfacaffe93a678d20fda239f557120"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2f185fbcef16ddfab9451925d69b0af28181a7a5efcfa9c6b47f76a2aa430e9f"
    $a1="7178198fc589e850de4356faada144f35d91fe3d8510ee021dbe489cac66b12f"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03370c307219d3d33781c917e10df30471407b8097cf71487eb63c69"
    $a1="2f47dbe417bb97c7fbeb4f1114d41edc48dd56b99ac203a7a642701a"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8e5d79468855b0aa30152460f869669ebece49a748839c70f19d17bb2a2239e2"
    $a1="18feb44cde7cc5d939c52a9bd97a6aa514e3c4b42900f16dec88ccb5c751a95d"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="06ff6516b10e34580acbb5f2b05ae2628cc1c661fbb3e50b31dac0d0fc5be94784163e820aed296a54555a0d4ecd0190"
    $a1="8c9774089b8e3840648e1a38bf1a0f5c8d884211a39d8e8bbf5b1bedec03f0cc7523a1a5c78328e615088389ae9c8f2a"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c56f59716f146eba7b862cf6a1443e68a3cee348bd8a6d51dcaa1ea5c52b41692ebca2e96063db57158e82f789a429d2723b0d84c3a308e198827399448c9090"
    $a1="307f61f0093091ee4a20eef27ee7094924327ba1b6690007150283abe162c47a2251742dd69e897d5eae457a6833e4a32d373152afec55c93baa769b54825a5c"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3VwZXIuc3VwZXI="
    $a1="bWFzdGVy"
condition:
    ($a0 and $a1)
}

