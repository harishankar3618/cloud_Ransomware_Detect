/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_modernie_ssh
{
    meta:
        id = "sfdHr1PxqCKKjRI0GjcA9"
        fingerprint = "b9dcab3416b76fd649fd9978c3b16ab3a68191ba2238ec268970c6efbe3d0c1c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d0a16cfc061c3359db455d00ec27035"
    $a1="db6befd63bd20f737df246520c36fb8b"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24f70c5e56148110"
    $a1="073721475a3ecb2f"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*BAA92ABEC2290BC39655E53B6D709FFE4F17D6AA"
    $a1="*46E994E705CAD4B93B3A59370CFAE344AF62BEBF"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}eLHOb36QN0/pjIw1GzwErQ=="
    $a1="{MD5}/TsBtij7zVZsz1oqtAVqGw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Dj6Lxi1Ezphm4wRXsO9YO3lNjEU="
    $a1="{SHA}CQN6eY2MVdpXbYA/+kQKfpyUAvo="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="78b1ce6f7e90374fe98c8c351b3c04ad"
    $a1="fd3b01b628fbcd566ccf5a2ab4056a1b"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0e3e8bc62d44ce9866e30457b0ef583b794d8c45"
    $a1="09037a798d8c55da576d803ffa440a7e9c9402fa"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="504da0cfa732ceb7f99ac06c8074aa4e7b36621a10a15a428c1fbe43bfc43d810cf7d200999ba936f95474143ee2e375"
    $a1="1d684629cdafb4a4a107f99d3610ddb9b8610f8439e02b8431241370173194d73afd317df0df4af3a62d9316a1a611bb"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb11768af6e89759ee9aa33ced5659362dead5f702c6441339e86239"
    $a1="01fc824c9cfa6ab1597d349b0e0cbb60983375278a990d2b7529a997"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fb34f7b753a936ea0ffd9d569918241809b4f187b00121ad63518f432d46835bb40e2bd3681865b6630a32a753e8534793aa3c96376b1101e0700e1de79534e"
    $a1="793eb58a2fdf9f8de72659580f8414f841dbae459d0d60230b9ca0f18f2c3b591d887e07055f9fef891909bd155c26d2ae39f76e886f87523a5a8132840a9b3d"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d651988096ee1c5bb2e0f7574a21390483f883f58f70adc9175cc78f85bb9afc"
    $a1="d6b4a087a58f8645107241b783dc4f187ca708413107433dfb9d2058a64dfcd8"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c7ecc957bf227e01fcc0ec710e3dd8df84cadf843e958f34658013216a535e6d6db487386f78792a9e7747b69582fb7f883c44a96de300bac7dee8ae3fa7ac9"
    $a1="2af8151bc3707323d828facb3cdcbf853baf893a5fa46cd03f4382745980fba33183dc43fab77d74a4193202c7ef6b45a07af8b0497b2fc4cb9d7c892b3f7feb"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fbc578b901414ca42cfc90301221201473feb655a08354cbbf56173136509e5"
    $a1="4e16ea6c76d0e434343f7afdcdf6aa2c7dd877a175438565816b67bd1c5ccc07"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66f1101d4753565b63d91d2df0ea611b9c935e69dc05bce99725de9f"
    $a1="aff90b20aa2231ce2938f9ade9e50f319d1e0a643c668a1155aeb52c"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91eafe66793d6fae1b658e241eed8f1b010eb514005596de5407c9187203ce88"
    $a1="368f91f113cf0f343f177c6df26c9a02e28422adab83c3472372c8cc7ea51065"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ef3678ad01ee027a5142d36fa4b27bfb2650f7b3e3bf7e508fb180f661468bcfaae8b545ac197c2ba0921dc005d39f19"
    $a1="93e239479ca32eb330eddf7beb6103d71beac60a0ac7b3a7ffb179ad88c83a6f6132672ad5ffa860191c278f49fe65f9"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba7e0993284435f7e8b3220617d8cbb4751909686649a9f793d15334081cf76be4b3ee96743ee9cc499022d412f4b22d486db65ee0d12df800cd299840f86fae"
    $a1="2869c26f456718306d1175e76906d7d79830e1342b7b73f1f56ae8cdd6950160e1320ff50058a7e1db030a868dd9f593aa37b99149461dc93181d25130fa3c45"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="SUVVc2Vy"
    $a1="REByajMzbDFuZw=="
condition:
    ($a0 and $a1)
}

