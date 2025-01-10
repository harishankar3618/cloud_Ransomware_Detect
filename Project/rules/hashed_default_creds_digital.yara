/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_digital
{
    meta:
        id = "2UKWxS0rElJ5sYBzgKisjQ"
        fingerprint = "b423b284eea2c308aa72573a2d782bdfac93084438a16d6bd0238fa0da105716"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abf18b968ecdb7d2beb4b1fcaa9bf54c"
    $a1="8f33e2ebe5960b8738d98a80363786b0"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3952b2430868d251"
    $a1="6067178d6665bcfe"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*EB87920C7207E533743E4C5D8C6AF2CC61C71B35"
    $a1="*12033B78389744F3F39AC4CE4CCFCAD6960D8EA0"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}t1I5CmytDgTJaWkfQGG91g=="
    $a1="{MD5}yB5yjZ1ML2NvBn+JzBSGLA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}6xX40Nbu8SUY24WVK8IjmKQSho0="
    $a1="{SHA}2kuSN7rMzfGcB2DKt67EqDWQELA="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b752390a6cad0e04c969691f4061bdd6"
    $a1="c81e728d9d4c2f636f067f89cc14862c"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb15f8d0d6eef12518db85952bc22398a412868d"
    $a1="da4b9237bacccdf19c0760cab7aec4a8359010b0"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a843ab7a61d79f6e16f673a5bd702c737be452b80fc92f912b0e608f4797d838e96ae673c13546da077d1aec5ae12954"
    $a1="d063457705d66d6f016e4cdd747db3af8d70ebfd36badd63de6c8ca4a9d8bfb5d874e7fbd750aa804dcaddae7eeef51e"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b422dcfa018ce6f6d2454b956382a957a129abab22e4f2db2953987d"
    $a1="58b2aaa0bfae7acc021b3260e941117b529b2e69de878fd7d45c61a9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="120a4a1088dee88846156d00b35926a919692060e71bdfa257ad288141a0e501d3d371478d1a3299702b679e6322d89ade132c12999f8a89ffa33b28711a38b7"
    $a1="40b244112641dd78dd4f93b6c9190dd46e0099194d5a44257b7efad6ef9ff4683da1eda0244448cb343aa688f5d3efd7314dafe580ac0bcbf115aeca9e8dc114"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91bb720d0df350055e59adcea2c1095597660a97e1ffa2a728fe873621acda1f"
    $a1="d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6bce1a0350103a3c0ea2e92c31f49ad88a58bd485dfce6f57a32502f69b98a0fe7e115f82e3a382a4f13a2d0bc966b21d363dee0d4cb1254a62b72414065b9a2"
    $a1="c5faca15ac2f93578b39ef4b6bbb871bdedce4ddd584fd31f0bb66fade3947e6bb1353e562414ed50638a8829ff3daccac7ef4a50acee72a5384ba9aeb604fc9"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14b9dbc85b0eab750605dac4f0149eab05003de7f39e61e7a95ab3f3bdcfa100"
    $a1="cd7aec459fb9c9fd67d89e6b733c394dd0503df3ab3d08e80894c9a4a14d086d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="421e0ca9f159d5b6099bc788b42b7e27672692edd6d5af5863f2b3ef"
    $a1="f3ff4f073ed24d62051c8d7bb73418b95db2f6ff9e4441af466f6d98"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ac749fcf0ec9a7b07755f5228edf9a872ce6665868c6a4693aa88ec408ea072"
    $a1="b1b1bd1ed240b1496c81ccf19ceccf2af6fd24fac10ae42023628abbe2687310"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a15dfb85ab204b230943e24cb8aa2721cac311248d0327000762349f96cb0c55c1870d7fc15241756cb996d21e86d417"
    $a1="39773563a8fc5c19ba80f0dc0f57bf49ba0e804abe8e68a1ed067252c30ef499d54ab4eb4e8f4cfa2cfac6c83798997e"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b618d7709f9703400edee5b789b6c6895284738fca06628b315cd246a422fcfd8de1e5f73355adaec77094a5cd2a5ecee7669f04e6c7ca1d6b16a1336baeb031"
    $a1="564e1971233e098c26d412f2d4e652742355e616fed8ba88fc9750f869aac1c29cb944175c374a7b6769989aa7a4216198ee12f53bf7827850dfe28540587a97"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Mg=="
    $a1="bWFpbnRhaW4="
condition:
    ($a0 and $a1)
}

