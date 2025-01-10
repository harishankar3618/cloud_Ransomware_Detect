/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_open_xchange_inc
{
    meta:
        id = "7eCuh0nCQ7jqf3ulB0ebM3"
        fingerprint = "be93015217b5d684247c56fca7dd4415487cab58216b88c141d948cf28cdaba3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="878d8014606cda29677a44efa1353fc7"
    $a1="dec9eac14158ab414b2bac771f3d0376"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="428567f408994404"
    $a1="0989e6521de7e111"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*14E65567ABDB5135D0CFD9A70B3032C179A49EE7"
    $a1="*2E45FDFAEC969445D1FE8B48EC1F11880861409B"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=="
    $a1="{MD5}23fkp2PsWxC9gYo5F/zHvQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ="
    $a1="{SHA}1++9JBDr5t+dhEn1IizEnWmlhSY="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ebe2294ecd0e0f08eab7690d2a6ee69"
    $a1="db77e4a763ec5b10bd818a3917fcc7bd"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
    $a1="d7efbd2410ebe6df9d8449f5222cc49d69a58526"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58a775ba4112be3005ae4407ce757d88fda71d40497bb8026ecac54d4e3ffc7232ce8de3ab5acb30ae39760fee7c53ed"
    $a1="c36baa62607cd0f4bace35754ae89ed0790fa9132a89d87e67411febe43cf15caec6ea592b336afddd66fb3d52c59dd8"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12"
    $a1="dbf00387b40fd586561426359761bfb259be5ec3b98c683163ce86f9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d682ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2"
    $a1="6c19b3a7bdbb251e066660e1f0ba8077dfb25327e9dc0da10abb09402fc4663b122a2d7a6ec3c4a45a82331a1dc538a65ba5ba8540e7761ae07c85242835586c"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
    $a1="bb96087835b2a082a33b6d7ee3ae240d07f8de033aaab3248dc0ff99705b042c"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fb6a5dd1b937f0c8a3ffc1cdb35edda4a41b2ca72b94e3d2c99c080aed86526aefcdc1e312cdd144d50b0bcd4a402051acd3373f90a96df6e13d9a0a9948993"
    $a1="39abfeb0ef70ece46520df890afa2608246a4979dd277760e8cb3edd13c95224248e09e86e75c00cb073263c6a944bf0c49848c4ea9db9e178bc9d8dd2362c81"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66e754709229a1a76f12b770d612d4dba1d51e28894e2dce1b53ca15104f84c0"
    $a1="c9baf4238b775e7a778299593072754ca70f26b26becc007553253323d2edd92"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9817fd4e8ae39d6e41532989e4422c5a7e46411dab4d2fdfa2270dad"
    $a1="f975d3a3780115c7fd6353e66abb77a17da423ff28d46c2297a5a8d0"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5a5207a8729b1f709cb710311751eb2fc8acad5a1fb8ac991b736e69b6529a3"
    $a1="9596bc2c008337d5197d074fbf8d1d67f521baab8b638dd5d660220d86ab21df"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5222ddb86d6061d2c0ef2bbc607271ff6f355d4283fd54267766b88ee186ca93ab0e421f3142755d56f76ee87889cb8c"
    $a1="e34ae819caca9487a6092ff046cd54c1eb14989ac529ef23c3489c5e5045a9d14457bf831839430537d8dd7d86a9eaf8"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b778a39a3663719dfc5e48c9d78431b1e45c2af9df538782bf199c189dabeac7680ada57dcec8eee91c4e3bf3bfa9af6ffde90cd1d249d1c6121d7b759a001b1"
    $a1="d5615815201ef429850e66f914747c19ad1488bae0142a7787f52e9f05df4610fa482becaeb5fd01377dec95c0eb3fb230e50f8a0f3629d8bd812465f810562a"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bWFpbGFkbWlu"
    $a1="c2VjcmV0"
condition:
    ($a0 and $a1)
}

