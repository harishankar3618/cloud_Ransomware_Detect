/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_textportal
{
    meta:
        id = "3sPYit7rh0vtGgCsko5muN"
        fingerprint = "b1a27c59d1621b635d6501fbe0a5241484811ac0f3fa05a493142a8b20c2e7ef"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a21990fcd3d759941e45c490f143d5f"
    $a1="0b98cb9de5097d90bc65f32a9dacca06"
    $a2="7a21990fcd3d759941e45c490f143d5f"
    $a3="69d2f83d24e49e2fdbef72d1bf40d1c1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e782c85379a326e"
    $a1="552b92ce561d5ca4"
    $a2="2e782c85379a326e"
    $a3="552b9111561d5ee7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a1="*6F093B4225E40833A661137AD9B0302F4855F0D7"
    $a2="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a3="*08518B28C0A6BD41831720E484A269AE64DB60E9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a1="{MD5}6nm1cUtuB2u0sA3Ch5q91w=="
    $a2="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a3="{MD5}1tkXLaB+bETB+8tXH9Co9g=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a1="{SHA}CNKLANjCwc5NBmKFfbU8gZGtJKU="
    $a2="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a3="{SHA}U8pMvEKTq5WwVeo1uvMgCoA1gyY="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="827ccb0eea8a706c4c34a16891f84e7b"
    $a1="ea79b5714b6e076bb4b00dc2879abdd7"
    $a2="827ccb0eea8a706c4c34a16891f84e7b"
    $a3="d6d9172da07e6c44c1fbcb571fd0a8f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cb2237d0679ca88db6464eac60da96345513964"
    $a1="08d28b00d8c2c1ce4d0662857db53c8191ad24a5"
    $a2="8cb2237d0679ca88db6464eac60da96345513964"
    $a3="53ca4cbc4293ab95b055ea35baf3200a80358326"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a1="0494e45741bafcf54ac1157d8cb6f42a1c3d2a65f370225dbecaf49acca51239e8d2b7a73e27a84e87476bc114d8c17f"
    $a2="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a3="cae643d03e8f3bbd47e61afc4f8cfb7fed9657d75e539c40e83ffcf5409447610a1b130d989d0a27da7a5e3e0d3b45d4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a1="fc086c0abf2fafed4860c0b5be9073b05b3600c58003518f3bc3ae67"
    $a2="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a3="008153f5be901efbcd07b51fc97c16c126deff115c63e94aa54f207c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a1="a7bffd16a550861887a18b68a1e7db9c25753eb3404b76774361eef723bb86492fa48f79e5128ecf781317b8cc44e24581dee2113f6cd08404e18c20a2cc72c3"
    $a2="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a3="f021ab9426341d1bc264e5917e21ec81d1230e27106878323ab287fdd222c4ab10605b14982b680082f6e94a320536304c8abd225d7703467e2140bf5959e929"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a1="179e78f1da13b5617d5c0399789621e52ce03037707c897b0cf26c759e6b6b2d"
    $a2="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a3="f256409baf32f972f805fdfe8c73ed6372145acbfc897d3f10e6b8b086e23ac2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a1="db9a9aa90aac7a90da5ab69692155d9330fbfe70c91885b74a91eb395e501694e1bdda76a82319ced1d31e774695142e879ca8db8a85bfc10ae85739580aa28c"
    $a2="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a3="42b724c893cba0ea966c99f19daf354d70c7c2f5661644d6160d1b26f90ba823eedd7e13e05cfafb8bfeda5aa63c3f7c709fd904064f9f676be5ef9c76adcaee"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a1="ae918098f371ebac3fc643a1c912f6dfb5ec408afa96202e010f756bf6540c37"
    $a2="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a3="26be7332a6591b0e6a6c4147b6e182efbf45eab6ad6b8e193fc521c0cc03ac6f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a1="b92a3adeccb43ee883a47a69447666a1243ec6b0b982cf2bad98ec9d"
    $a2="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a3="ef8a052d11cd0d6f18d856292b347369d8f7799f959f1fa65d7077de"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a1="5a8564342adcf6478cac7855f3579dba88746f39eb5cd1d1b3d5c5ea0cffd165"
    $a2="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a3="05ee7ca7ce8346a65e684a76b5a595fdc0684f3f18b26e7df8424b5c1d590cad"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a1="71994f5fa0da44efe6cb9804fbf10facb5412d74f985ad1a5816fa3f4a1ff1380abf186e9d10b6a624266d377c41cab9"
    $a2="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a3="75b2c38192e96fe4eed176d2dbf7502c37253650595756e2c519cb662b841c83bd7f520ff05eecd57b1d094bcbfd40ac"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a1="5c2d18617a03081b0871b4d4e2d2665a5a921bc0a6da71ece733c24f2fa4124efc9b909fc5c6ebe7073240d63c1b422dc5315c9f1e95115705ac8a1a0144e742"
    $a2="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a3="90fa851acbbc24f8fc5c80a64135a61eb1782c5fbf34bb4b9f6b3e9a15c173be58c14beb18a2f6694c8f918de3ffd9ba778d1868c61bd13b9c304b908c399888"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Z29kMg=="
    $a1="MTIzNDU="
    $a2="Z29kMQ=="
    $a3="MTIzNDU="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

