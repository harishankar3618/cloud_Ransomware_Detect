/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_openhab
{
    meta:
        id = "oIk8SgAb1oTxCFWSabS2k"
        fingerprint = "faa0eaeec4db667329e192018da972ab140799331687db89d18d21c3e3dd2726"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bfbe9bdb567187fdee1fbfcb5088ba3"
    $a1="0bfbe9bdb567187fdee1fbfcb5088ba3"
    $a2="e0bb356fd23ad715e6b55e10d3b85a4c"
    $a3="0a366241203a050268c2d8aa77fd0518"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="610e49bf11439ed5"
    $a1="610e49bf11439ed5"
    $a2="73fa062f0c2d354e"
    $a3="7a013e67391190fd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*9AFCD0A8A29FECE3F407225BABC42CA3F98D4E6A"
    $a1="*9AFCD0A8A29FECE3F407225BABC42CA3F98D4E6A"
    $a2="*6566952868A994DDB4138ACB295F0CFA73B37E4B"
    $a3="*D4647DEFCB590293FD916EC3B35B7BC793E6A599"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ylnCy58zgr30ERS3N0xhcQ=="
    $a1="{MD5}ylnCy58zgr30ERS3N0xhcQ=="
    $a2="{MD5}vEMJuSYXK/fxgO6q8ttgAg=="
    $a3="{MD5}h/ZNXAzDSL9HzRfJEfQ5bw=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}DSsUFpIOMKm5MndQW5Sh84592Y8="
    $a1="{SHA}DSsUFpIOMKm5MndQW5Sh84592Y8="
    $a2="{SHA}hdc6Rba4Dc5F7Bb5D2AcJhuGndM="
    $a3="{SHA}xqT+CyWnRJfpZvJ59RhsmeXOMOM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ca59c2cb9f3382bdf41114b7374c6171"
    $a1="ca59c2cb9f3382bdf41114b7374c6171"
    $a2="bc4309b926172bf7f180eeaaf2db6002"
    $a3="87f64d5c0cc348bf47cd17c911f4396f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d2b1416920e30a9b93277505b94a1f38e7dd98f"
    $a1="0d2b1416920e30a9b93277505b94a1f38e7dd98f"
    $a2="85d73a45b6b80dce45ec16f90f601c261b869dd3"
    $a3="c6a4fe0b25a74497e966f279f5186c99e5ce30e3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cde46cce502798a85bfbc48b007d207decbadcc3ccc567b96d81ad7874050dd2b875d037b1c8aa7ee2826689f6392621"
    $a1="cde46cce502798a85bfbc48b007d207decbadcc3ccc567b96d81ad7874050dd2b875d037b1c8aa7ee2826689f6392621"
    $a2="9a89d9553caaa216e70391c4117fe22e4af4e632f44044cd60bd27d22d5688e638beff602c6c34d4199c616c6db354e8"
    $a3="6f992bc76ea099a077e6d93ce7245a31d8513dae53271544628ea4d3edbb93c1fdee337fc05ba891b5eef45fb4fbb6a9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4b9b91fc0a81a7cd89218aec69e635f94bedd7ab621c5d73dd0363de"
    $a1="4b9b91fc0a81a7cd89218aec69e635f94bedd7ab621c5d73dd0363de"
    $a2="5e177f81b6f935538b284d7e17884371b0d8e5fb5a7a79c2646588cb"
    $a3="834e8777f9e7b3392041178198cf7ecf1d3cd4d6d3194e5a030be176"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ef69fb29f0b9e7a8990ffa741043f1d85ccc8c871efd539b3fe8303a0999c0cf140aff536c0164b5a4a6215857be5a7472b927622b053b4ddd17899707308df"
    $a1="1ef69fb29f0b9e7a8990ffa741043f1d85ccc8c871efd539b3fe8303a0999c0cf140aff536c0164b5a4a6215857be5a7472b927622b053b4ddd17899707308df"
    $a2="21740f19bb686e2d821b6f4e6754f09d4f80769fa5257d20777ea09344c4a52d6cd1fbcd8e79ecd95d25c74c7570a39936d8e8c17fb3eec649216c1fd7deaf24"
    $a3="d8696789560c1493ce4c1aaafd1ed5a83a0a777f57fef3965d922df524dc524aa0bc3e82b1acec25610af520819ef95112c5776ce14d973e7e0bb3fc9f3f1e45"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9569036ca5c65a5cfb0a070144e999c2a322f5711b0b05988b17437cb29be24b"
    $a1="9569036ca5c65a5cfb0a070144e999c2a322f5711b0b05988b17437cb29be24b"
    $a2="4f61a0fd056bc0fd8231899ec4d9f9ca06af0dec895b2a3b0773f6fbc1c99776"
    $a3="b1d3dc2cc0a1114599cc2a7571548b516b2168657b7d2ac19268506e80defdca"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4835672288b60144bebae640dbd5d0eee46011af4c571f3dc6119c772bfdd53b074276415521b1a3074f9a6ff68d0d5e76203fb52cec9ecb3e9bfa07357232d0"
    $a1="4835672288b60144bebae640dbd5d0eee46011af4c571f3dc6119c772bfdd53b074276415521b1a3074f9a6ff68d0d5e76203fb52cec9ecb3e9bfa07357232d0"
    $a2="30c1959c2f08f4859d7d6d045b8da1766a547a733ba7c791c2e16c75d94f8f28abf3d7f352b3531c73dd60aea52d03af2465177c5b6538d023fa49c7e984ad2f"
    $a3="1b9b1f01f5724f145ffcb78bf9b39fb6532e73d2d71c8efde4678f81293ad4201cab737fdd9882648b8446180c5ae8e1f650d31bffb006c2f2c16f078090e0fd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be5e794db2bb2f6814ede107e7d2b9fa8a111f41b50d4b82d5e4763bcb8dff77"
    $a1="be5e794db2bb2f6814ede107e7d2b9fa8a111f41b50d4b82d5e4763bcb8dff77"
    $a2="a5288b9aa31c782882b5d20ba2f32a780eecbe9f60622c91b74c2d36bcf6dfea"
    $a3="311fb1ea3d1821bcd70c6c40cebe38ebfa2321d9c61def00d63a4b39e5cd5e17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="420b40bffd7a5ff52b149ca644c319b4a7c0843d9f71195f7c40a76e"
    $a1="420b40bffd7a5ff52b149ca644c319b4a7c0843d9f71195f7c40a76e"
    $a2="a34116f6b1325af05e5207c5997b3709f37d68b89ad38014db4b669e"
    $a3="b624c683caaacd81f112da860908bccdb04701751b121c9e5bac5973"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ed42af2471b0357080a9b259784da680908149c754ed2227435e1dab5cd3d63"
    $a1="4ed42af2471b0357080a9b259784da680908149c754ed2227435e1dab5cd3d63"
    $a2="8a286b22bbdbd4f0ec1a0f4597612315f8c31cfaf25d9ab1f3d087725f2a7f42"
    $a3="2d1ae558fe7dc2710eb17f5c712e7564db2df29a878b051edb93a5a29d9d04d0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e04974694f81a0c7e245ecfe35f884290885a9c381959d2d7bff65aa966ca72c710f4c576304780e0adcdf07b11be25d"
    $a1="e04974694f81a0c7e245ecfe35f884290885a9c381959d2d7bff65aa966ca72c710f4c576304780e0adcdf07b11be25d"
    $a2="20d2b5f96d6b4a68307208046c6ba957b40d108f12e14e30e0f033bfc7a6f2ea377e08b44936450ee83eeb9eed0cae9e"
    $a3="03f4c36b38d0ce500a2418b15a6790b31ad794b690601cdbab1776f6d891bcd74ab72002be12098270c879d8e858a88f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9acd135acc5c8e26c5e37b13a3155f86480965c9d23244cede6bb1367d1ea378f54add8807cd1eb1be776d5250bd32aa399675ebfede46d3d999e8a1583475d0"
    $a1="9acd135acc5c8e26c5e37b13a3155f86480965c9d23244cede6bb1367d1ea378f54add8807cd1eb1be776d5250bd32aa399675ebfede46d3d999e8a1583475d0"
    $a2="6e689567094266398a2923bee3d0516919e08ce588ca8bff9bfa67259a0dc71403c136d0d49cf3dd6fcd61307aad578b4a00e6479648809fd25dc17edf63dc7f"
    $a3="e580eb9fe88a5e5c44f905cae25bedefc7dd5da58e068fe9503dd9bdca83756e68adea3a31dcc1bf33403ecec073f2c378ada046859afd2034cf95cb91f8c754"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3BlbmhhYmlhbg=="
    $a1="b3BlbmhhYmlhbg=="
    $a2="b3BlbmhhYg=="
    $a3="aGFib3Blbg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

