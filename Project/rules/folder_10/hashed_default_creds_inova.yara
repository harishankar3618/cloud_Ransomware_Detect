/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_inova
{
    meta:
        id = "2Zeuj5WM8aZBsr3gfDObaD"
        fingerprint = "cec468c023c80c90909bbcccc674b167fa1fe8b5d15f30680c4434c6a280616c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="131227cb32cbabf1145575fedc7f75f9"
    $a1="b991c53aa9d1a8248de6bc7468361fd0"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b928dca612481bb"
    $a1="291f2c93612748f6"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*367B2BF105010B7B8E56C94F7B6230E30BE1CAEF"
    $a1="*2C6D11D65D3D76DC72DD470CBA942EAD951CACD5"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}OqncVfIl41pXzSjVeVNwpA=="
    $a1="{MD5}n0yaW4CT4YXcy2iaoO5v4A=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}00lrrL/M8p7RXoLuVB73by9bXCM="
    $a1="{SHA}rfxs2ujGlyt/bLODRaSjsRXbPjw="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3aa9dc55f225e35a57cd28d5795370a4"
    $a1="9f4c9a5b8093e185dccb689aa0ee6fe0"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d3496bacbfccf29ed15e82ee541ef76f2f5b5c23"
    $a1="adfc6cdae8c6972b7f6cb38345a4a3b115db3e3c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e315184486f32c9d7c3e0fb4c8235553db7c564c8a32a89c2181410df8e5535d3b207e8351ae8f733a1c128423572a58"
    $a1="7c007479b667ab9a808550ee73ce9818541251ff9fb12540b867004ef659eabb1f12b4702e59f66d4e81f9bbc32e43c1"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="983a708e3df2c377e2b68595e74aa1f8fe699620e194f38530c032f0"
    $a1="3f27742157314e793fc9daf55c2e7db7e4980b806acbc69b27ff372f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e8bb8235e4bddb3f0de834507d50bc731578547a5dc0b18320bd0becca2b3939d7f14db19066c6393b6328be9ccdc558223c23213887dbd0c8be76ba909915f"
    $a1="880a2c02839be9d25ad8f43dfda082deccad74166f4c1407900650c316f2aeedda3718abcc23ea01a44c065a37b892ff9c6ab7cc5baa8e601167abaef7d6236b"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="75fcdc79c50111d864ba4b79fafc57e12938f22c679916d67a7a5825cfa5b63a"
    $a1="479c139143a076ba9152751a266ee3817fd5ca70d46b143b25ee46504bd81928"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f08602bc6c930eea3995af11a78fc4e6d5f90ebf6d8f7c982f0b06ab7c5a15fdb25ad67a92783e46d5bc3cedf32f6da05d867d12a65b398fd6b223fe0ce69f16"
    $a1="14a70e1680168058dab8e17a804182d1ce7ed4e58aaf0462b370c4db80bfab0d43ec07690f77f45e94a4bae11521c68a3551e2421541ff0928205bf419745012"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e788f0611575df9c2802da9bc9353c9bedc108ca9f1bb683ea10928b8203479"
    $a1="93571f9d80d24cdc326318ed1f1ed535201021119d5fd10ebcb5cfb99252a2b2"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7c8fd1ea03160e668f85d92adf4f3783ffa0d4315c141f0ec449644"
    $a1="eba5eebcd9f4a69b235ae240a1e8bb2b0a24ded6d1cab4e8761c214b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce34707fa4039f51d576c654abdc0eeb01450307fcf238eed7a45251c3e75d31"
    $a1="d602706f945af50ba5b0a4669ab4bdcd11f65dcca072e8cad2bd64367c88c7bc"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36dcaaced3983ec40e6e96dff0a2727094f20d7b86c3fcc77d36999d2fb11578a7bf81a34f57997e0ebc04fc55dfb468"
    $a1="99d30ebf55582c8702df271b343564eee72cf6b63845c345dd3c14eea232a38dfa18c914b817a800d18ea41621b2350c"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e58ad8d988825bd0074970c8248f7b9fc54ea44f7d6256ff50e41fd3aa5ac007eed9c1e8040d527f6bbee242b377e1d533406f1bd73c15c5799c8c8e4d3756ff"
    $a1="f4c61490c7b5a2c42d0774585174dce370c4f0139bcb0169d91a55980eb19dafe9dfea349440e5ec2b28f7793b141c95d36f9ec99171517b13e30f284144f11e"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aWNsb2Nr"
    $a1="dGltZWx5"
condition:
    ($a0 and $a1)
}

