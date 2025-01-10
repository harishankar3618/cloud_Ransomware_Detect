/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_iris
{
    meta:
        id = "4BmRWt75g28GnTgfcL7Cfr"
        fingerprint = "db5cfacd3e852e76d75278c78c97f99b31b54652eba84fc51682d7cec6be950f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0280777f37d4f4e7c478d21cec701463"
    $a1="d42a7e4ccf4197a5cea4f2de54a5fe45"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15f73cd91718b388"
    $a1="0c8e7ab4137e5ad9"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
    $a1="*469B64E2F9964B146BB50860BE92ED2D5E9011B4"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a1="{MD5}W5b8W68o62TYzJl8Je7c7w=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a1="{SHA}GRc7SODQNK5kJl1Vaw99kMgLTsQ="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f9bfe9d1345237cb3b2b205864da075"
    $a1="5b96fc5baf28eb64d8cc997c25eedcef"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a1="19173b48e0d034ae64265d556b0f7d90c80b4ec4"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a1="26bcf241a5f9dd2b623f35136232a6c9830d9ddc979880c22f72030eef6dc675a871aa2cac52c612e2fecf5d48492f54"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a1="fc0b76a91e726f60f4ecb31ebc3d213fdab48350dba4eeff039c71f7"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
    $a1="4e4dde8552a8f273efa7751d305063442b6d2fbbcc3c806924d31c65318a7203166064ad8d1206478f4af5b3171de95817c8d92e2500fd9971baf9743ab8f24d"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a1="800250e0abe4745406b71b866e6d11f92a7dddfceaf305079bc8c9fbc8de4806"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
    $a1="e7cf0c41e91dc6ccb10a10a9e85e627833fbcff1ad4718550f31a42116949a7ce02ad475e58dd8c1f165041e7ab7b866ed611703756d071fe78cbd5a82b90e33"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a1="5ecc4f111a368c8de158a367aa9af220e459244f983ccf5ffd6053ebbe160556"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a1="68c512124eccb399e344ff38cfeba3bde7a7c356bff9b57fa2a70f2b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a1="fba5b62ca5ba0c65f1c393b8e35db139e5a6902695f8b52cdecb6c2db3de0811"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a1="fb9321e867767645833361215eefd94c28d4b16084f13152232763affc598a22e1041642c2452e9832718c20677cdab9"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a1="3ac5d5b5d522116934d24616c9185c88d9fefbc2dbbd2aa0a66c611f902512d6a797daad363fe1bfcb473414256dc4fe51f61dc4db39945bfa2de50747a0aabe"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="UERQMTE="
    $a1="VXNlcg=="
condition:
    ($a0 and $a1)
}

