/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_nice_systems_ltd
{
    meta:
        id = "3425kVn8I5SW9rVvGru3DX"
        fingerprint = "657612157b738759a832158bf3c0119be4f4b59fc876b51f9f30545c1b58fd82"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="180eda34968bb5515ec1a6bbf29cc257"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="180eda34968bb5515ec1a6bbf29cc257"
    $a3="333f2904481e5ffbb5064955973a5d9a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1b75b4052eb863a3"
    $a1="58f7ee435f925abe"
    $a2="1b75b4052eb863a3"
    $a3="0f9a0e9f59b7cf36"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*9E559E45CFC52B90C1944EF4A5CBCD5E04D7098F"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*9E559E45CFC52B90C1944EF4A5CBCD5E04D7098F"
    $a3="*E3C93FB472B2F6FE47784E63D1451FE4E37D3703"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}6o9F5wRJHLv7IGo+9ymzYw=="
    $a1="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a2="{MD5}6o9F5wRJHLv7IGo+9ymzYw=="
    $a3="{MD5}2gBtFrkSitmZBvWAh7OvKQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}q/hR6GL5WL5de0ovsSMkJJ6Okkk="
    $a1="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a2="{SHA}q/hR6GL5WL5de0ovsSMkJJ6Okkk="
    $a3="{SHA}vKHelGpBQGC4Z553hT2eMrxyHEU="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea8f45e704491cbbfb206a3ef729b363"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="ea8f45e704491cbbfb206a3ef729b363"
    $a3="da006d16b9128ad99906f58087b3af29"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abf851e862f958be5d7b4a2fb12324249e8e9249"
    $a1="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a2="abf851e862f958be5d7b4a2fb12324249e8e9249"
    $a3="bca1de946a414060b8679e77853d9e32bc721c45"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6edc785d060315bf45341937f9b09fbfa81078bb68858d34758a9e9642fcac66b0f8021f7e223ad96d4632ada6812ac5"
    $a1="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a2="6edc785d060315bf45341937f9b09fbfa81078bb68858d34758a9e9642fcac66b0f8021f7e223ad96d4632ada6812ac5"
    $a3="6db9bad0dc3514b34221df2fd951015ffa19cb25a36e083eafc28937fbda6af33761eefac930003c37f3f5299ab64a41"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a8f86c56ca069a5fb9b3e055f56a6564fe63d0866d9e1cf7c4b9760"
    $a1="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a2="0a8f86c56ca069a5fb9b3e055f56a6564fe63d0866d9e1cf7c4b9760"
    $a3="6591013f07ce88246fba141ee0914f0595ed05685e84ff43a8dc133b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de66cc38e6c9951ef0aad2a99222f315e59e87d182895a2b4300d84567225180ad6273dbb4a4a2cc356c753a0ef6f74c9f03ad9465759960009a2969f081b9b8"
    $a1="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a2="de66cc38e6c9951ef0aad2a99222f315e59e87d182895a2b4300d84567225180ad6273dbb4a4a2cc356c753a0ef6f74c9f03ad9465759960009a2969f081b9b8"
    $a3="d38e60df3cafc8bba462c4c141c6b175c74a116d9f54ada21b9b17769c6629097d5049579799d56b8432ced152863164638375328f8a07e9dc54f7a4070a40ad"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4aa47f0fdad5e1c87093ddde8a219a75a0b2bf41cae1ebadbf8cff51957d3339"
    $a1="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a2="4aa47f0fdad5e1c87093ddde8a219a75a0b2bf41cae1ebadbf8cff51957d3339"
    $a3="4e2b25facc0e9a98c6574cab867ea6a31c7c883ad4a4865fd60cdc80fbd50e5d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc19fe1819fbd7d4399914cf4fca237ec614929651ee69b6a2657fd8e1447af12daedacb5135ad4d1b62bfd6d6dbe269055559e1d1b4137859b925c49af957d3"
    $a1="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a2="dc19fe1819fbd7d4399914cf4fca237ec614929651ee69b6a2657fd8e1447af12daedacb5135ad4d1b62bfd6d6dbe269055559e1d1b4137859b925c49af957d3"
    $a3="6119e635e4a8e28b2b632d1b1dee38c16bce4f695cab9ac769866b1fd9c55b0a723349132dbeffeb7792c62f9e181207c50171c600ceccb39ec7ed7e5cca9d0b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="06990a34eb39f5c651f666c0557808f94a4f646ab0343d78b0fd545a373dc185"
    $a1="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a2="06990a34eb39f5c651f666c0557808f94a4f646ab0343d78b0fd545a373dc185"
    $a3="388a104398d2efefac205ed6559d100d1135d882200e06e79a48c5196957c13f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f515cb98b43ae1365b6e23e61e366ac8889b35beef0ce471e5d96d8c"
    $a1="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a2="f515cb98b43ae1365b6e23e61e366ac8889b35beef0ce471e5d96d8c"
    $a3="353bdc81856e051f5aa1d1ebd9ed11691ba9cee08496778ed197b55b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf3b2ffb2d0216861534a8064e6ce3662ccd643e6a76ec12cb84ba1e8ca9bd43"
    $a1="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a2="cf3b2ffb2d0216861534a8064e6ce3662ccd643e6a76ec12cb84ba1e8ca9bd43"
    $a3="5c3a2a84d6c383d245654d508863a73004e9062ca8481a9f54fa3da9f7e72697"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="192b8ac3fb4eb32cfc08fb7523a714fdcfd31e8fbb314cd447b03022f041271f8cb64a58f1c11c7fd14e1354e2b04ba2"
    $a1="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a2="192b8ac3fb4eb32cfc08fb7523a714fdcfd31e8fbb314cd447b03022f041271f8cb64a58f1c11c7fd14e1354e2b04ba2"
    $a3="0b57b7df1323cbbec47d05bcdb1aeea4c7e0b0936928ad838b3330ebd8d0e6d109264aa25d705c16a975d4bfc2c8628d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a587c7f961b13921a8b6e438999a5ea931d36a2c404695683db03a5a601c01b623b2369e5e659cf51c13e93101b6ec5fe2770eb7ee91c4520e0fa5a6e99c0ef0"
    $a1="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a2="a587c7f961b13921a8b6e438999a5ea931d36a2c404695683db03a5a601c01b623b2369e5e659cf51c13e93101b6ec5fe2770eb7ee91c4520e0fa5a6e99c0ef0"
    $a3="21528e7eeb8e93cf2dac57b56fbaea7dd91e60bf3242155a33eb957d368a9d636a8b7ea4148f6fd73ffbb4126a20c8b84c3e3446d76179c3701626677dd2420c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW5pc3RyYXRvcg=="
    $a1="bmljZWN0aQ=="
    $a2="TmljZS1hZG1pbg=="
    $a3="bmljZWN0aQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

