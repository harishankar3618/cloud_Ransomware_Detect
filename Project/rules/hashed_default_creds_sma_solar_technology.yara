/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_sma_solar_technology
{
    meta:
        id = "7NA8Pom7YSdW0gjeB1wVip"
        fingerprint = "d462818c203efba843abbe32e4f673d0acdf64bb0b2a1322b8f666e418c2f905"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c1fa6977c9371431587369eb81c95c9"
    $a1="9db5a70db9fefabe408c978e8a130e22"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7891ed7b2633dd4b"
    $a1="656e7b702418fd12"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*0BA8FC2A0BA82D2BFCB187131338093471705D9C"
    $a1="*FB303DC9AB2919081F5C9BAA41229AC88C12EBA5"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}oon6QlLtWvjj6fm+5UXBcg=="
    $a1="{MD5}0b43dlaWDtBPFWTaIdgMjQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}+RE0G5VY2WEwdIy0uZ07UNYhuGY="
    $a1="{SHA}sy8wCL8DMNxpHz5bxdZazZwz8Jw="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a289fa4252ed5af8e3e9f9bee545c172"
    $a1="d1be377656960ed04f1564da21d80c8d"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f911341b9558d96130748cb4b99d3b50d621b866"
    $a1="b32f3008bf0330dc691f3e5bc5d65acd9c33f09c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="990addf057c1486caefc14c4dbc336290dcf2adb007f2593b8bb4ab80bc3a23ec044b3b0bb51df119e3e46285bbf3d66"
    $a1="4db4b0c1da6e12f24d1eb30c2b1cd56a4b478b964e34031aeedb2043a4369ba9a3c11f16b0499290cf6c04d0b15e5659"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="170ff27789113ed2101b575b4861df60040dc2b1206b23bcc66a1ab9"
    $a1="68ec7e28973a051ee57afc3239fa30504eaa6b3d7712694068130764"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8a67d6a9bb3eda72d6aa7eb9361d1c46ae63805afb7ef748dbb543dab1b2b88496c4ae017b8db70e15fd65f2bf3796a6ea64ddf78da6c4d32bc213e1d9af4f1"
    $a1="072675cfeb5682aa5e6218f85c89db6469885311dabb1a68b513a2e32f3814af0d281f0e76943cc544b67b5fe2128b5f5c61f6cae91113a5d71c171168acad44"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e4d00226255e697db90b471743a150a903121dda5d91b1cf13beac0615664c28"
    $a1="bb6b121974b6136364251f9ff4603b152334b02611c439ab7d3e65a5ec1db429"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99e1746aeb43c221d34500c7963576d2a39ab92b8baf1894f6c544ccbed77f968797f4b6333eb5d2a5cbee7d0525adfcf99eab24a1d25e0e17a97911695eaa25"
    $a1="9e3a140ae1f7f2af37a52f77a8714cc420d3d17553fa8e7a5ee9af4cac8961ab4829b5aa7b3208c7394158bd4d80cda865a5f1ac9fa00bfe5fa344970a231b52"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e41b18ea8c0afc1c1de1234096348d441695122b906c857dbbebe3fb07a4ffb"
    $a1="cf40ab52ed9ae59e5eb2127b431847c744097513ab845a477fc0d0a445dc55e0"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2140bf67dc8fbcfaec11b16cb7e31a7c5c02f934c4b47c8aae325344"
    $a1="1a48a2cc846f319fc1f43fbae0c27cce438898ab1ffcca59d30c0e9e"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b1c54de0ca4e049c46a6bceb32a51e31611a2de91e8c1134655acebc2e2b520"
    $a1="d94bcbb9741f06da5df46014e0fe986962c3cb629afa1b407209a0dd6421e819"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05a326f665edf95226e953799a22d6595d988cd6132636246a96cec322ff0fa2e82f83768133a879f564c46fcf5e7d4f"
    $a1="3391ccf39b85eda64ce6da54bb4f2afe815585764e5808de578e66d9ae3e7acfde14756d0898f734434adf3357bc469b"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0faff5c8f0e2567fe0de9a71e5e40fe237613bd04ee9b2d10727de17f470e649726997f67e4181a17eaaebf67f745c26a2be333cc3076caa67416fc5600cbac3"
    $a1="f063d11964a795a7a33ba044fcfc8dcbd17a44bbd50538d7deed2ba382f7ba5717bb0f6ae75fea4f37c956ebba811951f476cff0a039e86ae6744a36a102fb34"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="SW5zdGFsbGVy"
    $a1="c21h"
condition:
    ($a0 and $a1)
}

