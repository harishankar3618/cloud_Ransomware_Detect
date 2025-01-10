/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_radware
{
    meta:
        id = "14EWVbHBpRlIkmh9zIitzO"
        fingerprint = "c4a188d785b4e4843e341c779fcb7c0520897304ac3ae4d8bdb9640b2208c450"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="519512db08bed68c3ab7f7905fd06e6e"
    $a1="519512db08bed68c3ab7f7905fd06e6e"
    $a2="dd26f3e9d93404ea28f8ee393e3424d0"
    $a3="dd26f3e9d93404ea28f8ee393e3424d0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e398834765b5da8"
    $a1="5e398834765b5da8"
    $a2="077ebee5492627bb"
    $a3="077ebee5492627bb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7E5AF00DC80420982D961E605545F58ACA163F4A"
    $a1="*7E5AF00DC80420982D961E605545F58ACA163F4A"
    $a2="*BE8F26262B1AF06C97FCD9CB10B28584065A915D"
    $a3="*BE8F26262B1AF06C97FCD9CB10B28584065A915D"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Y9AsNumDwvU2XHSztab7KQ=="
    $a1="{MD5}Y9AsNumDwvU2XHSztab7KQ=="
    $a2="{MD5}NRMlpmCyVHRFavXJpWBsTg=="
    $a3="{MD5}NRMlpmCyVHRFavXJpWBsTg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}pgocep1ogiPZSOg+aiy0DNfIPzs="
    $a1="{SHA}pgocep1ogiPZSOg+aiy0DNfIPzs="
    $a2="{SHA}1EKU2rtVWdg0+PjRxdT9dcFldw4="
    $a3="{SHA}1EKU2rtVWdg0+PjRxdT9dcFldw4="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="63d02c36e983c2f5365c74b3b5a6fb29"
    $a1="63d02c36e983c2f5365c74b3b5a6fb29"
    $a2="351325a660b25474456af5c9a5606c4e"
    $a3="351325a660b25474456af5c9a5606c4e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a60a1c7a9d688223d948e83e6a2cb40cd7c83f3b"
    $a1="a60a1c7a9d688223d948e83e6a2cb40cd7c83f3b"
    $a2="d44294dabb5559d834f8f8d1c5d4fd75c165770e"
    $a3="d44294dabb5559d834f8f8d1c5d4fd75c165770e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50acf6854ff049011cd9187fd75de3d3f3f58c1b474fbf263b9be441811912ab269f93ee2020b1a19cfb9996243b506b"
    $a1="50acf6854ff049011cd9187fd75de3d3f3f58c1b474fbf263b9be441811912ab269f93ee2020b1a19cfb9996243b506b"
    $a2="5d51df127cb09685d20f2808a179325f18d41df55a6b65a3b0f982ce6377b79c06877eb66415bb4c9547d7ca0ccca642"
    $a3="5d51df127cb09685d20f2808a179325f18d41df55a6b65a3b0f982ce6377b79c06877eb66415bb4c9547d7ca0ccca642"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f2204c440c9157e336938952ff3a2639b1c7e4fb29c168d98ccac9a"
    $a1="1f2204c440c9157e336938952ff3a2639b1c7e4fb29c168d98ccac9a"
    $a2="6deca2175bfed6830906048cf5ab2611b4fa6b4e2394309ae2f6832b"
    $a3="6deca2175bfed6830906048cf5ab2611b4fa6b4e2394309ae2f6832b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e40c136d125d5b29d6de7394f2617968aaedd0d9f6af63748e3d35711de1b9a2fb5b63899b1bc8bdaf243625ccb2f003d11bacc9fe0ad1490472add97ad769d3"
    $a1="e40c136d125d5b29d6de7394f2617968aaedd0d9f6af63748e3d35711de1b9a2fb5b63899b1bc8bdaf243625ccb2f003d11bacc9fe0ad1490472add97ad769d3"
    $a2="0fcd307f76f7ab45e0e49269f6787552143f9652b394a2720e8d61a754841d815fcd9b05c7613ee746ef7e3ab5ac17421e08f3ff8d63f6a906177266fa0b2f69"
    $a3="0fcd307f76f7ab45e0e49269f6787552143f9652b394a2720e8d61a754841d815fcd9b05c7613ee746ef7e3ab5ac17421e08f3ff8d63f6a906177266fa0b2f69"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8cac552ef22e00eedd1f54b5a6e735ff57d093eac889aad542dda57c585d01c"
    $a1="d8cac552ef22e00eedd1f54b5a6e735ff57d093eac889aad542dda57c585d01c"
    $a2="0a7aacae9b43f934498185566d2a865ef93d4f4c4488c60d085f5b268c949825"
    $a3="0a7aacae9b43f934498185566d2a865ef93d4f4c4488c60d085f5b268c949825"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0da581b9fe0281f5d04d298ccaa56596b0deeb535c3c2564d370af01fc835ee9c99a116b169550befad06577064382d85df7ce90330d1198e6e56afec7fd6620"
    $a1="0da581b9fe0281f5d04d298ccaa56596b0deeb535c3c2564d370af01fc835ee9c99a116b169550befad06577064382d85df7ce90330d1198e6e56afec7fd6620"
    $a2="1fd267661ad758bb5cc76b65daa7f3c16b35a5855b65d2e509596037845b03be5b41fb1b74161565b4c85c868d0a102fe1e7a4f2943b71691dbd7d41c6d426ae"
    $a3="1fd267661ad758bb5cc76b65daa7f3c16b35a5855b65d2e509596037845b03be5b41fb1b74161565b4c85c868d0a102fe1e7a4f2943b71691dbd7d41c6d426ae"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="241c62cbf017c6d86c6789a12685ca53b869447d2978836ab40a64e0106e4bd8"
    $a1="241c62cbf017c6d86c6789a12685ca53b869447d2978836ab40a64e0106e4bd8"
    $a2="db2bbb0946ce87b56a027c63f2de00223d07b806bd6f24ab81b799056d328840"
    $a3="db2bbb0946ce87b56a027c63f2de00223d07b806bd6f24ab81b799056d328840"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2470d6b818c2b7cf4b177929f3f5d8092307085d24aae6b77f634021"
    $a1="2470d6b818c2b7cf4b177929f3f5d8092307085d24aae6b77f634021"
    $a2="37a5be8930801a88da62fdcf696d09358fe48339010d2e10db5bd13b"
    $a3="37a5be8930801a88da62fdcf696d09358fe48339010d2e10db5bd13b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58957c092f4040ebc115fa2d157888165595cb4fed30cd169b944ea74121a1d2"
    $a1="58957c092f4040ebc115fa2d157888165595cb4fed30cd169b944ea74121a1d2"
    $a2="c608b6a3b40f0bff5b6f781631392445083f63ae2ef7557eafe3cb8a372ff7e5"
    $a3="c608b6a3b40f0bff5b6f781631392445083f63ae2ef7557eafe3cb8a372ff7e5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3a2259bcf601938c1fc6e92ddd67df56647f0e28a3ff9d206920afd922e91ed082330e9259338120837dfc475cf2bf52"
    $a1="3a2259bcf601938c1fc6e92ddd67df56647f0e28a3ff9d206920afd922e91ed082330e9259338120837dfc475cf2bf52"
    $a2="f8f9c707a1f74cd3f763ac6e68e054c68baa44e0ab670690906de81ae7a54af528ea88379d07e95793fd6e5c5bf272a2"
    $a3="f8f9c707a1f74cd3f763ac6e68e054c68baa44e0ab670690906de81ae7a54af528ea88379d07e95793fd6e5c5bf272a2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a221ad4b83384a87429f1731409b6572699ec55ea9dc06900548bc22c149126f7c73c3c92fbc4b75386924242aaad351761f5b96d33188125908bde290e6a83a"
    $a1="a221ad4b83384a87429f1731409b6572699ec55ea9dc06900548bc22c149126f7c73c3c92fbc4b75386924242aaad351761f5b96d33188125908bde290e6a83a"
    $a2="27465fa032c1b4570bed0b6cbd10eb1bda7363a5fc498e605a57f5a6710c0e2b88b216a7f0f769024006003e59c91ebf1c135b2544a7730f3030aa6066af356c"
    $a3="27465fa032c1b4570bed0b6cbd10eb1bda7363a5fc498e605a57f5a6710c0e2b88b216a7f0f769024006003e59c91ebf1c135b2544a7730f3030aa6066af356c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cmFkd2FyZQ=="
    $a1="cmFkd2FyZQ=="
    $a2="bHA="
    $a3="bHA="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

