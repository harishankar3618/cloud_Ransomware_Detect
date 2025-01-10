/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_apc
{
    meta:
        id = "6nGEarwGVsm5Xc9dLVK1Hg"
        fingerprint = "1dd16592fd71c24bd43cea968e71de414cc6981762f1913316266a4418df8eb0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b96670ba87df193012a9b0ddbf14c634"
    $a1="8ed8b6f2aaeda80e8c9c4055bacf910b"
    $a2="b96670ba87df193012a9b0ddbf14c634"
    $a3="b96670ba87df193012a9b0ddbf14c634"
    $a4="520bb2211c403f0feefe4e7e6bcb9260"
    $a5="9d2e8cd56c5c7f34993c58bae7537778"
    $a6="b96670ba87df193012a9b0ddbf14c634"
    $a7="dddbcb37e837fea2d4c321ca8105ec48"
    $a8="b96670ba87df193012a9b0ddbf14c634"
    $a9="5d93591697ff29acfa4eb6a086205cf1"
    $a10="5d93591697ff29acfa4eb6a086205cf1"
    $a11="5d93591697ff29acfa4eb6a086205cf1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7cdcc46a2c1a585d"
    $a1="69ddad3d54a22b52"
    $a2="7cdcc46a2c1a585d"
    $a3="7cdcc46a2c1a585d"
    $a4="7345b60a0a7868dd"
    $a5="1dbd4d345146e009"
    $a6="7cdcc46a2c1a585d"
    $a7="55743dec57707aa0"
    $a8="7cdcc46a2c1a585d"
    $a9="0dd0751e564477c7"
    $a10="0dd0751e564477c7"
    $a11="0dd0751e564477c7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a1="*965E9F326E96D0343097F671E837ED989280EA35"
    $a2="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a3="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a4="*C71FE3464BF650F5208E4808638BE6B9B9C43959"
    $a5="*C697E2251DECB7B86232C38189F493FC2FEF614A"
    $a6="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a7="*922A4B420903CAD4E7FC56A23122AB927E051FE3"
    $a8="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a9="*61342F052E319D36B0E6C984AF680C4087210453"
    $a10="*61342F052E319D36B0E6C984AF680C4087210453"
    $a11="*61342F052E319D36B0E6C984AF680C4087210453"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a1="{MD5}DtMBe5EZIOrlFOEqVqyY2Q=="
    $a2="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a3="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a4="{MD5}Dmj3U7xgH12dBHF/lQQnYg=="
    $a5="{MD5}VdWYtBdHjZ42kok1Q36v5w=="
    $a6="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a7="{MD5}M267sheb6qc0Ck8WIPOvQA=="
    $a8="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a9="{MD5}kT+cSdy1ROIIfO4oT0oAtw=="
    $a10="{MD5}kT+cSdy1ROIIfO4oT0oAtw=="
    $a11="{MD5}kT+cSdy1ROIIfO4oT0oAtw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a1="{SHA}ZlPO/V0t3Ewrwmt1/AnbqAsYGxM="
    $a2="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a3="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a4="{SHA}G/4VK5ZaSjvMST/ia0b98AUJ+oM="
    $a5="{SHA}u6JhcFbzrZsarr0t8QwOac9PZH0="
    $a6="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a7="{SHA}midxgpchjDdXw2XTV9E/SdD6MGU="
    $a8="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a9="{SHA}86kpszZLRxpIH0982gtFWezemro="
    $a10="{SHA}86kpszZLRxpIH0982gtFWezemro="
    $a11="{SHA}86kpszZLRxpIH0982gtFWezemro="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a1="0ed3017b911920eae514e12a56ac98d9"
    $a2="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a3="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a4="0e68f753bc601f5d9d04717f95042762"
    $a5="55d598b417478d9e36928935437eafe7"
    $a6="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a7="336ebbb2179beaa7340a4f1620f3af40"
    $a8="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a9="913f9c49dcb544e2087cee284f4a00b7"
    $a10="913f9c49dcb544e2087cee284f4a00b7"
    $a11="913f9c49dcb544e2087cee284f4a00b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a1="6653cefd5d2ddc4c2bc26b75fc09dba80b181b13"
    $a2="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a3="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a4="1bfe152b965a4a3bcc493fe26b46fdf00509fa83"
    $a5="bba2617056f3ad9b1aaebd2df10c0e69cf4f647d"
    $a6="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a7="9a27718297218c3757c365d357d13f49d0fa3065"
    $a8="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a9="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a10="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a11="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a1="e14b54a4aae88e8c1d60b237e7d5df732868089c61da40c923246ad9c96e61f4a8773ee9e7ccf7e2a76e2be6a4ea12c8"
    $a2="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a3="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a4="07da3c989714339f2dfdc9d8dea56cf410755bd8da3b5c48bf4530dd3228bd4025b4ecc43149915c222c94bdbbb99a34"
    $a5="34936fbd99a6d707fffa289bf9c174a110ccc5c5ee3ecfbf2fdbc8467bbd2d89c9e08d5fea4cb31f55d1779b1ebeb46c"
    $a6="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a7="3ce313ec5ea0e8e20c6d3e0a70418198cd3cc1a54bb1e51f1a3135dc03d014e20f3387875bba5f5d37e54100b9535762"
    $a8="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a9="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
    $a10="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
    $a11="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a1="77044a646ec05b83a2d3f9163bb765abbb115a34b2df9e198adf84ba"
    $a2="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a3="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a4="58714c17b0ab4e300bac7f3dae1b844e421b0832a84e0efc4cc0f9bd"
    $a5="92ed51bbe9c7cdf1c50d112af91a0462a4888fedf81965c66c55fe59"
    $a6="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a7="c3352c01875335502f888606000fee7f03bdf8331037cec22a1bb55a"
    $a8="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a9="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a10="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a11="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a1="478cf2511b4cbc1880181ff4ca94ed37fa7a7a0c2834eed9110cb10a48179715c5f3baca00b4d5b451ef2975c6bdf0698ce8fc323b9f3caa6f66c5eb621b6746"
    $a2="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a3="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a4="ff9ee9f31ca1dc3b54fa2169102ea5f1e908e5504af2058376726f6c1508f039ce559aba30ae0e7b55856cf79a603369d5713fd504d63b1a5950cfdc46a0cae7"
    $a5="bcda783cb1abf9cef08145640871afd7bf05c18ccfb6e45ea4d4c46f95b0a1e10fd87b6f4862b5d435269100d63902e000e9d8c3baa06396152516495fbf1eec"
    $a6="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a7="ff3d9d060c06599e083d26bcdffd24b51c68e3a7cd10859d6763701e31dad0debdaee7085b95e7b0c5f9c535d5e031e75e885fde7a6056065fce009f597345c9"
    $a8="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a9="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
    $a10="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
    $a11="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a1="9561dd4c25e91218406ecd9fd43dae8813ad8b3110d9f0b040d97a92114dca30"
    $a2="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a3="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a4="a43915481c3b48d871d73fb0396701d3626c2cc5e5d1a95ec17e067cc8d3d7fe"
    $a5="9bea1a11c11649bc93ab31823bad0af7a83d70e7530c9b381056ed1deedc9220"
    $a6="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a7="8171bacf32668a8f44b90087ad107ed63170f57154763ba7e44047bf9e5a7be3"
    $a8="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a9="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
    $a10="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
    $a11="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a1="ad8050cc0a02b684db545ac6bd35c6560b7a6844251e148ca49c73a4a628a1a41099d0c584c2875a1ce2ad0e0fea6a83f57c9e05005ceb066b30f0240a849ebe"
    $a2="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a3="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a4="c57c6a00e3c2a33201d554ead54abae28ed7861dee647d854833e48fc97ff6654eef506087bcaa8f016030eea157411cbaa85d5d9afb43a05ac579a6b57ca567"
    $a5="e1bf07905158276eda8f77e8fd984ad8085ce88c7f8eafcd8c64e56b74c39a4ffc5fd5752f482fa10aae16aba6e738627f0f430972e8a553005d3794ed9849d7"
    $a6="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a7="8d2f4f0bac20160beccfa32131beeb745b19fa24352e74356659edf6e463847b91130101ef25bf20d2cd8bb46a5b3558f5fe28361c15ca6e6513160d569c9592"
    $a8="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a9="2efa3755160d85e0ddc6a827f9a458a19829a83d286f0b6a46960491558320e74a3dc092986ead0b95e0ade7e368e363056a1396fdba590669fc1e631edf11ea"
    $a10="2efa3755160d85e0ddc6a827f9a458a19829a83d286f0b6a46960491558320e74a3dc092986ead0b95e0ade7e368e363056a1396fdba590669fc1e631edf11ea"
    $a11="2efa3755160d85e0ddc6a827f9a458a19829a83d286f0b6a46960491558320e74a3dc092986ead0b95e0ade7e368e363056a1396fdba590669fc1e631edf11ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a1="9f3654d0c4bf9bc4a6dbbefccbfaf0b05574e7fa9edf22384633ba10ce2f69b6"
    $a2="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a3="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a4="edd87c2a7ebc1d47fc691da77f68d600f0c87fd34f6ff49eca4fa61e2d1536bb"
    $a5="f2aa0be7eb0021b60c988c9cbdc393b122c02c549f19e49b251ad399e9e1f847"
    $a6="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a7="97c665ef42239cceba9e65db0a1123f2b3de1891ba4462778304b1e07c4103a7"
    $a8="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a9="f7a7eba9542ac5dd4d5abd94a46de7b8c5f09c5d530ebff4a8f698bf25487fdf"
    $a10="f7a7eba9542ac5dd4d5abd94a46de7b8c5f09c5d530ebff4a8f698bf25487fdf"
    $a11="f7a7eba9542ac5dd4d5abd94a46de7b8c5f09c5d530ebff4a8f698bf25487fdf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a1="86d9551ea8b79b5fbbdf7f69849ba516861b95819051e623e5d9586b"
    $a2="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a3="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a4="cee18a4cb12aebdb494bc2162bd4de85ee82649bc6b30953e6caa5e0"
    $a5="f22db770eeb09733518c60b5db362616dd1f53d547a444db01b25d72"
    $a6="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a7="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
    $a8="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a9="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a10="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a11="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a1="5bf5681158a0e6494a12e84b54589f81eee6c89e84af8d7ef6f384a333d1611d"
    $a2="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a3="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a4="2dad92536da841885bdfbaa56762c8bce1f627a450527683a2638b68d313cfe5"
    $a5="551383ddb06f444e1e78d37df3a163b97335e5b07e15c837f049e70b90f45d94"
    $a6="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a7="057d1b930b9c8e962bf34656a2c010888ae6a2a5fc4de074ecc8cb3bf4782685"
    $a8="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a9="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
    $a10="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
    $a11="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a1="3379808947acdca8124f0c199195195fd5a9908a8e58b11fe7c4eebba30e61d1fc510d37ebf6c86aa7dbfb279e096e26"
    $a2="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a3="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a4="97b22d309a6e74198abf64a5a02082cb4ff0019635e26b93241a86d7cd14b9ba31eea4d4deae6658d5730240fe4298d9"
    $a5="a910850260eb99156533f51f1946dbfd14082558b3d453158371b7088c90d3869b3d38b387a132dcbcafd5de7e9fb76e"
    $a6="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a7="0e08ace98462c032a1d1ef35387532a39d62bf837abfdfd1ac221c6a070fe0e064ce07d88c6004e63d55d1fa8d508327"
    $a8="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a9="a1fe5f185b6e65143b7b8a37c8a8b2fcf53b58cc4ffe021c6b4b157d8b3a9e69ce6a3c4d7361adb1cf83d947b3b7c4f4"
    $a10="a1fe5f185b6e65143b7b8a37c8a8b2fcf53b58cc4ffe021c6b4b157d8b3a9e69ce6a3c4d7361adb1cf83d947b3b7c4f4"
    $a11="a1fe5f185b6e65143b7b8a37c8a8b2fcf53b58cc4ffe021c6b4b157d8b3a9e69ce6a3c4d7361adb1cf83d947b3b7c4f4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a1="472e0334c19bf2a8e1b0a703c62e0ed0bfd823efbc3a29ea1320f1b4f6c00b7741db929400779b3609c1641fb9b205d1301ab5983d7735f3fa21a96500b0d532"
    $a2="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a3="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a4="b45387d6ffc14bf82fdd5a1502e04f82bc8ef7d3aca5b14a26bc7bbce1b262c47404b1a5ea25c1605b19f82b52c8aab2de3e30f2f9ab3a470947a1f1cf80d841"
    $a5="a6619c87639fee3540a1127ddaabdb0543cc0ea2cad151796276ec0474179b3897a4a6eb1b274afbfa0653a2ddb4b4562e2472a7aa89b6691f9f6862a13332d4"
    $a6="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a7="a042b8def54466d33a9fa2de436041aac98bb190a245f7829b0f1ee858568e115ebb963491f5aabbec1e69d7deee0bdcf846bc626029b59ad517f520aa6a8f21"
    $a8="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a9="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
    $a10="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
    $a11="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YXBjdXNlcg=="
    $a1="YXBj"
    $a2="YXBj"
    $a3="YXBj"
    $a4="UE9XRVJDSFVURQ=="
    $a5="QVBD"
    $a6="cmVhZG9ubHk="
    $a7="YXBj"
    $a8="ZGV2aWNl"
    $a9="YXBj"
    $a10="ZGV2aWNl"
    $a11="ZGV2aWNl"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

