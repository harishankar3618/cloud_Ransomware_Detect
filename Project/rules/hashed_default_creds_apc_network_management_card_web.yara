/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_apc_network_management_card_web
{
    meta:
        id = "5r9waC7Cq1YBzTMAQpc0Xf"
        fingerprint = "c59764836af40358a43ff6a7b5d514a9b036a1b1943fc35afce4a789e9bc3f55"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b96670ba87df193012a9b0ddbf14c634"
    $a1="b96670ba87df193012a9b0ddbf14c634"
    $a2="b96670ba87df193012a9b0ddbf14c634"
    $a3="5d93591697ff29acfa4eb6a086205cf1"
    $a4="b96670ba87df193012a9b0ddbf14c634"
    $a5="dddbcb37e837fea2d4c321ca8105ec48"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7cdcc46a2c1a585d"
    $a1="7cdcc46a2c1a585d"
    $a2="7cdcc46a2c1a585d"
    $a3="0dd0751e564477c7"
    $a4="7cdcc46a2c1a585d"
    $a5="55743dec57707aa0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a1="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a2="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a3="*61342F052E319D36B0E6C984AF680C4087210453"
    $a4="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a5="*922A4B420903CAD4E7FC56A23122AB927E051FE3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a1="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a2="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a3="{MD5}kT+cSdy1ROIIfO4oT0oAtw=="
    $a4="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a5="{MD5}M267sheb6qc0Ck8WIPOvQA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a1="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a2="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a3="{SHA}86kpszZLRxpIH0982gtFWezemro="
    $a4="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a5="{SHA}midxgpchjDdXw2XTV9E/SdD6MGU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a1="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a2="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a3="913f9c49dcb544e2087cee284f4a00b7"
    $a4="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a5="336ebbb2179beaa7340a4f1620f3af40"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a1="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a2="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a3="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a4="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a5="9a27718297218c3757c365d357d13f49d0fa3065"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a1="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a2="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a3="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
    $a4="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a5="3ce313ec5ea0e8e20c6d3e0a70418198cd3cc1a54bb1e51f1a3135dc03d014e20f3387875bba5f5d37e54100b9535762"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a1="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a2="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a3="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a4="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a5="c3352c01875335502f888606000fee7f03bdf8331037cec22a1bb55a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a1="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a2="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a3="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
    $a4="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a5="ff3d9d060c06599e083d26bcdffd24b51c68e3a7cd10859d6763701e31dad0debdaee7085b95e7b0c5f9c535d5e031e75e885fde7a6056065fce009f597345c9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a1="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a2="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a3="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
    $a4="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a5="8171bacf32668a8f44b90087ad107ed63170f57154763ba7e44047bf9e5a7be3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a1="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a2="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a3="2efa3755160d85e0ddc6a827f9a458a19829a83d286f0b6a46960491558320e74a3dc092986ead0b95e0ade7e368e363056a1396fdba590669fc1e631edf11ea"
    $a4="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a5="8d2f4f0bac20160beccfa32131beeb745b19fa24352e74356659edf6e463847b91130101ef25bf20d2cd8bb46a5b3558f5fe28361c15ca6e6513160d569c9592"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a1="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a2="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a3="f7a7eba9542ac5dd4d5abd94a46de7b8c5f09c5d530ebff4a8f698bf25487fdf"
    $a4="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a5="97c665ef42239cceba9e65db0a1123f2b3de1891ba4462778304b1e07c4103a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a1="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a2="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a3="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a4="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a5="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a1="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a2="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a3="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
    $a4="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a5="057d1b930b9c8e962bf34656a2c010888ae6a2a5fc4de074ecc8cb3bf4782685"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a1="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a2="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a3="a1fe5f185b6e65143b7b8a37c8a8b2fcf53b58cc4ffe021c6b4b157d8b3a9e69ce6a3c4d7361adb1cf83d947b3b7c4f4"
    $a4="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a5="0e08ace98462c032a1d1ef35387532a39d62bf837abfdfd1ac221c6a070fe0e064ce07d88c6004e63d55d1fa8d508327"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a1="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a2="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a3="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
    $a4="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a5="a042b8def54466d33a9fa2de436041aac98bb190a245f7829b0f1ee858568e115ebb963491f5aabbec1e69d7deee0bdcf846bc626029b59ad517f520aa6a8f21"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YXBj"
    $a1="YXBj"
    $a2="ZGV2aWNl"
    $a3="YXBj"
    $a4="cmVhZG9ubHk="
    $a5="YXBj"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

