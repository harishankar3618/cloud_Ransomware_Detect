/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_xzeres
{
    meta:
        id = "2ZbPTKGsjTsSQA1JVgA1JL"
        fingerprint = "0202941819faa7145312b732c08c05c53f7d7d02b46395d6120bcacdc3381bab"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e681cae8a397031b20eb9958894cf8d7"
    $a1="760527cd2d1d25951523f858c7806311"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="349451f95f3d75b4"
    $a1="53feaebd57704d7e"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*981643D2333B77CB4EEF14DAEED10A853A2FCE13"
    $a1="*7F0E6F44431365892C3537F43D0424C990699D0A"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}YGEDO6eaedvSXZy22juXQw=="
    $a1="{MD5}JdpwcmTSc3ttZZ1vZp5+JA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ZRE3BweqiGTYrcLpGy62hvDr0Hg="
    $a1="{SHA}0030bVAZN9IekDrBo3GZfRZyd5I="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6061033ba79a79dbd25d9cb6da3b9743"
    $a1="25da707264d2737b6d659d6f669e7e24"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6511370707aa8864d8adc2e91b2eb686f0ebd078"
    $a1="d34df46d501937d21e903ac1a371997d16727792"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f176d95b83e3fad5d0bef9013d42e52b62de341c4bbab8fef12c2313d1350472f26d832dcb74d7bde47a7227d904b84b"
    $a1="62d35c44b07b37fa595e75f066f8aa1f8aeb5567bd99671e10603cc4a53c721a035e35cca06ba75d5c0ac42757ca84c8"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8110db162ea239766dbb231dc50a3b9b0e6ab075492c048f56ddc441"
    $a1="6e6951a88f2fe43d973c72634c76725b4e0e83b8aa783e38faffa983"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da75acad5566bf640b2734140b546efe1b7115af33f2e87867d3d71e6b7939eeb9cff083f747500281da3cca46a4be217a9df90842481526a6afbc18aed3e185"
    $a1="754a07b4c5e5976695a1e8d4220c30167d9ad299e292d91e1fd21da6abe79f383e74a75d81cf5c46f783cff99fcc9114a1772fb2bbc779f9bf4571575811a240"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7cd7daa72e252b87c857cdc16b32a5f8a50472011c3f189519ba849a1c401432"
    $a1="3d88eee185288c2628121c261f7cc8c4974511d3e11fdc282d99765bdd4abad9"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f015cca82b7e8dee81fe1e848143b8baf65cc78ba8cb987ceba93e261a5fd3b76ee12a9986e1420d1921813228ca465508c567714331312afe98600ecb2c35b3"
    $a1="09d2b5594542c7d070d694657395ca2536497d22dc0a31eac8b559e905f6129eb4b411fce2146c9ecb29005811b856075f80cacf13fbbf91db2e57265b290616"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e88ffbe5daa08bc897c42df4800388033c44b709bccc43ec402febfdf27e154e"
    $a1="c792b79fe15775d690b9111ab3231af28796bb38bb39f7f58185a20fe1c05611"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b1b5845817f8718552915219129b26f425955442ce11a229dd3558a8"
    $a1="081b69b06364f0f59828f1a54db5c297d773f11956907f9b3b6718fc"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90e6214bbec1ea92e239ac7bc3f41465bf4cf61a166d6c6549947dde4c9d1f48"
    $a1="861da640dfdb2d83d8c0620db7bdb33739fbf910406c2f42bf6b3dca610f37d4"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a819a40f4c31d74e30355c059eba6bc0cafdb2c2b8721dc1d37cde57d0a610db53c722a9ce37d0702cd19dfefad491e"
    $a1="0c8d5f70aae8cc9ec266e32b7160485adbec1f40c43b4957f143042bbf713738eae27f63629ace1b81b49f479bdb08fa"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="27d26f0dbd2f196cbfed387e9d20a0212bbe393526e2a1b7a087daf685fa08c3f3dee888d40785deb7fa8f693b79ce051c85bf3e6913c8d10278f23f65099d85"
    $a1="5eb357f631c3d51249eb289d202ab341050cb40eeb35e1ffb3224fdfb3e478b36750312c592fc20f1a5c8de1c2b7b290940e518dd92c982238f0c1e9d719aa17"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="TXlUdXJiaW5l"
    $a1="bTQ0MitTUnQ="
condition:
    ($a0 and $a1)
}

