/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_omron
{
    meta:
        id = "3AjCgzCYfSudfE5bez4emr"
        fingerprint = "81b9880e30c1874878182d5e296c9f6a9d318dc3d91418f204dcf7c8ffc14137"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d891ab402caf2e89ccdd33ed54333ac"
    $a1="7d891ab402caf2e89ccdd33ed54333ac"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a1838273cbc9961"
    $a1="0a1838273cbc9961"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*69156C3775BC63A03BDF56AD0B48E2BE5DF601DD"
    $a1="*69156C3775BC63A03BDF56AD0B48E2BE5DF601DD"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}wh+Wm18D0z1D4E+PE252gg=="
    $a1="{MD5}wh+Wm18D0z1D4E+PE252gg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}dQXWSlTgYbes1UzNWLSdxDUAtjU="
    $a1="{SHA}dQXWSlTgYbes1UzNWLSdxDUAtjU="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c21f969b5f03d33d43e04f8f136e7682"
    $a1="c21f969b5f03d33d43e04f8f136e7682"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7505d64a54e061b7acd54ccd58b49dc43500b635"
    $a1="7505d64a54e061b7acd54ccd58b49dc43500b635"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="42f7113044c011e770740189f408d58fa50b795bd67a83a5dffe7b31a6463841de17df777ecbd9666ebb69e3a5be7d32"
    $a1="42f7113044c011e770740189f408d58fa50b795bd67a83a5dffe7b31a6463841de17df777ecbd9666ebb69e3a5be7d32"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0e8b3c2dda2512b55e4dc5d4859b1877e98109c7c4e755ccd2a5763"
    $a1="f0e8b3c2dda2512b55e4dc5d4859b1877e98109c7c4e755ccd2a5763"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1625cdb75d25d9f699fd2779f44095b6e320767f606f095eb7edab5581e9e3441adbb0d628832f7dc4574a77a382973ce22911b7e4df2a9d2c693826bbd125bc"
    $a1="1625cdb75d25d9f699fd2779f44095b6e320767f606f095eb7edab5581e9e3441adbb0d628832f7dc4574a77a382973ce22911b7e4df2a9d2c693826bbd125bc"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f"
    $a1="37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a3712e2b92f69ead391b691710a587f21fae1e7b83b94b7835344eed1c463cfe03816e61922646f7aa0b581f3ba35842b12e556b2e4e0644c0f1d1d0549a79f"
    $a1="6a3712e2b92f69ead391b691710a587f21fae1e7b83b94b7835344eed1c463cfe03816e61922646f7aa0b581f3ba35842b12e556b2e4e0644c0f1d1d0549a79f"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f38de7eea698e71df046d36abca9a5d7ce3f82f829f4b8c0f54a6334209985a"
    $a1="4f38de7eea698e71df046d36abca9a5d7ce3f82f829f4b8c0f54a6334209985a"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
    $a1="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
    $a1="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f437f71603b12fec1a4c1cdf46af48d0274fc3da86d451c00285697137cd82fb803b543f025e4d4549eb5efb514643c8"
    $a1="f437f71603b12fec1a4c1cdf46af48d0274fc3da86d451c00285697137cd82fb803b543f025e4d4549eb5efb514643c8"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fbaf1d3516e4849991e8eaa16e401a9d0cebad944297cd80022f9424c8d9d172f7cc94844f529cca51005498f56ca90672ca918cbbfc06c0071b9c12b98f89b6"
    $a1="fbaf1d3516e4849991e8eaa16e401a9d0cebad944297cd80022f9424c8d9d172f7cc94844f529cca51005498f56ca90672ca918cbbfc06c0071b9c12b98f89b6"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZGVmYXVsdA=="
    $a1="ZGVmYXVsdA=="
condition:
    ($a0 and $a1)
}

