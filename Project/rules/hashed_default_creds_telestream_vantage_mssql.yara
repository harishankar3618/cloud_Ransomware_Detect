/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        id = "6TLh3Hvsk0AYZmeD77zriU"
        fingerprint = "588c93f2a34875d4a5f35164ab419d61163ec0efa8ca5174d8b6206ad5a70294"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e168c5f2e53f5fd9db4a149bb57a15f"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1095e31046995ef6"
    $a1="077ff75a4925858c"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*17E962D9A5242BD7DF3B11A8AC0BAFDA6C788959"
    $a1="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}lCDjnUFQEWbDq4uS98x3pg=="
    $a1="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}rQ5vPv218SfH9dzhULTebJQ/e9E="
    $a1="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9420e39d41501166c3ab8b92f7cc77a6"
    $a1="c12e01f2a13ff5587e1e9e4aedb8242d"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad0e6f3efdb5f127c7f5dce150b4de6c943f7bd1"
    $a1="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b4ab4d896a849d6d743926b32a1ffa213f99d134b06f04db0bff749406b56465db920d00ad6b216c9a9fe1588c863ad8"
    $a1="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eac3ba748a4627100d3e34229d6ad50e7a052d345668614731254654"
    $a1="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="395fab32ac3a4da86b80aa274cfbf4e5a14c3cdb051fdb2fd600310857d3efc2f1967935ee0e29414699a430f40cfa34d0c6d9eb4dd0a399726e034daa692212"
    $a1="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be7578b8c1c3c574143b3a8c1ecb24fde889a90c8a5b433e95ed166a647e1b8e"
    $a1="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="333a49c25923b180cfb332b7bd4fae451a9004db66630fe649edbbd5f7425e74bfbc1fb0838207f1a95c851470dea39c0a568b11d84406e1a4f99e50fcddd86f"
    $a1="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="763447f877e416e379cb0276229f1582f58274b5aea8fdebf868ff03c845e6f9"
    $a1="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2345ecb1b5afc18f76e0e9062552879c81bd029fe9d17cfd9785048"
    $a1="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29ced6b7dc96a2e74d207e1328154bdda24050c76fc98d27d07903334d44a7d7"
    $a1="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a39b1049da1d00531eead669f1477f8204e0a32e2f240aab68888c7e6d4e9d658937f312203fd38de820e9ab4f692ef"
    $a1="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bd4950c106d9bccb3bcaf3fe9db9e12cf8c671226ea315e97f8068aaaa28dd65a1cdb694f38da90b1b3416888ccc3026e1c94ce8c1e16727d0bb3e0327a5eae4"
    $a1="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2E="
    $a1="dmFudGFnZTEyIQ=="
condition:
    ($a0 and $a1)
}

