/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_echelon
{
    meta:
        id = "6cKalYLqNwFQ9SrtNcYjue"
        fingerprint = "3d0d2d5033a56f167450339fb3e81e7b975caf8ed7a57182205db0257d32aa34"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff765d296da26840854d84126e8ddfb2"
    $a1="ff765d296da26840854d84126e8ddfb2"
    $a2="2c51b2ab1045cc2da80d9a352281521a"
    $a3="224c410159eebdf789c9d9f3104242eb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74e9bbcc68353655"
    $a1="74e9bbcc68353655"
    $a2="753dd70c6b66f0cb"
    $a3="48eb983013f7ec1e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*75591BEA199F4B87A22B5ED7A4972DDAD059DDDE"
    $a1="*75591BEA199F4B87A22B5ED7A4972DDAD059DDDE"
    $a2="*59E5082E5C8A6E41D84407C596AE0AC2E21F1BFA"
    $a3="*8FE3F9FC6BECFCB7B0A52444E72F244C01337154"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}1T1iBWuHjxaNWlYO3XtGaw=="
    $a1="{MD5}1T1iBWuHjxaNWlYO3XtGaw=="
    $a2="{MD5}ksx1aKPgfEuCoWbpyr9/HA=="
    $a3="{MD5}OonIUaME8oV3urxCUr5rTQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}b2wsg6cxqfFUKkr7tF6gQ5xPRco="
    $a1="{SHA}b2wsg6cxqfFUKkr7tF6gQ5xPRco="
    $a2="{SHA}/2qp8tFh8PT66EIjVjQSlnSqIug="
    $a3="{SHA}yZ3znnj5XMv00/x9ISoPpa2QdCo="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d53d62056b878f168d5a560edd7b466b"
    $a1="d53d62056b878f168d5a560edd7b466b"
    $a2="92cc7568a3e07c4b82a166e9cabf7f1c"
    $a3="3a89c851a304f28577babc4252be6b4d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f6c2c83a731a9f1542a4afbb45ea0439c4f45ca"
    $a1="6f6c2c83a731a9f1542a4afbb45ea0439c4f45ca"
    $a2="ff6aa9f2d161f0f4fae842235634129674aa22e8"
    $a3="c99df39e78f95ccbf4d3fc7d212a0fa5ad90742a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="645104a1b9c7b10e0a1a2d11cc7030360c50eff1c9a6187d4c1318dd9a861ddad42062f1e7c980c3c0e39471e84d7499"
    $a1="645104a1b9c7b10e0a1a2d11cc7030360c50eff1c9a6187d4c1318dd9a861ddad42062f1e7c980c3c0e39471e84d7499"
    $a2="7c5965f7106a8cf01d45360fdec51568189b9a0b3bf69b90f2a978c303819d82701e3aed9aa512e41f9d12bae4d21f8b"
    $a3="e757449617a5368e0ae8982d59e258a820e72fcacb7d71ed6b69e0c6eb28c6a7e4cc530626dd1023293239c403023998"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9dbfdebc83bb85be8204293e1ac7ab6aab8e6f07b2521f5ca608196"
    $a1="a9dbfdebc83bb85be8204293e1ac7ab6aab8e6f07b2521f5ca608196"
    $a2="f627abca2eca9ad27bf89b9afff4cdd60b4dd361c314de203632b633"
    $a3="5cd534249a0867d4243f7192f71dd46d37310097d3d70b1582dd6751"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="148f853770daf506693ab8e09f613e7df214b423babf090c536f320cdf576b5fb1784f65ed8268984913bd8e75bb7815ec5205b212b922a22834d5b6e399102d"
    $a1="148f853770daf506693ab8e09f613e7df214b423babf090c536f320cdf576b5fb1784f65ed8268984913bd8e75bb7815ec5205b212b922a22834d5b6e399102d"
    $a2="c4658ba1be4cf84908c075c2ae2b3d8489a4710dbefd2de93dcd9d14d88fe926f5be68848bc48b633556a4f35f44cd6ccdf65486f9c5796ebbf1fa20466c219c"
    $a3="2b4dfa3e3dc5474deff172459e10e4e95d3f2da8a6d65cffb9459440b0807455a3ebaba7c4de11526bf07b7403c07cd423c63069e818dd4b640f5b17f701e39e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31e50f4c66b3b08e8affd2c8c7e8de9a925372a15b0ac20c469dbc21e8dc1c01"
    $a1="31e50f4c66b3b08e8affd2c8c7e8de9a925372a15b0ac20c469dbc21e8dc1c01"
    $a2="a0628e2238c62a61e33789e81984de5e41ba58b85d4c7452564f2c158b3a4347"
    $a3="f2e1af85c2ff9a94981bc96e57b960e1e497f9379613311a2310e0449ee7723c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bcad1d03c904223ac62a9850aa31b6af3468cc8f2820efad5f1b1c03710524df47f121462b234479d18be292a57940225ffc12c8a111825de7c4fdbca19f77e3"
    $a1="bcad1d03c904223ac62a9850aa31b6af3468cc8f2820efad5f1b1c03710524df47f121462b234479d18be292a57940225ffc12c8a111825de7c4fdbca19f77e3"
    $a2="4bf4f3232214b372b598506b89b952a6af81ff193169f4cbfe1359a6cf90d77a6ff104050c04c1c17be03e6453127a8e7b4aea591f673219973075cc791c7df2"
    $a3="b192b944e41f8684230ab8c1ee2bfd190b9d5c759d6d40b28d6601b5a974c3a11f79b751b60bb14c1775b4aa99a64d308e984d4f2750064135eb0447456a33fd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5756d18256a7d25364cc470f20e1d507b17ed879fad7fe484b9140cd8f4034a6"
    $a1="5756d18256a7d25364cc470f20e1d507b17ed879fad7fe484b9140cd8f4034a6"
    $a2="89327b6fe3ff58072b91e5db974033aa1d3a045a49393c3b615a43cec28cb9d7"
    $a3="eccb5cd52034303a3c88c8e59400bee1391b26346e0774238eee2796c469f3fc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0ee18d48831bf830553f88ec9ad9c8dd3b81a8016620d68f34039a3"
    $a1="f0ee18d48831bf830553f88ec9ad9c8dd3b81a8016620d68f34039a3"
    $a2="93344d3d133e51d0aedc85a0e8910ba726347178db13a8c3a9419577"
    $a3="b88d4fc9071df351fa3841d418d46571fb3918c18ba9b3d5800bc1a5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c96d4251251492e3f5a17cd90cea0224932e4851321a2264abbad37683dbd2e"
    $a1="5c96d4251251492e3f5a17cd90cea0224932e4851321a2264abbad37683dbd2e"
    $a2="424eadc41c02be1e3b82f976fd9294a62f29d0536a75869bd40e212a3409b9f3"
    $a3="ba1a564a4a50e0cb98951923e3b0c1fa6fba2841eddc4984f6dde5d8ee2de0d8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22b04b08a93d823f398886cd248706707270de24134156b7dcb73c39072a64d864a5f48555912542ad850e7724022ccc"
    $a1="22b04b08a93d823f398886cd248706707270de24134156b7dcb73c39072a64d864a5f48555912542ad850e7724022ccc"
    $a2="3277048881406436896ad8ff320250609f161c8d03de6bb78d12e1a1602324100cbe1571d2e37c6786d2901c937901e9"
    $a3="6ca48b0a091f344d7ec10291910f4de7911c297591552047faf40c35c8cedc7848c6225e8032f0e0a6a4e86e70973c68"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2eccb593b748c043fecf5dcf9f9af9126b45c5f5eca95d7ee3d223585ab4f3628b1753ea168df21376f6e5dd9af0cf0b1b48ee78367d01589d5ca1019a1356c5"
    $a1="2eccb593b748c043fecf5dcf9f9af9126b45c5f5eca95d7ee3d223585ab4f3628b1753ea168df21376f6e5dd9af0cf0b1b48ee78367d01589d5ca1019a1356c5"
    $a2="090f304f4a56d59acbe2103b05204ff370a28c2309ff0dc8223a8e93515d269b5d8096906e2f8424930e957cd0421200a8b52a0080cff0efa14d8d91f8c2dbb6"
    $a3="c91b2b4093bbf2b10d9dc2552da14de9e7dae514b9af39073c4d54f7a25b3e96c85696a4fa54d643ddf3f76b57aeccb06a266d4625f7a3ebaab7a2ec2fcfad5f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aWxvbg=="
    $a1="aWxvbg=="
    $a2="RWNoZWxvbg=="
    $a3="ZWNoZWxvbmNvcnA="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

