/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ruckus_wireless
{
    meta:
        id = "1a1Kn7Ps4s5KdaDhomPSR7"
        fingerprint = "a62d35a570568aa2ea8b7a8b2bf6bd9799f95ada999e3d9f55ffbd585228b522"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f3305662ce54c2b07e0b64d22f0c769c"
    $a1="fad2607eda55ca3ecf8d89067ee91f84"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="f3305662ce54c2b07e0b64d22f0c769c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48bafdfb7dee634f"
    $a1="60c033095644bd16"
    $a2="5d2e19393cc5ef67"
    $a3="43e9a4ab75570f5b"
    $a4="48bafdfb7dee634f"
    $a5="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8A3C48B214207AC133B8A5C1416FC0924554C5F6"
    $a1="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
    $a2="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*8A3C48B214207AC133B8A5C1416FC0924554C5F6"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}yD1tbf9xFGpr3rtM03p1Yg=="
    $a1="{MD5}GzIxZVzrt6H3g+3fJ9JUyg=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}yD1tbf9xFGpr3rtM03p1Yg=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}PZKFGpBlgrBr7wEQqecmkNuhzHU="
    $a1="{SHA}hFG6ihTXl1PTTLM7UbpGtLAl64E="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}PZKFGpBlgrBr7wEQqecmkNuhzHU="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c83d6d6dff71146a6bdebb4cd37a7562"
    $a1="1b3231655cebb7a1f783eddf27d254ca"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="c83d6d6dff71146a6bdebb4cd37a7562"
    $a5="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d92851a906582b06bef0110a9e72690dba1cc75"
    $a1="8451ba8a14d79753d34cb33b51ba46b4b025eb81"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="3d92851a906582b06bef0110a9e72690dba1cc75"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b74395f13122cabb61d5a81c202335e8576cbac16b266054d8104c226e01b0a631a3c21af9e706c867c7ece2a0556323"
    $a1="4092bc3d8a0d7a293f438e15d1a039db25c54342ad87c3d97b4d0554fd6df01bf61704aa1bfe6fdc51c077212a1841e8"
    $a2="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="b74395f13122cabb61d5a81c202335e8576cbac16b266054d8104c226e01b0a631a3c21af9e706c867c7ece2a0556323"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ab7ad1292e425ab214b232aec809222903f78a2101fb079060a52bb"
    $a1="0f726b72946abd860c0972fa8b50fc3c7ee6edcdeb23b42d6684e708"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="7ab7ad1292e425ab214b232aec809222903f78a2101fb079060a52bb"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f27c7c3a46cb68f033a8084ba1d01532b6fd2c44ff5ce5dc956fd1cdcd0ff20dff4720666acc751900daf82893337c9adad80d67bc2bd16188d7ec8f2a96871b"
    $a1="36379d8584770820d95741c8efe571cc0ab37e2021c505fd8f384724d0676020ebc6d4f318e2533acf708fab8ede09c950a8daef54299ab9ea5ba1e1fd4b73bf"
    $a2="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="f27c7c3a46cb68f033a8084ba1d01532b6fd2c44ff5ce5dc956fd1cdcd0ff20dff4720666acc751900daf82893337c9adad80d67bc2bd16188d7ec8f2a96871b"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8bf970626cfecd259f2ad2eb8115c5ef815d55d7c15738db8caac198fdf2d7f8"
    $a1="73d1b1b1bc1dabfb97f216d897b7968e44b06457920f00f2dc6c1ed3be25ad4c"
    $a2="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="8bf970626cfecd259f2ad2eb8115c5ef815d55d7c15738db8caac198fdf2d7f8"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1eec3d5027a51595573b0a6f4fec56b7b25a8376e18fe5f30b5de1e7343861ab7ab7479e0138cd15853632b41d5f7b2ba4de9f400af8b6d98588b39bcbea90ee"
    $a1="da8d291e0916119783bb03757c6252fb55ea1d51bfb05e3044d676a827ad9afd002fcfdc5706406cb66b61cea06b9ba64f895d7e66b8aedd5bd84182b9b46fe0"
    $a2="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="1eec3d5027a51595573b0a6f4fec56b7b25a8376e18fe5f30b5de1e7343861ab7ab7479e0138cd15853632b41d5f7b2ba4de9f400af8b6d98588b39bcbea90ee"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6efcc5adadff51e5d5272853de5c2a43943bf5babfd325814178920d5bdc8a2c"
    $a1="7b866d188933ccc5dfc6f79bd6366c759f7661ff500626bc1b013b6947eb5831"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="6efcc5adadff51e5d5272853de5c2a43943bf5babfd325814178920d5bdc8a2c"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8d0e89a52352fe63c628c77029b35dba84279413467016ce455fc5c"
    $a1="1bbdd3ab361d7fd9a47de72543e337093aaa664a02248557615675c4"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="f8d0e89a52352fe63c628c77029b35dba84279413467016ce455fc5c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26e702cb0b9996a2f6270632821a53f8fe3f1a49f45ed0095bf687452c4ed11a"
    $a1="79de1c617efcf3d784ca3b5d1be7fefb1d1287b079fe4527640c36446cd29ea0"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="26e702cb0b9996a2f6270632821a53f8fe3f1a49f45ed0095bf687452c4ed11a"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0be81c0501f4a2cbd2fb6522b225f2c19913bcf5bfde8d51a06ad2f1b3fdda78fb6bbdb8345fb77632967ceb92877cd"
    $a1="a42d04a5b4a2ea45ecf45279aaf3ec8fd906355e3ab856231ae7815a5df6a96f76fe4987dd638981314c942ba825de69"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="c0be81c0501f4a2cbd2fb6522b225f2c19913bcf5bfde8d51a06ad2f1b3fdda78fb6bbdb8345fb77632967ceb92877cd"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a19b1fcb5374562b4a5c28dde363d2730f3f13ae33395c939206f1207e82918d7208d3aedf43a2ac98239c7d0e3d3d3fba73849c0d6c376ee760c07f70daf829"
    $a1="a5cb39ab7a85e70d39ae78b734b0f42660126100c6d458fdd3f8e6b20ab8f73b2db2a02a0ca8d38d40b6b2544be6491243703c5770cbce76385c2e3a9c791f36"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="a19b1fcb5374562b4a5c28dde363d2730f3f13ae33395c939206f1207e82918d7208d3aedf43a2ac98239c7d0e3d3d3fba73849c0d6c376ee760c07f70daf829"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3VwZXI="
    $a1="c3AtYWRtaW4="
    $a2="YWRtaW4="
    $a3="cGFzc3dvcmQ="
    $a4="YWRtaW4="
    $a5="c3AtYWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

