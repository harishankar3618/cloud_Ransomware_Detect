/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_microsoft
{
    meta:
        id = "66tdNWD9yvpfloP1Nbor8k"
        fingerprint = "664071a91bb4e506c5dd9856b40bf6d809b026b5e87e3867a0db31df798ba7cd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="57d583aa46d571502aad4bb7aea09c70"
    $a1="c88c185ef8deec9b9c846743be92bd68"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="0280777f37d4f4e7c478d21cec701463"
    $a5="0280777f37d4f4e7c478d21cec701463"
    $a6="d144986c6122b1b1654ba39932465528"
    $a7="d144986c6122b1b1654ba39932465528"
    $a8="3d2b4dfac512b7ef6188248b8e113cb9"
    $a9="3d2b4dfac512b7ef6188248b8e113cb9"
    $a10="0af2b9053748dca06c597f4b2573f9f3"
    $a11="0af2b9053748dca06c597f4b2573f9f3"
    $a12="962e17f6e8204b0586fa10e2df266f60"
    $a13="0b949d4edf5126e318fb50a92e8f6ce7"
    $a14="79e7bfe8a33cb4c2ea6c83541aeffc3b"
    $a15="79e7bfe8a33cb4c2ea6c83541aeffc3b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule mysql323_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a486e7929011a28"
    $a1="6013e7eb6ba4d801"
    $a2="43e9a4ab75570f5b"
    $a3="43e9a4ab75570f5b"
    $a4="15f73cd91718b388"
    $a5="15f73cd91718b388"
    $a6="58f7ee435f925abe"
    $a7="58f7ee435f925abe"
    $a8="01181bc63be6204f"
    $a9="01181bc63be6204f"
    $a10="4d75470c619b482b"
    $a11="4d75470c619b482b"
    $a12="0aaf5aba5ede3e17"
    $a13="389e2a471f7e3936"
    $a14="7c322543213bc140"
    $a15="7c322543213bc140"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule mysql41_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a1="*EFE1E8118720417EAC0066B7170C12A1126BB988"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
    $a5="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
    $a6="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a7="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a8="*B83A2F73F9E74C1EF54E25B4C8A06A68E40CEDF1"
    $a9="*B83A2F73F9E74C1EF54E25B4C8A06A68E40CEDF1"
    $a10="*B1DD8044491463D5279575D3E82237D749962EFD"
    $a11="*B1DD8044491463D5279575D3E82237D749962EFD"
    $a12="*57870FFA4ACFE2C83807484749C44309587F60E7"
    $a13="*02AB774F64B946E371A4B8B8F6098C39CC4987CF"
    $a14="*8BAF031297D0FC2BA25DEEC2062F5AAD3249E0AD"
    $a15="*8BAF031297D0FC2BA25DEEC2062F5AAD3249E0AD"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule ldap_md5_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a1="{MD5}NeHOrKb0JdyHohJfVZ9NbQ=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a5="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a6="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a7="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a8="{MD5}rbgxp/3YPdHiownOdZHf+A=="
    $a9="{MD5}rbgxp/3YPdHiownOdZHf+A=="
    $a10="{MD5}NOAZHCAXKQ9VWl2d+I5njA=="
    $a11="{MD5}NOAZHCAXKQ9VWl2d+I5njA=="
    $a12="{MD5}yAKykVorUiGV8K9TgD8rGw=="
    $a13="{MD5}ldcCszJrq/UZ3P98uSCvRw=="
    $a14="{MD5}PcJv4xwCmWHTaBEZPmnJGQ=="
    $a15="{MD5}PcJv4xwCmWHTaBEZPmnJGQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule ldap_sha1_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a1="{SHA}d4mzcug02HUp9oqoe4ZHJrtpnHo="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a5="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a6="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a7="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a8="{SHA}+s6D7jAUvcj5ggPMlOLokiJFLpA="
    $a9="{SHA}+s6D7jAUvcj5ggPMlOLokiJFLpA="
    $a10="{SHA}LM6BZM+UFHJgAQs7kWFBNYLMqcM="
    $a11="{SHA}LM6BZM+UFHJgAQs7kWFBNYLMqcM="
    $a12="{SHA}jrZiFZeNk/WLTbcBX7bpgfGGbj8="
    $a13="{SHA}/qCP/I1GrRIDQaSNOPWV2S1r5RY="
    $a14="{SHA}/llLifJ4ZGzDzlmSvIhFGMET4p4="
    $a15="{SHA}/llLifJ4ZGzDzlmSvIhFGMET4p4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule md5_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee11cbb19052e40b07aac0ca060c23ee"
    $a1="35e1ceaca6f425dc87a2125f559f4d6d"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="8f9bfe9d1345237cb3b2b205864da075"
    $a5="8f9bfe9d1345237cb3b2b205864da075"
    $a6="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a7="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a8="adb831a7fdd83dd1e2a309ce7591dff8"
    $a9="adb831a7fdd83dd1e2a309ce7591dff8"
    $a10="34e0191c2017290f555a5d9df88e678c"
    $a11="34e0191c2017290f555a5d9df88e678c"
    $a12="c802b2915a2b522195f0af53803f2b1b"
    $a13="95d702b3326babf519dcff7cb920af47"
    $a14="3dc26fe31c029961d36811193e69c919"
    $a15="3dc26fe31c029961d36811193e69c919"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha1_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12dea96fec20593566ab75692c9949596833adc9"
    $a1="7789b372e834d87529f68aa87b864726bb699c7a"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a5="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a6="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a7="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a8="face83ee3014bdc8f98203cc94e2e89222452e90"
    $a9="face83ee3014bdc8f98203cc94e2e89222452e90"
    $a10="2cce8164cf94147260010b3b9161413582cca9c3"
    $a11="2cce8164cf94147260010b3b9161413582cca9c3"
    $a12="8eb66215978d93f58b4db7015fb6e981f1866e3f"
    $a13="fea08ffc8d46ad120341a48d38f595d92d6be516"
    $a14="fe594b89f278646cc3ce5992bc884518c113e29e"
    $a15="fe594b89f278646cc3ce5992bc884518c113e29e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha384_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a1="e05524aab2c15fd593e47a7a2825ffb72cb6c00f2914746abd10d15a0e6c0b519e1b5142a7acf028f3dbdc470933cc0d"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a5="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a6="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a7="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a8="4477d2e5351a588186edc3371e30f1cfb64ad5f01aac0c504340342e70dafc3343c0b3e878327a8263e11ecf8dd33b30"
    $a9="4477d2e5351a588186edc3371e30f1cfb64ad5f01aac0c504340342e70dafc3343c0b3e878327a8263e11ecf8dd33b30"
    $a10="d0f2bab80e7001a42d089c4c154253e8cb6032c8d41cf2b98c3877746d2257ad5f5263b6e220042654f673703330dcc7"
    $a11="d0f2bab80e7001a42d089c4c154253e8cb6032c8d41cf2b98c3877746d2257ad5f5263b6e220042654f673703330dcc7"
    $a12="691e16b9e4df16b70819d1f6cd9fc1774b62662dfb6b84bcbd7765445ceb74d1e3e325384276aaf6f822bddede03505a"
    $a13="014b8471ea2d98f7a19b1163cedf51d8a1c870cd09fa9fa6fb02b7aab25e2d9e8261f12edd43b8b8df892c93a4829dfd"
    $a14="5c24134fe6a8a72a061c157f7191dcb3dc02d203cb69ae5d1ea418adb64746fb6a4378ac307cf45978a1f3d536ad8a29"
    $a15="5c24134fe6a8a72a061c157f7191dcb3dc02d203cb69ae5d1ea418adb64746fb6a4378ac307cf45978a1f3d536ad8a29"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha224_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a1="537d21880c207ca6f1620fb66775e8eea6eb0394be15c277671dd27d"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a5="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a6="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a7="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a8="1c95d70b4960a674e2c8a0e86c3a2ada419b9b7534912790666ed9bb"
    $a9="1c95d70b4960a674e2c8a0e86c3a2ada419b9b7534912790666ed9bb"
    $a10="4cf7c11763549176ffee1d55608d7eb9d0b1166d96bf656863180349"
    $a11="4cf7c11763549176ffee1d55608d7eb9d0b1166d96bf656863180349"
    $a12="b87945fdb5d23cc40c1561895cc904d1a47815dd6b57fe76c418a21c"
    $a13="c7dd2cfe31cb55b8e77585868c1e67d35b07bd5dfaddc29eb9a6e5c7"
    $a14="1386e45ec7d12980a14ade12e3319d62e19aa056b522b1471abe899f"
    $a15="1386e45ec7d12980a14ade12e3319d62e19aa056b522b1471abe899f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha512_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a1="ac72823c595544075f90737370209040b73832b48863f7eea6173608bdada5fe7cb8200804c279261700e9f34ecdca882428fb99d02d9d387c35b1bdae8853de"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
    $a5="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
    $a6="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a7="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a8="cc5ec2b61fbbdd18d85dd14ab60db397b21b5548999a6afd3ce9557b19c300494a5fd29987e03a6f06677c209b88de47684388de8250671cdd778799eecd018a"
    $a9="cc5ec2b61fbbdd18d85dd14ab60db397b21b5548999a6afd3ce9557b19c300494a5fd29987e03a6f06677c209b88de47684388de8250671cdd778799eecd018a"
    $a10="b1a5ba82f1c803ab4d3bd2709b81a51c81c90e55bdede64d6c4f66a9d5336dc9237c34c2e52184f8091fe96b5fbedb541b48a3f0861fe74ee671acc7c6c93e6b"
    $a11="b1a5ba82f1c803ab4d3bd2709b81a51c81c90e55bdede64d6c4f66a9d5336dc9237c34c2e52184f8091fe96b5fbedb541b48a3f0861fe74ee671acc7c6c93e6b"
    $a12="d098688148ccecc39ec1e57d291d29cdb58666259953d2e06f9afc091a4bdcd8bcdeae524401e68fb62f821763c70e075de83107d1cf7aae60ec8d79ae49d33b"
    $a13="92f3959e62fd73ae608d9b856c0f050ef9f742fdc24a472350c879def5251ac43bbdd6c2f7092a0c6e95f0f1ea0fc6e2704b5e764559f406177521b504618b5f"
    $a14="0619e15727bb9b77c6af3cc7c1431a346ae1450a174dc0d375bc6a816a0690c966531084db4e31266fb26535751ce0b9c16b59ec719e8f5af96f099ab80c6796"
    $a15="0619e15727bb9b77c6af3cc7c1431a346ae1450a174dc0d375bc6a816a0690c966531084db4e31266fb26535751ce0b9c16b59ec719e8f5af96f099ab80c6796"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha256_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a1="3df59c6f0ba35199c606b079a1e71879a6cd454cf40be87958bfd7ed0e364f5e"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a5="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a6="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a7="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a8="5ed8944a85a9763fd315852f448cb7de36c5e928e13b3be427f98f7dc455f141"
    $a9="5ed8944a85a9763fd315852f448cb7de36c5e928e13b3be427f98f7dc455f141"
    $a10="2f0860b3cc6d396499ef3be04866af3b885f4c1934e77c346f0ce2443ff0f640"
    $a11="2f0860b3cc6d396499ef3be04866af3b885f4c1934e77c346f0ce2443ff0f640"
    $a12="a4fbcda21d33b11f38ee0f50d2b21ba3c56fd9fccd5444846a46fc7d16fb63d1"
    $a13="cef54334edb669f337fd35144f5832c25e9adb716a7f3f57ee016d6212300c26"
    $a14="f072c365ed726ea6c0e1749227c422b9b2bd63ac130644021d82515afa9ed9be"
    $a15="f072c365ed726ea6c0e1749227c422b9b2bd63ac130644021d82515afa9ed9be"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2b_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a1="cbe8a1a8d9d6dd4de54d15706f91a8acbfb26273847a4b28d543342dd643116d9f7f0378b902a662e3f7ffd44f478d479af21cabe1be7667d5573ac9bd838f6c"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
    $a5="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
    $a6="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a7="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a8="0b38c93bb2e46b2037c88ddccad59cbe1092f2ee7eb24ece6381de92d02f323865d52ac3d5a2a7da513661224b910c258184a1bbe405c9ebe1eabd83633f1e5d"
    $a9="0b38c93bb2e46b2037c88ddccad59cbe1092f2ee7eb24ece6381de92d02f323865d52ac3d5a2a7da513661224b910c258184a1bbe405c9ebe1eabd83633f1e5d"
    $a10="f0b40c1781fad318fd2652c22647cd21de1e330da1f5bd6a8c20dcdfd0bc80c800fbe0871779cc76139c8842759dceac6611931e7c29785f373c145f7bd73daa"
    $a11="f0b40c1781fad318fd2652c22647cd21de1e330da1f5bd6a8c20dcdfd0bc80c800fbe0871779cc76139c8842759dceac6611931e7c29785f373c145f7bd73daa"
    $a12="4f3141d8bd698bc32c08c9f3b6b2c5ec101247cc4f2b4f16f34addeb34a3301f040e0f90d2dd7641345edc262b2565da2ad0a91822ff4439e9bdbac84eec1e8b"
    $a13="34a3cfd9057a121849a9d9c913311797b99da25ec2d0dacfa802e70236e114cad366f5758a3c4f2eab7d650ff844c641760e454d370354b4429fb93875f1bdbe"
    $a14="480144aeed08c6159371cdc11e1521fca92ef8ff3d1dd00e5dbd09912a5387156fe78ae101aefd5a886e24d8d6135b4053a702947735f326a2577681eb450ebd"
    $a15="480144aeed08c6159371cdc11e1521fca92ef8ff3d1dd00e5dbd09912a5387156fe78ae101aefd5a886e24d8d6135b4053a702947735f326a2577681eb450ebd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2s_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a1="36823053efd5881af427a85643737eb92ce445de6dcb24fe04d4478d1687387f"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a5="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a6="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a7="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a8="df4738b4ed2274b73722607a4d1cc2158eb209ef16b350087d867393f98db685"
    $a9="df4738b4ed2274b73722607a4d1cc2158eb209ef16b350087d867393f98db685"
    $a10="2e165bc4791c525b47a7e8df1a45ef56530cded9097fb532c464204c7ed1ef9b"
    $a11="2e165bc4791c525b47a7e8df1a45ef56530cded9097fb532c464204c7ed1ef9b"
    $a12="03c74c30e1bf2e1dea38c9dfebc00cdfd95006e79b56e209adc951f0e9fc9b5f"
    $a13="cae9c5f376efeb3dd5890f146db55c4cb6c4a3779cce7ff9f4ba4e78881f14d1"
    $a14="257c4331c9533c5caece6e4705ba2215ee64029fe71e471736b1337197498d8b"
    $a15="257c4331c9533c5caece6e4705ba2215ee64029fe71e471736b1337197498d8b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_224_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a1="deaecd48a1f6a5dc5238e1f8d5012f425bd7c8b96ba7bbe08229820a"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a5="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a6="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a7="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a8="e810597249305f414f75eb5a9d2644820de439bc4647bbbdd90f702d"
    $a9="e810597249305f414f75eb5a9d2644820de439bc4647bbbdd90f702d"
    $a10="9b50c41c3d8dbc5749eea69cf13855e34c3a42601a53c6189cd80219"
    $a11="9b50c41c3d8dbc5749eea69cf13855e34c3a42601a53c6189cd80219"
    $a12="dd2ca5875d0b78d22778a554da348e9573c5d766eb758ac2caa4e9fc"
    $a13="d3dec77e80bb6f533414323b4dfd739941d4438cb099509b25e56ecd"
    $a14="901a6bbc8420c582476a5e532991e8ad2a6eb47f257e46e7ebce397b"
    $a15="901a6bbc8420c582476a5e532991e8ad2a6eb47f257e46e7ebce397b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_256_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a1="8b8d64102829b2979ae2e3ab9ad13a0323bd0c668b79d1b670d8ad647a84c310"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a5="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a6="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a7="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a8="2848f07d55acfdd67caf77f276e1f0a529e4026f1708356d77b1ced98326836e"
    $a9="2848f07d55acfdd67caf77f276e1f0a529e4026f1708356d77b1ced98326836e"
    $a10="cbf1f151f6c9c7a0d5d9b326167853fb6e7d2331d99256b50babab5e154eb6b2"
    $a11="cbf1f151f6c9c7a0d5d9b326167853fb6e7d2331d99256b50babab5e154eb6b2"
    $a12="8c9d71e8d10351d0543301acf51f98a6a5810b16ca66011a7e2f30c804c7ea94"
    $a13="cd961d181710c60c2a168bb3e999dc30db7ff17f23bb7374edc2e529c9ecd1d9"
    $a14="576c21871d58fe2264f6a583c33d0c35ea41bc24a1ec998efde9551886b91ef8"
    $a15="576c21871d58fe2264f6a583c33d0c35ea41bc24a1ec998efde9551886b91ef8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_384_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a1="81716125a9b6e542bd0736fa4b04330f7fc1ef64eb1390428c7cfd7ddfad29dcaefe8b0bf3615fbdb0570be99b91c926"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a5="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a6="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a7="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a8="6d2bddea82451f8471ec7642ce69af08a2be6845ab02b2d5094fd89640037515a544044c7fbe733a7d26d6758892e60a"
    $a9="6d2bddea82451f8471ec7642ce69af08a2be6845ab02b2d5094fd89640037515a544044c7fbe733a7d26d6758892e60a"
    $a10="5ae3f7721d1cb33db42fad05994b030c8623d75b247f659554457887d93c3f7d05fcd9c1060fff397709331233e7d729"
    $a11="5ae3f7721d1cb33db42fad05994b030c8623d75b247f659554457887d93c3f7d05fcd9c1060fff397709331233e7d729"
    $a12="7cca4bbb98ea5cb8e55c6b10b33d2d07fabeebd47102dbac0c02e5f7fe0cba8d46c54c93da1aecdc932319bf1b55dceb"
    $a13="a0e05ee90a719226b05e3439b3b70d9f1d1c36832f075aff5bf6f1dc1232de34277454dd278c58c05eaaebc589600f6b"
    $a14="e1176aaee5357fe006f136949a6529e05074bad4caff8cc89bafba2c6eb5637089f87f4eb21861d473e104d26135836e"
    $a15="e1176aaee5357fe006f136949a6529e05074bad4caff8cc89bafba2c6eb5637089f87f4eb21861d473e104d26135836e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_512_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a1="5c84b826ae76b96ed9e9e41fe5788a16adc3cb185483b6d4008f9ddcb14a050e753ee2ad82433cea8a30dcf286418a4bfed6473b378ca0cfff3351ad7c433ba4"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a5="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a6="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a7="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a8="90f2e09d2bbcaec0bf162a060461aa3f49647fec9cd87f0df9ea028e723ce3723fd47026b152f9fadf7af211cec81c285b8223199bce57ceb7aeafa60752a100"
    $a9="90f2e09d2bbcaec0bf162a060461aa3f49647fec9cd87f0df9ea028e723ce3723fd47026b152f9fadf7af211cec81c285b8223199bce57ceb7aeafa60752a100"
    $a10="c567ae1d0f91e297efac5db0f1e4a62bbd0d56f5320ed11026dd6139676bf2853879e79b910de9677f1fc04648cdc330a98a655737e988c84885355553ec2d8e"
    $a11="c567ae1d0f91e297efac5db0f1e4a62bbd0d56f5320ed11026dd6139676bf2853879e79b910de9677f1fc04648cdc330a98a655737e988c84885355553ec2d8e"
    $a12="22e4ff124422f8de091bee72e2ec8c637ba473a4ee52bb7111eb4d2de258f41572debee13be0304c297baf04beed302f9579c9b417b4240c287c74551796f52c"
    $a13="2ad63f903f67c567ad52883679de1fa02a3affafef58cde990c4da8f2cd87e920664fa0563879a4a64e8a8373396c3a7b0151ae0d083b682c6089a3e1c57b95b"
    $a14="5232a44326f1d6742587f77adca5b26be8dfe0dc334d1e14e8a75af5d0127c4405c1fe88f6183672493cb088be76fcb1e2cd04c58e6e66e1cec50c3b94cda7d8"
    $a15="5232a44326f1d6742587f77adca5b26be8dfe0dc334d1e14e8a75af5d0127c4405c1fe88f6183672493cb088be76fcb1e2cd04c58e6e66e1cec50c3b94cda7d8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule base64_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZnJlZSB1c2Vy"
    $a1="dXNlcg=="
    $a2="YWRtaW4="
    $a3="YWRtaW4="
    $a4="VXNlcg=="
    $a5="VXNlcg=="
    $a6="QWRtaW5pc3RyYXRvcg=="
    $a7="QWRtaW5pc3RyYXRvcg=="
    $a8="R3Vlc3Q="
    $a9="R3Vlc3Q="
    $a10="SVNfJGhvc3RuYW1l"
    $a11="SVNfJGhvc3RuYW1l"
    $a12="TERBUF9Bbm9ueW1vdXM="
    $a13="TGRhcFBhc3N3b3JkXzE="
    $a14="TVNIT01F"
    $a15="TVNIT01F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

