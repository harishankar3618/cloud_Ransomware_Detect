/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_lantronix
{
    meta:
        id = "2zMwsZpAxVvbi2uJbuDrGV"
        fingerprint = "4f8943ce2541b95a579dd8049dcf190be3c00fd14ad6cf3aa0b0fa5fd31cbcbc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f441f41aa59214cccc3d4ba5ed1550cc"
    $a1="724279aa825e91ca54a5cc1db868bd4d"
    $a2="9000b201bdef274265885986a8cf50a0"
    $a3="cc607a8ad1d888e0ffbbc71539e6d864"
    $a4="4e6342ecc5ed563057800830d710dd61"
    $a5="e6bd4cdb1e447131b60418f31d0b81d6"
    $a6="9000b201bdef274265885986a8cf50a0"
    $a7="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a77f1277b51f67f"
    $a1="7cdeca722c1bee73"
    $a2="0fcbac4511e5c7de"
    $a3="5f7bee3e78957ef2"
    $a4="4c6b424453a9dfb4"
    $a5="2af9b9db5e1767f3"
    $a6="0fcbac4511e5c7de"
    $a7="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a1="*0C1648C40981C5CA7B0410D41CB3ED8C43E05388"
    $a2="*B415DD9C4FB5EF59FE80C4FEBC1F9C715E6E97C4"
    $a3="*96D6A0C2685F450571C6500185A4FF596EF22098"
    $a4="*49D3CEBD189B8C5D4A47C975133BB2357A327585"
    $a5="*497F081B3750057FE652584E2611798B53DB6389"
    $a6="*B415DD9C4FB5EF59FE80C4FEBC1F9C715E6E97C4"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a1="{MD5}EAuMrXzypW9t948XH5eh7A=="
    $a2="{MD5}epW/kmoDM/V3Ba6sB6Niog=="
    $a3="{MD5}SKNltM4eMipVrpAX89rwwA=="
    $a4="{MD5}nfOwHGDfINE4Q4Qf8NRILA=="
    $a5="{MD5}1WtpmDDne6U4VWecsdJS2g=="
    $a6="{MD5}epW/kmoDM/V3Ba6sB6Niog=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a1="{SHA}xf4CANHHpROb0Y/SImjEyov0XpA="
    $a2="{SHA}vVZNtdXMNY6w41I9PgMEFznyMNU="
    $a3="{SHA}oVm3roG6NVKvYelzGyCHBRWURTg="
    $a4="{SHA}DxJUGvzOF1+zS7BaeclbdudlSIs="
    $a5="{SHA}Jzb6spHwTmm2LUkMPAk2H1uCRho="
    $a6="{SHA}vVZNtdXMNY6w41I9PgMEFznyMNU="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54b53072540eeeb8f8e9343e71f28176"
    $a1="100b8cad7cf2a56f6df78f171f97a1ec"
    $a2="7a95bf926a0333f57705aeac07a362a2"
    $a3="48a365b4ce1e322a55ae9017f3daf0c0"
    $a4="9df3b01c60df20d13843841ff0d4482c"
    $a5="d56b699830e77ba53855679cb1d252da"
    $a6="7a95bf926a0333f57705aeac07a362a2"
    $a7="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a1="c5fe0200d1c7a5139bd18fd22268c4ca8bf45e90"
    $a2="bd564db5d5cc358eb0e3523d3e03041739f230d5"
    $a3="a159b7ae81ba3552af61e9731b20870515944538"
    $a4="0f12541afcce175fb34bb05a79c95b76e765488b"
    $a5="2736fab291f04e69b62d490c3c09361f5b82461a"
    $a6="bd564db5d5cc358eb0e3523d3e03041739f230d5"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a1="da39e337d7aca91516ebc4d0c96f3549c15be792df607f1cf5885ad30910c19a69743b873e409b54e6b8bcc9db829a3c"
    $a2="78e42a356435093bf78bb56c3adf897e884f9b2c8bf0bc719ece297b505869959cfe9efb64108e4063414479b1fc597d"
    $a3="da9b3e0e3764965ea1ea652d0d504c40c14ffb05d26a1eadda70833bba54782b7e427a6c75003c8c8ecd96ffea88cdb8"
    $a4="49e18e684812e9034a6c1eef90b337cbc9ee8de6383e57b79f4bc255393417ab33def30f0f3398c5489c00faab52a619"
    $a5="b188d166dc05c1c824c16ff6739f42c4dc8313da98a037289784daea7710c3402c13c2a9442dcbe19d33467381bf7979"
    $a6="78e42a356435093bf78bb56c3adf897e884f9b2c8bf0bc719ece297b505869959cfe9efb64108e4063414479b1fc597d"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a1="904e1dfdd115698ca60d626134dd92d5f3362df3cd4bcf8fde0501de"
    $a2="7ba5f98ac94c57079d6452cfe6521165cc182a5d25927002a1ad7d99"
    $a3="02f382b76ca1ab7aa06ab03345c7712fd5b971fb0c0f2aef98bac9cd"
    $a4="24289a24be5d6ee8df8f3cedf9b538b4cb69fbaf8abca98797b328ac"
    $a5="6583756055182f816b6c5dba70cabb3be2813c2a57f645ca2f7f79a9"
    $a6="7ba5f98ac94c57079d6452cfe6521165cc182a5d25927002a1ad7d99"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a1="40d380d92f53ad12cf2194596874a9179f1ee3f92e8f7c994bf94db3291abb89c3ff351ed2b91130157fc7d32f842ced4b998a9de6e0e01d987a28d96934e6cc"
    $a2="a19b7f9fe873c8f7932b0256dbc5836dfb64063dc84c824ae7a1fa652cff200cc8e437c95b46bdd21084521b3e6b15cad5ea5521db91fbd8a933a1460b1fc2ef"
    $a3="f6235735d47e6ccc82cc743bb0f4578e2f21572003d61e62c719fd9345101031e6aeed4b2ba8b059916b3764dac90fbdb6a0a88fe5fa7d7f483013a63cc089e0"
    $a4="932778fa1dd9a15dac1f6d7690b29b70e9c205a8d2b4a437f007bf6df4fe3c5200520078f95184bd37ce6ed67f362a42b4263ed4c8ba6d777b0166f9af879897"
    $a5="107350f79b8400469b09b40b91710e81a4276c7744a20fdb11fbfb31b5936332ff682f57bb9b2318b970789f7f9d5ea26bc2ff0bc94f61935a4072ad8125fe4d"
    $a6="a19b7f9fe873c8f7932b0256dbc5836dfb64063dc84c824ae7a1fa652cff200cc8e437c95b46bdd21084521b3e6b15cad5ea5521db91fbd8a933a1460b1fc2ef"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a1="d6a7cd2a7371b1a15d543196979ff74fdb027023ebf187d5d329be11055c77fd"
    $a2="2f9acb02faa121bb2a3621951f57b4c690655337edee2e5ac350be2b3be88ea8"
    $a3="d577adc54e95f42f15de2e7c134669888b7d6fb74df97bd62cb4f5b73c281db4"
    $a4="a0561fd649cdb6baa784055f051bad796ea0afef17fca38219549deeba4e8c1a"
    $a5="428821350e9691491f616b754cd8315fb86d797ab35d843479e732ef90665324"
    $a6="2f9acb02faa121bb2a3621951f57b4c690655337edee2e5ac350be2b3be88ea8"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a1="9d0cdc80d29977b52125ac1e933f95e8d41e0de299291e4e2d8659883dd1f3b7d15c4d4422433259bbaab04eb2021d8d83d79f02fed263509b1df6eff0e1c726"
    $a2="4a5da2ebd2552455f3ccde94a636d353fa7c4aa65a16c50bf27a0672412af4d5fcadfb936e371fb75e84d89ee436faff35cb6f9951268611733b60135457cf49"
    $a3="da668ac94129340a5db3fa3d91341413bbfd477fb277272bbee5122fc1ebef04a33a76c01ed027ea066b3b7f3819f487ba6dfeaaaff9a326b49c39519ec7f474"
    $a4="3668a081b0929274a97abf15209dab17ae30a35a7751a62e5515262524cb38b5216cff0ed604cf6a8f5f5b573aa0573735764a99a6028f22e0d2ea1eaaac810c"
    $a5="02fa8d46fb2ac65ee42912604250a146af74c6b8cff1acd09bc5f460fb9850cad2674f76f982ed052c78d178196ed4c10256e2bc50e191dbb82f625cad071090"
    $a6="4a5da2ebd2552455f3ccde94a636d353fa7c4aa65a16c50bf27a0672412af4d5fcadfb936e371fb75e84d89ee436faff35cb6f9951268611733b60135457cf49"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a1="73baba47b79bb83663182e7d9bfcdf5e4ce5c7812d7d91995b704d01a29e0b5d"
    $a2="50306d5ff12c751f2aefc09e5b3df58b84a676fbebbb8fd17b84b6a445c6df5d"
    $a3="0eac0ddb08d482a2cb9e297e499508a9e4f4b229229d43a6f2f78d129ebfb203"
    $a4="13ed751afcecd936bcbe496a38545e63d2fb97f2ad8fc5b72f17d29784c34db5"
    $a5="8a4c21160430a7a93bedcfd6876aa77a9269a4ab59aa6adb42692717f6a2bb80"
    $a6="50306d5ff12c751f2aefc09e5b3df58b84a676fbebbb8fd17b84b6a445c6df5d"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a1="1b80ba673a959ff153aa35c0bcf7bbc66aee780c7680fbb15a445c3a"
    $a2="44dce7e29c53baf26f62ba8fb762fa83014db48740a391cc97a16b7f"
    $a3="b3c613fcea10ca76dab2bae1ff0054b92d46aead56580e60898b6f82"
    $a4="a86118aed12772c63e1641003f22dadc2be7ee74d4cb33aeb0b3466d"
    $a5="0509e9a858996f62da0f676687a1e2b209ed07819cd43f3021981b38"
    $a6="44dce7e29c53baf26f62ba8fb762fa83014db48740a391cc97a16b7f"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a1="7798f5d064ee771c317e429a5e947ea61afa61a9071c4c0a4abac29ed8a83947"
    $a2="64e0033a157085ecc01bc7e53e9f6e032754676e57788f5b92bd147efbdc4a2f"
    $a3="78377bddcc5fb7199a28965a65772069ce9de533aa0b7ac7c63fde2e2cc95966"
    $a4="1037f1f67277cd916301c10e5417b95c117abbd8daf2b794c30a90ee67898b53"
    $a5="a2ce5400c881d0469d3fda706ca5392fb9f351ff95a8a300e0fefd11b0bf1d32"
    $a6="64e0033a157085ecc01bc7e53e9f6e032754676e57788f5b92bd147efbdc4a2f"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a1="29bbaaf5bb4833d1ee99731dd706c7564d545323dc38077324710346b47c672f6cd95b095b2ab146106b26250aa52eb8"
    $a2="3acd17e3e97eaf1e83d90d5080eb21a6dc8480d001b9adce3a3aab542d485ef6805597e7cb61d046d1d084f03c414546"
    $a3="f5276408a10d9c8841ac9fc0a3002818b5d55ef8065c3dca312cf764e4ef7213ae21d3f35423123de91061a2ee8a0bb5"
    $a4="8515c138c59d8d72b3d9ec1bb64c0ee8f1d8e270d29c1eb632b0ae048661bf0121c24c7749166760a022f8c2d48fab62"
    $a5="fc2b975d7d78d7a007b8577e807f66a26dfcf0a008a8678464c68d438dd6ee18a444ac5f594674f189183f2db8a15c95"
    $a6="3acd17e3e97eaf1e83d90d5080eb21a6dc8480d001b9adce3a3aab542d485ef6805597e7cb61d046d1d084f03c414546"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a1="6b6c2518fc56046954105459797b70438cc08402f8d6eef226fc8f020a2455cf1d82d399252a237846cb6e72215e1168372d99fc54618321ca44838b1705c63b"
    $a2="e78d3d718b7681d5fddcdfeb18a55895828bbced7f64f8ad8c91043a3c7c0d2be0d9cdfabd969f89d156e2b19d2e6b7c4056a08385ff7ab43995503048bfe9b2"
    $a3="100bcb6ac8e9f7bff18df1d6f6d0a41e7dfbddfdd55971bdd087c6c8039e02ae42ee60dcbc967ef03164de21fa0374152686c3c322f6e1bf56aeccc43fdfe3cd"
    $a4="2ccefc4001cc12acc9512f44784c55dff5086894fd436dfcb30f64a2c5a55dbae984b86c749d29e10254c770f3b21ca6fc11d84ddd9077db29c6e6bcb4c48f24"
    $a5="63d5cbf2a2135866c520f4b47404907891511d1f9a5d74e4326befa94120c92e805d6a7ce4e00c8fb0ce607d5623b19b5eec17e4b1ce20dbdb169cbb07827b9f"
    $a6="e78d3d718b7681d5fddcdfeb18a55895828bbced7f64f8ad8c91043a3c7c0d2be0d9cdfabd969f89d156e2b19d2e6b7c4056a08385ff7ab43995503048bfe9b2"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YW55"
    $a1="c3lzdGVt"
    $a2="c3lzYWRtaW4="
    $a3="UEFTUw=="
    $a4="bG9naW4="
    $a5="YWNjZXNz"
    $a6="YWRtaW4="
    $a7="UEFTUw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

