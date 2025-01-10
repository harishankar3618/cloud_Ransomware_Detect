/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        id = "2uZ3SK9VsinTwqerqEXEVR"
        fingerprint = "a9fd0638544fc50f4241cc4f7cf6540069a267b0b58f88b24ed96a40eeab6d70"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a64773b37e9751de3083ac6accdbf69f"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="a87f3a337d73085c45f9416be5787d86"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="b9f917853e3dbf6e6831ecce60725930"
    $a5="8f62e69c0919247c923b60a23c0e46b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67d7ee501cc18bcc"
    $a1="43e9a4ab75570f5b"
    $a2="2b50114e7dd56ee6"
    $a3="67457e226a1a15bd"
    $a4="728889ee26187486"
    $a5="1e0c530062ec7e17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*830A96CC094C26FC591231B3C9DBEFEF8DB09EEB"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*DDFB542AA0BD1D251995D81AEBEB96DEEAD1132F"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*74B1C21ACE0C2D6B0678A5E503D2A60E8F9651A3"
    $a5="*F5AB3475E4D0309381498567B7C7A270ADED2652"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}zPbTTUSwmqjueUju4gqovw=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}1B6Y0er6bWAR06cPGluS8A=="
    $a3="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a4="{MD5}vtEoNlIWwBmYiRXtOt11+w=="
    $a5="{MD5}C66i8K4gFQ23j1jN2sRCqQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}JVAH/iXwoFy5rk5Jy2Ov5AdDw0E="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}6/x5EAd3cMg0D2PNLcoqwfEgRE8="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}fGphxo74ubawYbKMNIvB7Xkhy1M="
    $a5="{SHA}jme7JrNY4u0g/lUu1vuDLzl6UH0="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ccf6d34d44b09aa8ee7948eee20aa8bf"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="d41e98d1eafa6d6011d3a70f1a5b92f0"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="bed128365216c019988915ed3add75fb"
    $a5="0baea2f0ae20150db78f58cddac442a9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="255007fe25f0a05cb9ae4e49cb63afe40743c341"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="ebfc7910077770c8340f63cd2dca2ac1f120444f"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="7c6a61c68ef8b9b6b061b28c348bc1ed7921cb53"
    $a5="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ee416263fbee3734bd97d4d06a3e81b6d9ad840690734b0820ed65821810debcb831bb813f2bb45c6b62cd0c657076a"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="053409a4197558e5f75ac94858361c8d82acf09d7a4189508ca8bd9bba57f824ca1d91187902b893e2c4b07dd85b969b"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="68daa2085274c092300bc1893351b9bace14870a6982124409e5b27ec14942508d606e69654ce2ce6ff4729823e26254"
    $a5="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30c511656eb9ab11a255c09adfcdba7b155f2b5988a0f495920454e3"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="bb3dde385e8be09d6a46a981d471fe621ee35f79d5423e2faeaa9e3f"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="4fc07c8146ff8d20695edb3d980fab332183eb02af267d5d68de188d"
    $a5="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c58bf987479bdbc51f9736086c58e703ad5e0636c0c0abb4b9ec06a1e9e8cbfd867d2561968a04d419475a28fb3dc12ce0e3219eb98edbdeddcde6c756c4c789"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="fe0d8456dd3f1a0f68cde11860c34bddce97dcbc20f389f534af8c4c49e225f6307ca16e414ac04c8d67b80821690edceb86f8de0d5286dd37ee562e3dcf2e80"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="e0469addd8d57a3623494096dabc19bebca1a038c9da696940b3f853d106a6ecfa5bd60ce8e72884efa3bd92b930da178fd616f40facad654212d7c2f8817dd4"
    $a5="2cff38a527697f0c8df41a644671718d7d139c9b6d836e126b62677d8b57b1598874b6b0595c10358f59ca4e943d8fd2aa57327db011a421a80ec65945ea210b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fbd3a8579c5b44363b2b7c122ec20a6c6f47fe1352efb498f4a8a6be2aced87"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="ab38eadaeb746599f2c1ee90f8267f31f467347462764a24d71ac1843ee77fe3"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="8f0e2f76e22b43e2855189877e7dc1e1e7d98c226c95db247cd1d547928334a9"
    $a5="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce601dc12ad887bdf9c4c8848edb38cd194f3bfdde20ee85898d0847d38accb2a962a2874b345a7ca3212b9be2156aef1636408af5a64b15a7a9cc7cc41bb00"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="b4b2a7043856b7ceed2dca20a921310884c741ab4e478b53d85bec56ef0aa2af64b499a57665e4bc8199700d1665c48827d222f33fb61346c8692f75965c75a1"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="493ad8c53ccbc1109d8db20847d7da79cd6055c86c0c0f5a823d3cfb593f8a8e266d2d560fd9713931f0975db479424a3101c308743f792860924a7b5010f749"
    $a5="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b39b9ec42b286d3089ee1a9d3cd032b70008eb8efe57351e96129cfc1bc2d8aa"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="2b3e97675aeca50cd4e00252abc5d8cb734540cd86db41fd5ff99d2e37275575"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="0da254bc3667d03941a3095a2256300c4b25089720d4a324e02843c22fecdde4"
    $a5="2538fd118f310b61a135cfbefc4524bfc4860d075ad19c7a9f1ba86dca1913ae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="efed7525ac81c01746db507bf21f5cac4a0e2847718e1e5b6da320bb"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="7407d101c6ec8cab3ece152481870447479a1d165f3ff0ee42872050"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="7dba765e4642eb08f384328cd06aba95b33e9a872ed559bf50131458"
    $a5="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="34cf402b02e28622e5c38295884c60ae0d68930f68f434a47e38486d8536e7d5"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="abdbd5fe0eafa959a296ffa0b3dd55c7413a4f1917b5fe5599eeb0c361501b56"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="be87f99a67e48ec4ec9f05b565f6ca531e24b9c71a62cfd3a58f54ebc60115ea"
    $a5="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bd940211b363ba7cb886eb12823f839d85a7c3ac99b83ec11bb1bd9b864d781d36d46304f2e370b17187b887239ecaeb"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="3bfd8dba3ba5129c6b372ed2defd56522faf6d0b31fc820b7f8e4a43de90bb70356d08c71bca39652e7e4996b12ca8f1"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="d1d974afe6993a728a48bb032fdaea8547a0b676f718b6c2ece8a583e98a20aa3b48ff211f88ca7b0116ee0e41bd62ff"
    $a5="05de7187b529f77320118b614d697fd59004745c2993e9e827e78b02049458c9afb928d19c5e7f2917c9d57c9b841ad1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d5b40da04e01be337d8bbdb7d6fece6c441696f43b22f3a28f5211786b0b1f11deb5c4851b395ef583dddfe13b55d5eea989577ff98f8c32903231fca38146c"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="4bdc214c7bba4a88527d78c8086746d18e8639d8f5b7a9f1ec105a3d002a3002fc05d98967fc68d0edaab6cec7fe46775ef8ba79db251bbfcacc098dad6ce083"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="a9d14097c6b60a6c07a8d7b02b48feac60e83f43e59122ad00cad8122c492eec52f4590a18b733b909e3f17f2fa555012254b1ef6800ab815eb36a4098079532"
    $a5="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4wMDAx"
    $a2="cm9vdA=="
    $a3="UGFzc3cwcmQ="
    $a4="c3VwZXJ1c2Vy"
    $a5="cGFzc3cwcmQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

