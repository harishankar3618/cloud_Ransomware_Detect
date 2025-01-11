/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ascend
{
    meta:
        id = "5ub1b5opMGLKmW8JXMBkYA"
        fingerprint = "d9e0e2da5712c872e606b45e58b41647c16d78178428f98e04edc245c43816f8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c99036dd323323e9662f1cf97c217aa4"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="3212c03db38b7fb4ba4f1838b9b84e3c"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="0c4d36957773a3d3fc4dc1c692615ba5"
    $a5="dddbcb37e837fea2d4c321ca8105ec48"
    $a6="494062405d6c6ce94794d2431bb29c21"
    $a7="628427e87df42adc7e75d2dd5c14b170"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2082450856b89077"
    $a1="43e9a4ab75570f5b"
    $a2="62aa93a8008d2b17"
    $a3="67457e226a1a15bd"
    $a4="649cbaab14185e8e"
    $a5="55743dec57707aa0"
    $a6="649cbf7e14186161"
    $a7="4606b41d6ade74c2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*06D52F7D03663CBCAB6ADB48D1F757632FFBDF52"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*F41EB78C5190F200941114EA9A846EA7C8660866"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*78FB7C5D32AF903AF5905FFD2484ED91A31A4A29"
    $a5="*922A4B420903CAD4E7FC56A23122AB927E051FE3"
    $a6="*04819F91FA44D553D301CA7F7CE3848BC3053BB9"
    $a7="*FC4C8052E3C11C2C1FBB16180EFFFC36869B177E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}F9QzCXUCmMFEiNUPVv0rjw=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}7UWED2pkFcpetQrmB+lEnw=="
    $a3="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a4="{MD5}YvRYkM1IGVvo6TGKo4NFaw=="
    $a5="{MD5}M267sheb6qc0Ck8WIPOvQA=="
    $a6="{MD5}Mz0+LdmPRnhsZxbLWZlfwQ=="
    $a7="{MD5}Lqf+K9BR7AdqImt9q3aqow=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}AT3jRWbUHNxUR/IoIDvbrMxh+gc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}uPrYkdQxTdwx04LOaki9Pj/xNbc="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}thGulhlNPC3nriYN5RSbkGwbp2I="
    $a5="{SHA}midxgpchjDdXw2XTV9E/SdD6MGU="
    $a6="{SHA}qd01G+4mFQrM/M03Acew2yY3mJY="
    $a7="{SHA}rM+IHoIe1iyoQtNBZEJqfZIVqUg="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17d43309750298c14488d50f56fd2b8f"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="ed45840f6a6415ca5eb50ae607e9449f"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="62f45890cd48195be8e9318aa383456b"
    $a5="336ebbb2179beaa7340a4f1620f3af40"
    $a6="333d3e2dd98f46786c6716cb59995fc1"
    $a7="2ea7fe2bd051ec076a226b7dab76aaa3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="013de34566d41cdc5447f228203bdbaccc61fa07"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="b8fad891d4314ddc31d382ce6a48bd3e3ff135b7"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="b611ae96194d3c2de7ae260de5149b906c1ba762"
    $a5="9a27718297218c3757c365d357d13f49d0fa3065"
    $a6="a9dd351bee26150accfccd3701c7b0db26379896"
    $a7="accf881e821ed62ca842d34164426a7d9215a948"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d6c3fe9b85eb9028a901801247e8fe30983c3de24b0a0af9d64867b8ea05f208e7c9a0d22bfb60c142d834511b681017"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="3fe35e481a78c49434a85ead9d705ed62919749d5e766cd2d6ef060127181ca83cd4087b6e11644b2f09a3957fb78c7c"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="d12fdf2e3f04f870d878b475689c612b02e3214bbe9446904dd412a3d2e9801d0b1b1850f7307807d086dd100257092f"
    $a5="3ce313ec5ea0e8e20c6d3e0a70418198cd3cc1a54bb1e51f1a3135dc03d014e20f3387875bba5f5d37e54100b9535762"
    $a6="f4d6fe6f62934bf34a452ce6184e42a4892a40a70371eb2e883c8573b93349afc606c710db090584dbe31ef4c22b1078"
    $a7="07118c8912d6527cd58200ac894bf3abf0aa38c27d0db9fb866e0016f348cf3b59b7a96e14e000217d01d00e0734c76c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="329872e9ba9650413d00e126e516ec4e83233a487e455d4b44d59c28"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="9ccb03ee072bc1417365a249f925ddff6bf050841749e0ed0e141fe4"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="aab31839eda6ae30c9e04b073a6c840b3da972c72ecd46f020c599f1"
    $a5="c3352c01875335502f888606000fee7f03bdf8331037cec22a1bb55a"
    $a6="931cb2c2657631363b8a216b6ae51002af953a5dac26fa43f60abca2"
    $a7="7525d4343f66352bf3e51528c809fd8473f7969996aa6b9fe9ab39aa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="312f56286d241f48161a79d79da887d9a4c469e2656bba2f807a0fcb303f560a1f8d3ebc5ca35d375ceaa9419de273822a4c4f5d33b9dbad36a6bf1a74ae01fd"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="90009d12415ac46a2c7e4492c12bbbb22d7888011ca9aca98ac14837f210e110fc63b991f24f0d51dc4c18245e08cfd2d93380569ca3a00701dda743e9a08a69"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="bd41baa75fe7647f1d27c31a72b4e2dfc537db475e089a139f67a82d7f555aa1c902aab6ed849b376ff5fd0f2d37ea9f3421ec2ba2c82312c65806da7d45c648"
    $a5="ff3d9d060c06599e083d26bcdffd24b51c68e3a7cd10859d6763701e31dad0debdaee7085b95e7b0c5f9c535d5e031e75e885fde7a6056065fce009f597345c9"
    $a6="7bfb8ed4f69d24f6300c57f6bf8ec89f76e6d7158f09eaa4a1dad5128a153ab83e6e7248ca0bbc875494ba510e29fbc339cda3698a0ea414eea7eeb80f2bd283"
    $a7="837b64c137ec2633242b1363ab465707b6a26fecbd5c47e17a0ba457369afaaa9f04dda78a72d64607959a2a002586fdc77f87d943c95c42e7a9eca4ee2f41c6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a19d16c5d8b543833282a7a750a04981e21ec906a5388c03356630dbad24187"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="2ea802eeb4485cf32398e8fa1c85d0be431cfa53e21c8cae1e413c628eef2c0c"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="79214a67320d0255297ff8f4107aea70e3d674cfa601a81eaa0fe72c93716993"
    $a5="8171bacf32668a8f44b90087ad107ed63170f57154763ba7e44047bf9e5a7be3"
    $a6="2a54483d03dadc8ab9e4f69e68f4340018c3dcb9e63546d55f5e5d88737b81c5"
    $a7="dbed7fe3ca011c3d1fb0fec3bdced5031d4ef17dfce2fa867717f7beeff23d8e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bdf217367281ef6f820983eafa704c7fd9fcf1b20e6ce9745da5c976af399702c582a2a9247c6254672d148921e89d06e8b605a5b4c0c3fd74e960880c69297"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="31a330e8c8e72bbafd399ac5f50823c0682a5d830acbbe8df65bda0e7a93178e71604d50a9698af12175a35ba66e74dc5749d7991bdbaa638fc9518d3f3f4b12"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="dfa9daa408bc2317afad1086df4f602fff9a34309c2202dc6ebff703d85fedfb9ac0f1a35da6c3589dcc9730145934675694f66aa7a42f3714d78860c908275c"
    $a5="8d2f4f0bac20160beccfa32131beeb745b19fa24352e74356659edf6e463847b91130101ef25bf20d2cd8bb46a5b3558f5fe28361c15ca6e6513160d569c9592"
    $a6="b540ea01ced69e6e6159f992e3ed9c30b7a65f08f2f031ee6147c2b6395762004f79c137503167324ce307f412f483348f6273c1c33a8b42f4fbbd856d355d67"
    $a7="ef2fd09f1a0711ffb157269b5f22c433a85a2f3396d8d9348ad9564ea7a6bd425026558c84725e288b9eea12002305558cd95e61fe7a198d1bb69df986c1b3d3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e3ed214cbf925e45a33acc2f691ec692b38564ef66d2f80b75dcb16710d9cc6"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="d65713daf4bfd4cec7b745476c42fcdb7f34045f314f4842f6e47dcc25d27ab9"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="e9906881fc284dae8238878c1a409311519713023291779b53d8636234c9a735"
    $a5="97c665ef42239cceba9e65db0a1123f2b3de1891ba4462778304b1e07c4103a7"
    $a6="c396f26e2507ca2b9d5723d5e649f705767beb0d4326572f45afb469faa21151"
    $a7="deccbbaa43384c8f3618af30729423bce158c9e716a394cdb960da011c4390d8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9be3fb156646ef4114be768ffb84fa2fe91909db0a56a87f13a55dd9"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="def073a2b31ce23ee32457ab705a51f1abbce8e25c327dfb36c98873"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="78b3f0c8476104cf533ef1a8f77b7f941e9278c0e889a72d9b986454"
    $a5="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
    $a6="9e7fb7d8aeae258f2cfa631463fc989f13ba0f90f852bac101f2d0e7"
    $a7="ef7288e18476c5b2efb6d043e4bd7f5d955df401618360641761f6dd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91580e467eda1432da3ac8b3e2541033fa0c733e544a82024dabf260dc326cf1"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="a214f7312073b63bf1c183534e979b18533771ab290e105043b898942702a995"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="9f9b41032ecfcb70a6060c45f72cfe28c7a982a75e1dcca4f02d82bdf58bfd3b"
    $a5="057d1b930b9c8e962bf34656a2c010888ae6a2a5fc4de074ecc8cb3bf4782685"
    $a6="ca177780df436f74a06ea281c897a680fb5c59033451d73faa0e65ec25da4ad9"
    $a7="ecadc4b42ff468b63d113a1ff868aa2d8c4566bfc8e41c6c0b1197f0cc86cf0f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b35410f11c81b31198871c612d05639757dc8a279ed5c8c663a5d9683969d85704b1316f47b1cc0168711735088580a4"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="a741e81d56af5d8d8989246b020b6511ca94eab702c084079afd8a0493d6231f66c3a7ea7a86c37bb61597d4956bb8aa"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="59a8a0053065fe4eaa6942c9eea9ba79846a14e747a11c9039779239e63b346f7bd3439514164f573ed9c4c0ec37b89e"
    $a5="0e08ace98462c032a1d1ef35387532a39d62bf837abfdfd1ac221c6a070fe0e064ce07d88c6004e63d55d1fa8d508327"
    $a6="a53f652c63106cc8e536222155fb49f98e6071e10f0a523b81ec1359d1d2ab8351fcf141a3442ccad71de87fa1f18efd"
    $a7="efd9e5ef02a9405c6da4dd3b8451f61834c6c444d2ff6654a29a2c4709e69d98815377874349b9d9189f72527b2216df"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17e9de94a290a315ec0e256d5075c1180d0e103275e1ea169e3c0fadee41b5891c50df88b6c434eae0d6ea7a2d9abfdaa1b0163ca8baa6587b2fd38618c9f583"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="830da7fdae27f65e0604953d955bdc20f007c6cbbb2a807cae31d88cef2403516d6c5f7a656f47eafc376cf37127fa824e115f7b34db333904354490edea6292"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="77e103fa4098a3ee23c73bec9df9561b0396fca97097342fbf7fe7dc1c489b401baa6153933443b204fbc19a5c8154b1e1ff2014242ff9a181f92926d49fe4b4"
    $a5="a042b8def54466d33a9fa2de436041aac98bb190a245f7829b0f1ee858568e115ebb963491f5aabbec1e69d7deee0bdcf846bc626029b59ad517f520aa6a8f21"
    $a6="a74fa0d922a306eb09a5cefed65b4165387ea013cdcc19ed7ca7a5d32a4bf9e594f18d28e3127e715593e3b9cd57bce95be5592ca580455878daa1cdceefbcb5"
    $a7="0932668b8444d7cc4c45425e8a81d3e4b857045672c7dfd99aa0937aaf86f4ceeb80af7e6845120b7ff6ff482d5ba4513f4b65b76c5ee2f2e2f037ac874ad4cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="QXNjZW5k"
    $a2="cm9vdA=="
    $a3="YXNjZW5k"
    $a4="cmVhZG9ubHk="
    $a5="bHVjZW50dGVjaDI="
    $a6="cmVhZHdyaXRl"
    $a7="bHVjZW50dGVjaDE="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

