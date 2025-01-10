/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_watchguard
{
    meta:
        id = "ewVNBbWGmhjQoPI9U44t"
        fingerprint = "e7056796170d07e6f846296af51c1c13add0188631a85d4b988053f5ba1ffdaa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36aa83bdcab3c9fdaf321ca42a31c3fc"
    $a1="57d583aa46d571502aad4bb7aea09c70"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="628427e87df42adc7e75d2dd5c14b170"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="dddbcb37e837fea2d4c321ca8105ec48"
    $a7="e3d83ea8259bb43662acccaf9c4352d1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29bad1457ee5e49e"
    $a1="1a486e7929011a28"
    $a2="43e9a4ab75570f5b"
    $a3="43e9a4ab75570f5b"
    $a4="4606b41d6ade74c2"
    $a5="43e9a4ab75570f5b"
    $a6="55743dec57707aa0"
    $a7="0ec731921ffcfe74"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*196BDEDE2AE4F84CA44C47D54D78478C7E2BD7B7"
    $a1="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*FC4C8052E3C11C2C1FBB16180EFFFC36869B177E"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*922A4B420903CAD4E7FC56A23122AB927E051FE3"
    $a7="*15E5CE8BD40B2370371D57F7DC5E7A48066EE26B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Gh3JHJBzJcaScd3wyUS8cg=="
    $a1="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}Lqf+K9BR7AdqImt9q3aqow=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}M267sheb6qc0Ck8WIPOvQA=="
    $a7="{MD5}mstEVJtBVjaXu0kBROxiWA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nU4eI71bcnBGqeO0t9tXvY1u5oQ="
    $a1="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}rM+IHoIe1iyoQtNBZEJqfZIVqUg="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}midxgpchjDdXw2XTV9E/SdD6MGU="
    $a7="{SHA}SKNmHYRkePqZGoJevRC3hnFES1s="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a1dc91c907325c69271ddf0c944bc72"
    $a1="ee11cbb19052e40b07aac0ca060c23ee"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="2ea7fe2bd051ec076a226b7dab76aaa3"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="336ebbb2179beaa7340a4f1620f3af40"
    $a7="9acb44549b41563697bb490144ec6258"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d4e1e23bd5b727046a9e3b4b7db57bd8d6ee684"
    $a1="12dea96fec20593566ab75692c9949596833adc9"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="accf881e821ed62ca842d34164426a7d9215a948"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="9a27718297218c3757c365d357d13f49d0fa3065"
    $a7="48a3661d846478fa991a825ebd10b78671444b5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad111970708aaff07524d81f71582952b75ade74951ebb3c25e801fc4a3f17de8d3e8fbc7c271114462fe63f67d33536"
    $a1="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="07118c8912d6527cd58200ac894bf3abf0aa38c27d0db9fb866e0016f348cf3b59b7a96e14e000217d01d00e0734c76c"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="3ce313ec5ea0e8e20c6d3e0a70418198cd3cc1a54bb1e51f1a3135dc03d014e20f3387875bba5f5d37e54100b9535762"
    $a7="26e1a4f10b3b1ea18e963a2950efb28ee201b97dbd259f4408412681dc43b9b4924a9c2181244aa9a5469854d3bcd769"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ccc9c73a37651c6b35de64c3a37858ccae045d285f57fffb409d251d"
    $a1="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="7525d4343f66352bf3e51528c809fd8473f7969996aa6b9fe9ab39aa"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="c3352c01875335502f888606000fee7f03bdf8331037cec22a1bb55a"
    $a7="687a9ab8247c24007fbf40838b4a9773c4918b4c0307b4cda86322d0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5b722b307fce6c944905d132691d5e4a2214b7fe92b738920eb3fce3a90420a19511c3010a0e7712b054daef5b57bad59ecbd93b3280f210578f547f4aed4d25"
    $a1="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="837b64c137ec2633242b1363ab465707b6a26fecbd5c47e17a0ba457369afaaa9f04dda78a72d64607959a2a002586fdc77f87d943c95c42e7a9eca4ee2f41c6"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="ff3d9d060c06599e083d26bcdffd24b51c68e3a7cd10859d6763701e31dad0debdaee7085b95e7b0c5f9c535d5e031e75e885fde7a6056065fce009f597345c9"
    $a7="df3dbdbf1630f9f3c9a2bdcc458518a08aa0d03252be523384fe247953ad31f70c04f641eedc8ec10e8eb4ab10df1fbc29a3ced71689770b3839d83e9782e627"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1"
    $a1="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="dbed7fe3ca011c3d1fb0fec3bdced5031d4ef17dfce2fa867717f7beeff23d8e"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="8171bacf32668a8f44b90087ad107ed63170f57154763ba7e44047bf9e5a7be3"
    $a7="073c1634c496cdb649d1afe0a312bbb4b7e1741b271542e4a436c3b8824b1761"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43886c4979efcf7990b5283dc2826b5d7247407adf002b3a95f6b04ebf5e483fe3ed435c8ba731492f0cc99c7af8221917e720d6ab41c8ce7f6afcc91392c159"
    $a1="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="ef2fd09f1a0711ffb157269b5f22c433a85a2f3396d8d9348ad9564ea7a6bd425026558c84725e288b9eea12002305558cd95e61fe7a198d1bb69df986c1b3d3"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="8d2f4f0bac20160beccfa32131beeb745b19fa24352e74356659edf6e463847b91130101ef25bf20d2cd8bb46a5b3558f5fe28361c15ca6e6513160d569c9592"
    $a7="432202ebdb99b29e5ae78eb00f46d3522a0234d765b2fb0a32181ef6b79f3a4e2cb2ee8c6bb188fbacc19f2eaa6037b5da8165f699ba5209d104e2bafc9cc392"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f5a01bbbf0ce658abcacc64c7efdb3f108a18705ca66196340090bedc11f431"
    $a1="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="deccbbaa43384c8f3618af30729423bce158c9e716a394cdb960da011c4390d8"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="97c665ef42239cceba9e65db0a1123f2b3de1891ba4462778304b1e07c4103a7"
    $a7="a1841fc7fb2d8bcd738e92a840db5e0183b8b5988f806a5e5199cea8cbf70860"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30c04cbad71a234a295ef6445ce18fbf2e39b83e054b93e6030e305c"
    $a1="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="ef7288e18476c5b2efb6d043e4bd7f5d955df401618360641761f6dd"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
    $a7="9623c659c62f27f089236dfc7dee913d0ac0c1539cb396341e9ea72a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73899d2adaad774417b0208da85162b61c8dbdf79bb0f7108c2686b93721d1f4"
    $a1="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="ecadc4b42ff468b63d113a1ff868aa2d8c4566bfc8e41c6c0b1197f0cc86cf0f"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="057d1b930b9c8e962bf34656a2c010888ae6a2a5fc4de074ecc8cb3bf4782685"
    $a7="916612ebfcf7d0f4d35c0d8dc3f2505e4d1352fe1274235fa0eb3f4eade4cc80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36d841bb32fc5ef1a5704652097584ee789f4d2e745fa283516320163dba0d699b5a502de4f33321155dc5715e0c1e4d"
    $a1="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="efd9e5ef02a9405c6da4dd3b8451f61834c6c444d2ff6654a29a2c4709e69d98815377874349b9d9189f72527b2216df"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="0e08ace98462c032a1d1ef35387532a39d62bf837abfdfd1ac221c6a070fe0e064ce07d88c6004e63d55d1fa8d508327"
    $a7="9af28d366e58609cf8d8d6bb3479614fef9eaddc93a5e291d7982629f0042dcc2361ddce35753e3e96aee091051d23d4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62f264d7ad826f02a8af714c0a54b197935b717656b80461686d450f7b3abde4c553541515de2052b9af70f710f0cd8a1a2d3f4d60aa72608d71a63a9a93c0f5"
    $a1="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="0932668b8444d7cc4c45425e8a81d3e4b857045672c7dfd99aa0937aaf86f4ceeb80af7e6845120b7ff6ff482d5ba4513f4b65b76c5ee2f2e2f037ac874ad4cc"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="a042b8def54466d33a9fa2de436041aac98bb190a245f7829b0f1ee858568e115ebb963491f5aabbec1e69d7deee0bdcf846bc626029b59ad517f520aa6a8f21"
    $a7="cc71e3881deb5bca7f8e1dae59c6d2eb3616a7633141055096259c5132ca3b1cd1ffd322ec01cb859e3bb43409e79c2806c8800d4d260de23b6f3a6c2126dab0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dXNlcg=="
    $a1="cGFzcw=="
    $a2="YWRtaW4="
    $a3="YWRtaW4="
    $a4="YWRtaW4="
    $a5="cmVhZHdyaXRl"
    $a6="c3RhdHVz"
    $a7="cmVhZG9ubHk="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

