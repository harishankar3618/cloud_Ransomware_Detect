/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_toshiba
{
    meta:
        id = "7JoVVTHeJSq74PxJS7r7QX"
        fingerprint = "3054b90f71acf71830508e8e040f94c06c6f956583373dedc2b581ed4f3cd298"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="32ed87bdb5fdc5e9cba88547376818d4"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
    $a2="32ed87bdb5fdc5e9cba88547376818d4"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="160a5b7c7d1e2e685d9eee7f5509bdc5"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="76d202b312c8523d37fcdb4cd8288242"
    $a7="fad2607eda55ca3ecf8d89067ee91f84"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="565491d704013245"
    $a1="4077eb0b03ddce3b"
    $a2="565491d704013245"
    $a3="43e9a4ab75570f5b"
    $a4="75b5698f67983cbc"
    $a5="67457e226a1a15bd"
    $a6="42eb18606e157de6"
    $a7="60c033095644bd16"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a1="*D89A99106002D77C1D327FC41E005919505638B0"
    $a2="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*ADE95979E72432A5AE627E51655F153B2F182A04"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a6="*72EA7A3B37C7CF2067FD7ACD7FF596E05B9A9242"
    $a7="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}4QrcOUm6Wau+VuBX8g+IPg=="
    $a1="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a2="{MD5}4QrcOUm6Wau+VuBX8g+IPg=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}6lYh6uNWKx6VhyfLc6lvOw=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a6="{MD5}gqPyEslcFRaQfyfhIgxvEw=="
    $a7="{MD5}GzIxZVzrt6H3g+3fJ9JUyg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs="
    $a1="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a2="{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}zeGJy+wIOqrTHYkL6UuKaNRj/Xo="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}Fv9QS3bnUhzjVgCoDhRoCmEbl7U="
    $a7="{SHA}hFG6ihTXl1PTTLM7UbpGtLAl64E="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e10adc3949ba59abbe56e057f20f883e"
    $a1="e3afed0047b08059d0fada10f400c1e5"
    $a2="e10adc3949ba59abbe56e057f20f883e"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="ea5621eae3562b1e958727cb73a96f3b"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="82a3f212c95c1516907f27e1220c6f13"
    $a7="1b3231655cebb7a1f783eddf27d254ca"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a1="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a2="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="cde189cbec083aaad31d890be94b8a68d463fd7a"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="16ff504b76e7521ce35600a80e14680a611b97b5"
    $a7="8451ba8a14d79753d34cb33b51ba46b4b025eb81"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454"
    $a1="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a2="0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="d4c13f46f34b0fdb6095c4e217b507b5ec6b3304a020f0f06f7b65c858b47f23e442b12e81580cf5fcb3f8e6e6e126a5"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a6="aa3822ba7688c799171187bdd69a83972aab4533fff75e64dc8c4986ecaca324994339de0d33550776855e637e9da1ae"
    $a7="4092bc3d8a0d7a293f438e15d1a039db25c54342ad87c3d97b4d0554fd6df01bf61704aa1bfe6fdc51c077212a1841e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
    $a1="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a2="f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="84afc65caef3282b304e5e1a84108c455b36ef32ec4b06f11b9c0d3e"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="b071206b92c208e609fa3eb492165c271b41ad94cc0134bffeebf766"
    $a7="0f726b72946abd860c0972fa8b50fc3c7ee6edcdeb23b42d6684e708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"
    $a1="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a2="ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="77b72f3d2e797945b42065e43a762aef2e720003a61b591a5cb4a9b4a9ca5e4290031c1afabfe88f458a5e630ce151cc8ebc9d0c44d1d11bc37cc6774b5cc6c3"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a6="2fa085c1b2641a4422b860b7c6a4e805e4fb9b92264aacff13bc09a741d4c5b7265cabd7ca2dba4fe8785763839a887fdd726e79c0b11fe3df0cdb1c1eb465ec"
    $a7="36379d8584770820d95741c8efe571cc0ab37e2021c505fd8f384724d0676020ebc6d4f318e2533acf708fab8ede09c950a8daef54299ab9ea5ba1e1fd4b73bf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
    $a1="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a2="8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="9f18baf3cfd06bdc561f8de27768d2da497e34588b7ff0dd55b9bff74164392d"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a6="9fa7b1c3f5ae1bbcd5a9a444acbeba2c0ce3eeecea3508d25964dac2fb29bd64"
    $a7="73d1b1b1bc1dabfb97f216d897b7968e44b06457920f00f2dc6c1ed3be25ad4c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3910b0f4b6f1aede44da90bb7705a868b265861b36e6f7f29dba7223f6f1ce7b10e0dd25e47deb70bd7f3b24f7da653409cd9014f8715e4013c15fee38ab418"
    $a1="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a2="b3910b0f4b6f1aede44da90bb7705a868b265861b36e6f7f29dba7223f6f1ce7b10e0dd25e47deb70bd7f3b24f7da653409cd9014f8715e4013c15fee38ab418"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="83027e1fbbc01db584280e25d33ca4f92df77614f11c0d033a00cf0441744c83c8ca1d3e5d97e203d302051ec534ca547b363c27290e298391d7b19374ee96d9"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a6="81adc0e3a44c2a7f11c0e5cdcd8a7803073b722bf5c5ab5d8ce0db21410b99197e75a4664066216027e612eb132013bc4c323cfa5b2b666facd265b3e897938c"
    $a7="da8d291e0916119783bb03757c6252fb55ea1d51bfb05e3044d676a827ad9afd002fcfdc5706406cb66b61cea06b9ba64f895d7e66b8aedd5bd84182b9b46fe0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba2649757ec72ed0b9bd8b3063687767946145f13abcb38e2718fdaad6c771e0"
    $a1="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a2="ba2649757ec72ed0b9bd8b3063687767946145f13abcb38e2718fdaad6c771e0"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="122012d2ba8102ee76043865a99ff1ba727661f4074726491a41ac0feb9653bb"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a6="b9847718c3ef331fd9ef26eaaa3cfab9f9bc0909f1516689d08c8ea3fdf30b86"
    $a7="7b866d188933ccc5dfc6f79bd6366c759f7661ff500626bc1b013b6947eb5831"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6be790258b73da9441099c4cb6aeec1f0c883152dd74e7581b70a648"
    $a1="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a2="6be790258b73da9441099c4cb6aeec1f0c883152dd74e7581b70a648"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="dd4a9f71ed6e86954d93830442061c4dc17b9180a7055d1092d1511e"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="3ed054654392c1c523083b2a6901e20d9044728afb1868e9233fee31"
    $a7="1bbdd3ab361d7fd9a47de72543e337093aaa664a02248557615675c4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d7190eb194ff9494625514b6d178c87f99c5973e28c398969d2233f2960a573e"
    $a1="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a2="d7190eb194ff9494625514b6d178c87f99c5973e28c398969d2233f2960a573e"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="d26837c039a088681096c042dc5956da9203126296c341e2301f74369b0ce2eb"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a6="8d95023180bfaa5d3eceb67a79f89c2178db5d9ceb12bd1d2470eedbbe6eaaf3"
    $a7="79de1c617efcf3d784ca3b5d1be7fefb1d1287b079fe4527640c36446cd29ea0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fb0da774034ba308fbe02f3e90dc004191df7aec3758b6be8451d09f1ff7ec18765f96e71faff637925c6be1d65f1cd"
    $a1="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a2="1fb0da774034ba308fbe02f3e90dc004191df7aec3758b6be8451d09f1ff7ec18765f96e71faff637925c6be1d65f1cd"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="4c42ef7b0246320b439a9b5620a501f493ed4cd25bf86f84a6eb290cbaeef1c31b5b74842199caeab312298721be805f"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a6="679d52c4dd8f21db53fa3c2e3abf57b68b1bfaca1d0c52739b7dc0a591d0e05a80f25b838d9c06e30d5fb9fb3a85555b"
    $a7="a42d04a5b4a2ea45ecf45279aaf3ec8fd906355e3ab856231ae7815a5df6a96f76fe4987dd638981314c942ba825de69"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64d09d9930c8ecf79e513167a588cb75439b762ce8f9b22ea59765f32aa74ca19d2f1e97dc922a3d4954594a05062917fb24d1f8e72f2ed02a58ed7534f94d27"
    $a1="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a2="64d09d9930c8ecf79e513167a588cb75439b762ce8f9b22ea59765f32aa74ca19d2f1e97dc922a3d4954594a05062917fb24d1f8e72f2ed02a58ed7534f94d27"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="306ae24c028fbeca81458d5869b97b104293e83fa0277976729bb037f3369d695afc706463c0f4810d88594828a24ccac530046ec116a15af4b1415bfb9c155f"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a6="f7230feef1ce2ca605dc637c337be0d591d4e4d17d9eed5d71ae4b7fce114907332f7ac815308a5271f0f16b314676a20304fe76cca591e83e1fc6526a7c27aa"
    $a7="a5cb39ab7a85e70d39ae78b734b0f42660126100c6d458fdd3f8e6b20ab8f73b2db2a02a0ca8d38d40b6b2544be6491243703c5770cbce76385c2e3a9c791f36"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW4="
    $a1="MTIzNDU2"
    $a2="YWRtaW4="
    $a3="MTIzNDU2"
    $a4="cm9vdA=="
    $a5="aWt3Yg=="
    $a6="c3VwZXI="
    $a7="c3VwZXJwYXNz"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

