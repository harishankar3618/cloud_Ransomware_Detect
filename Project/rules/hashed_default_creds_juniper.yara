/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_juniper
{
    meta:
        id = "Jh8nHwLSaQ01aJL1oC4gD"
        fingerprint = "04f626d36d5f0b80c3f63dce043fc77f52b0d99ee7015b9c3f90c36a6f3d734f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e41364f3191d288dceef6373c3b40634"
    $a1="e41364f3191d288dceef6373c3b40634"
    $a2="9f6f7eb38fb0f133107a6ef02a2a2a94"
    $a3="9f6f7eb38fb0f133107a6ef02a2a2a94"
    $a4="f9e37e83b83c47a93c2f09f66408631b"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="e41364f3191d288dceef6373c3b40634"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="adf8b4f972a0854e849d74d83502821e"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="e168ab4ba7f72029ff07a6c3e45d2738"
    $a11="e168ab4ba7f72029ff07a6c3e45d2738"
    $a12="84956d35b03d4d733676d520d61b59d1"
    $a13="fad2607eda55ca3ecf8d89067ee91f84"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule mysql323_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="707ad979245de1d6"
    $a1="707ad979245de1d6"
    $a2="0696b6a17454d01e"
    $a3="0696b6a17454d01e"
    $a4="4b5698aa4603595b"
    $a5="43e9a4ab75570f5b"
    $a6="707ad979245de1d6"
    $a7="43e9a4ab75570f5b"
    $a8="55c1c81d14903932"
    $a9="43e9a4ab75570f5b"
    $a10="2f53d8097fac303a"
    $a11="2f53d8097fac303a"
    $a12="6d854ac121ebb529"
    $a13="60c033095644bd16"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule mysql41_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*DA7B25B1BA72C91D124FAD86067FE077C0D8F5B8"
    $a1="*DA7B25B1BA72C91D124FAD86067FE077C0D8F5B8"
    $a2="*FD6C4E7782F5B03F2C923C345BB19E47AD530DCC"
    $a3="*FD6C4E7782F5B03F2C923C345BB19E47AD530DCC"
    $a4="*6691484EA6B50DDDE1926A220DA01FA9E575C18A"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*DA7B25B1BA72C91D124FAD86067FE077C0D8F5B8"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*3D5B8D67927F4A2E700FB064CFDFB3782DB314E6"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a10="*3DD53704FFD8E6BBEEA51437F46D13FBCA2FFDB4"
    $a11="*3DD53704FFD8E6BBEEA51437F46D13FBCA2FFDB4"
    $a12="*AEB59784B985CE3167B371CA645C86111AEC20E0"
    $a13="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule ldap_md5_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}8iK57IRp0nIw70IB+V49Rg=="
    $a1="{MD5}8iK57IRp0nIw70IB+V49Rg=="
    $a2="{MD5}u6A0iR49O45N3TT1wCi33A=="
    $a3="{MD5}u6A0iR49O45N3TT1wCi33A=="
    $a4="{MD5}6ZoYxCjLONXyYIU2eJIuAw=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}8iK57IRp0nIw70IB+V49Rg=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}CuJBWwo9ilircdnmCK81Gw=="
    $a9="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a10="{MD5}KfWO1Kme4y/GTCX5Zw4PTg=="
    $a11="{MD5}KfWO1Kme4y/GTCX5Zw4PTg=="
    $a12="{MD5}ok89Nva6qHxytSHsP8AeLg=="
    $a13="{MD5}GzIxZVzrt6H3g+3fJ9JUyg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule ldap_sha1_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}glee/aW9bOYEewkD/6Ri8sHh2mU="
    $a1="{SHA}glee/aW9bOYEewkD/6Ri8sHh2mU="
    $a2="{SHA}5c+2irAGdhhlWwDGjYczY/4StyM="
    $a3="{SHA}5c+2irAGdhhlWwDGjYczY/4StyM="
    $a4="{SHA}Y2fEjdGT1W6nsLqtJbGUVeUp9e4="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}glee/aW9bOYEewkD/6Ri8sHh2mU="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}osUMjHQzDFtU6gth5vv+6iB/Y5o="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}JYeMvDhGQcHVz1L/iTWElbs05lw="
    $a11="{SHA}JYeMvDhGQcHVz1L/iTWElbs05lw="
    $a12="{SHA}1sU4nyLeXbsz33I6Mwm0JzqdLOc="
    $a13="{SHA}hFG6ihTXl1PTTLM7UbpGtLAl64E="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule md5_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f222b9ec8469d27230ef4201f95e3d46"
    $a1="f222b9ec8469d27230ef4201f95e3d46"
    $a2="bba034891e3d3b8e4ddd34f5c028b7dc"
    $a3="bba034891e3d3b8e4ddd34f5c028b7dc"
    $a4="e99a18c428cb38d5f260853678922e03"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="f222b9ec8469d27230ef4201f95e3d46"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="0ae2415b0a3d8a58ab71d9e608af351b"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="29f58ed4a99ee32fc64c25f9670e0f4e"
    $a11="29f58ed4a99ee32fc64c25f9670e0f4e"
    $a12="a24f3d36f6baa87c72b521ec3fc01e2e"
    $a13="1b3231655cebb7a1f783eddf27d254ca"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha1_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a1="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a2="e5cfb68ab0067618655b00c68d873363fe12b723"
    $a3="e5cfb68ab0067618655b00c68d873363fe12b723"
    $a4="6367c48dd193d56ea7b0baad25b19455e529f5ee"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="a2c50c8c74330c5b54ea0b61e6fbfeea207f639a"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="25878cbc384641c1d5cf52ff89358495bb34e65c"
    $a11="25878cbc384641c1d5cf52ff89358495bb34e65c"
    $a12="d6c5389f22de5dbb33df723a3309b4273a9d2ce7"
    $a13="8451ba8a14d79753d34cb33b51ba46b4b025eb81"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha384_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a1="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a2="f29d9083823cd602c0cc12705238aa5e4ab626e558331698f40b170a1a3152837faea8ccb8566b1129e30d057a84ff5d"
    $a3="f29d9083823cd602c0cc12705238aa5e4ab626e558331698f40b170a1a3152837faea8ccb8566b1129e30d057a84ff5d"
    $a4="a31d79891919cad24f3264479d76884f581bee32e86778373db3a124de975dd86a40fc7f399b331133b281ab4b11a6ca"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="6942407cc2d2ceff0e0ab598bc7d6341363dd2182e5ee8d30355402eac065efdcaea8ed734f6cb6e4cbf36d786cd3d06"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a10="073ab580db3ec877d60b05b08f33795ffce78c4f265ad8d30a3e84b8881789d5755483b2a26308943b536da2619f6cc8"
    $a11="073ab580db3ec877d60b05b08f33795ffce78c4f265ad8d30a3e84b8881789d5755483b2a26308943b536da2619f6cc8"
    $a12="4e8af95e7fda722d8aa8d194dec4b4a1f0ab4b936afa00cb3a8c3f2b8556a05c920849e731b98e96549707440efbf14c"
    $a13="4092bc3d8a0d7a293f438e15d1a039db25c54342ad87c3d97b4d0554fd6df01bf61704aa1bfe6fdc51c077212a1841e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha224_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a1="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a2="4279fbe1067b40837bc33323de5d6fd1785fd7f7606a79251879e99c"
    $a3="4279fbe1067b40837bc33323de5d6fd1785fd7f7606a79251879e99c"
    $a4="5c69bb695cc29b93d655e1a4bb5656cda624080d686f74477ea09349"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="41d8ab51aa117d8121cca391219c4c9adf1fd888417cf07504197a27"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="43779d1eda1cd9654de397b9311958b739d4ccef98e7f1e9c43d94ad"
    $a11="43779d1eda1cd9654de397b9311958b739d4ccef98e7f1e9c43d94ad"
    $a12="e12503cafeb0fe81c90cb7be772832c6b1bd22fb9329425e936b8cbd"
    $a13="0f726b72946abd860c0972fa8b50fc3c7ee6edcdeb23b42d6684e708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha512_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a1="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a2="7ce0ba2ea55e20401498f76450481d6d40829c024d70a8317efc91d1477487571e1415bbe8f4ae0e5aaed4c46750f6770d0dab4e24d52d7b68a7c8cad60f2e2a"
    $a3="7ce0ba2ea55e20401498f76450481d6d40829c024d70a8317efc91d1477487571e1415bbe8f4ae0e5aaed4c46750f6770d0dab4e24d52d7b68a7c8cad60f2e2a"
    $a4="c70b5dd9ebfb6f51d09d4132b7170c9d20750a7852f00680f65658f0310e810056e6763c34c9a00b0e940076f54495c169fc2302cceb312039271c43469507dc"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="cb247e9bbd901879f1112bdfb6cddc4899538ed68097e2b4a4d40a71ff90bf9ba26b0cf455bbe295563c61b5e6df122f9e8dd0afac5a599904cd19fe61308ae9"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a10="fcd78f7be6deef8efef818081b6a9bd1f09e65d7a9f874192fb5fa6627defa0912fc62957a722a3e99e117369495c2e3d492eadda3e3918e887f31c6940f0eda"
    $a11="fcd78f7be6deef8efef818081b6a9bd1f09e65d7a9f874192fb5fa6627defa0912fc62957a722a3e99e117369495c2e3d492eadda3e3918e887f31c6940f0eda"
    $a12="e6793def3f019b4bcf8450de68864668b63c2ed36c93fc62cc06904d091db6ba9e399d7db4093bb79b9e7cf1c046cf0d20292222eec90666ec8168a77c2bb803"
    $a13="36379d8584770820d95741c8efe571cc0ab37e2021c505fd8f384724d0676020ebc6d4f318e2533acf708fab8ede09c950a8daef54299ab9ea5ba1e1fd4b73bf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha256_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a1="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a2="0a2b6aed9a29e267b2d2f7898e42316d36a027848755b946c1e9ea42649e69e0"
    $a3="0a2b6aed9a29e267b2d2f7898e42316d36a027848755b946c1e9ea42649e69e0"
    $a4="6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="b5fec6a11b2236e2c5bd760dd50cfcdba47407dfce613681c05dcd6fb75f7acc"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="7f411c23e7d9d268b51470b27920d362905e71fca86a2ef5c70747984b30a29a"
    $a11="7f411c23e7d9d268b51470b27920d362905e71fca86a2ef5c70747984b30a29a"
    $a12="58dd311734e74638f99c93265713b03c391561c6ce626f8a745d1c7ece7675fa"
    $a13="73d1b1b1bc1dabfb97f216d897b7968e44b06457920f00f2dc6c1ed3be25ad4c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2b_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a1="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a2="8cc249a7d8ec1963c391ae0a8538e62321ba92d9d713ac6eaca8608ed1a25617da77be496ecbfc6773d4000f6cef1dea523118592b45a59f1b50c301e5a89009"
    $a3="8cc249a7d8ec1963c391ae0a8538e62321ba92d9d713ac6eaca8608ed1a25617da77be496ecbfc6773d4000f6cef1dea523118592b45a59f1b50c301e5a89009"
    $a4="585f3b691b374d85d6883348aaad9d63b4cb6b1c9c01aa1ccd2fcb880b27d2e1023c71be0213f161f3caec468178f9266ce06c0517491feb0f181cb4a0c9e67a"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a8="11eaf240b60d40159e0757b56fc4999737b5c9f7eb67ee0cca555c1a46a2cc9b5e7ab62c8513751f968ef466af723bbb39a0ed5ea3bd7693b5de8b8f6745a996"
    $a9="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a10="b9722577230d64d1f0481b3fc1eb29352f0b3640a967dd9276d8f1b417b2f7dd0dafdfb94cfac7adaeede0e830fcacb427517ae73953dfaa8bceac4ace86b254"
    $a11="b9722577230d64d1f0481b3fc1eb29352f0b3640a967dd9276d8f1b417b2f7dd0dafdfb94cfac7adaeede0e830fcacb427517ae73953dfaa8bceac4ace86b254"
    $a12="ff4339a67d0d9692d46206e9a2ec2054b48e73c0e03b364bcbba76b84560b7df10d8616b3347dcf51ba795ebefef9271cad0f75492b16c8114189593f2d345cf"
    $a13="da8d291e0916119783bb03757c6252fb55ea1d51bfb05e3044d676a827ad9afd002fcfdc5706406cb66b61cea06b9ba64f895d7e66b8aedd5bd84182b9b46fe0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2s_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a1="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a2="6cf89fc9d03c853b527101b230e9c407518587ea1e5a02acf8a04d503011a009"
    $a3="6cf89fc9d03c853b527101b230e9c407518587ea1e5a02acf8a04d503011a009"
    $a4="bb48bdae67206a493787b69821008fcd6249d013125972db3660e75ab6f3c884"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="e1bcef28ec1e2de5e2dcb74a5c8b52190c44c17ded9c8f4a2482e8cb8299459a"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a10="64e6c635432e4f47869c2d062ac7738cc60facd584184c89e2e5614b9d00d666"
    $a11="64e6c635432e4f47869c2d062ac7738cc60facd584184c89e2e5614b9d00d666"
    $a12="eb43801c2bbc902aa1a198866e32ded43c5004c7c47954b04f003d287d2356cd"
    $a13="7b866d188933ccc5dfc6f79bd6366c759f7661ff500626bc1b013b6947eb5831"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_224_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a1="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a2="aa37e818a70652b92859f6fcb4a017e719f83d07039457447c61037b"
    $a3="aa37e818a70652b92859f6fcb4a017e719f83d07039457447c61037b"
    $a4="026727ec105a060b02a0086a2181748f6b9ac3cea3fc347ca8675984"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="e75cf98e6e8fc6775e99d9d2563f172f1855b3f1788c9a7db0932704"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="56279de09aff6b05fc30a9e345a3602f03b12fbcc48b3f21bf76cbf6"
    $a11="56279de09aff6b05fc30a9e345a3602f03b12fbcc48b3f21bf76cbf6"
    $a12="a9ae02a96da3643414ad2a9fb3d76d6a6d441c84f745edf5e0aea1c7"
    $a13="1bbdd3ab361d7fd9a47de72543e337093aaa664a02248557615675c4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_256_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a1="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a2="b521ec75f7cab7a2f3aff2631c89a706ff899eb3f81f1457199c73e371272568"
    $a3="b521ec75f7cab7a2f3aff2631c89a706ff899eb3f81f1457199c73e371272568"
    $a4="f58fa3df820114f56e1544354379820cff464c9c41cb3ca0ad0b0843c9bb67ee"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="91f679a7fe843734184eb5e5b53a3cb82401336c7750fae790fd6b594619d853"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a10="ef10231f890a38ce1fb470f7c566b2fdb713ff364f9253c5b838e73bf8d8c55d"
    $a11="ef10231f890a38ce1fb470f7c566b2fdb713ff364f9253c5b838e73bf8d8c55d"
    $a12="6673b63f3a87b427a12cdbf510ac140b227d458666f7d6ee2a0dea4526a4dd39"
    $a13="79de1c617efcf3d784ca3b5d1be7fefb1d1287b079fe4527640c36446cd29ea0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_384_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a1="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a2="33ce5107b40988a8734c41e3cba1b8f6e4f6da52d6799d6387ce87d6f50c4a47041adfecc4fbe88a3b2c2a18764724e3"
    $a3="33ce5107b40988a8734c41e3cba1b8f6e4f6da52d6799d6387ce87d6f50c4a47041adfecc4fbe88a3b2c2a18764724e3"
    $a4="e07300227b15a724fdf6555569e38282022d106d778aa2268898dc21639b24e1e00fcc0a6d96ffc8b3a97c7fa7296305"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="8ec9de56e89a5103fc2307816c7ec4b5b3c4ad29a2ba8d219e1864b5ba041798fcef6de0004b155e69ec41975d24f2dc"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a10="7402910b87f2e5294a29e2a5388a2908f98aea5a20f1e4e1074bd67e4d11c182c2a709d7772ac1b05c5d66c7011d7ec8"
    $a11="7402910b87f2e5294a29e2a5388a2908f98aea5a20f1e4e1074bd67e4d11c182c2a709d7772ac1b05c5d66c7011d7ec8"
    $a12="e571cf56bb1b8c66f560c4f729627feba4863b5ecfd75b7eaa4c5e8b1d92a614214eb0981dfdb5675d39db73b3c0d4ad"
    $a13="a42d04a5b4a2ea45ecf45279aaf3ec8fd906355e3ab856231ae7815a5df6a96f76fe4987dd638981314c942ba825de69"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_512_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a1="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a2="76e7d4dec7414f98d398948e38d0232cfa311fa1053ffd8a977a6a0fc2911ba81debbb577282eded9bf22ac2a7797e2dc2dfa8a1a72352988ceb80e7deb9a1ee"
    $a3="76e7d4dec7414f98d398948e38d0232cfa311fa1053ffd8a977a6a0fc2911ba81debbb577282eded9bf22ac2a7797e2dc2dfa8a1a72352988ceb80e7deb9a1ee"
    $a4="3274f8455be84b8c7d79f9bd93e6c8520d13f6bd2855f3bb9c006ca9f3cce25d4b924d0370f8af4e27a350fd2baeef58bc37e0f4e4a403fe64c98017fa012757"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="343044eba1a91f0d960f6d74515841926409bd574a203089c491cf4591ea7c1b918b4c381c13ee0a77f42d7bb2e04d9e4d75a189db5d20d1c6780ad744d7ec6a"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="cfab24261aacfc33b29081381b843df5e7e5f69f230ac7f91a00f7bfaa468ceb439e2ff659ff401f9961487d379b710b48708a1ffb7538bf75999a3b1e86365e"
    $a11="cfab24261aacfc33b29081381b843df5e7e5f69f230ac7f91a00f7bfaa468ceb439e2ff659ff401f9961487d379b710b48708a1ffb7538bf75999a3b1e86365e"
    $a12="f00c644c174825d50278946c432d337ca61c711b102785c9fdfe1fe7f65a8b163d1087ce0f964d31b510a9ef8aef606eb22d0fcbe45f889548649919d3e907b1"
    $a13="a5cb39ab7a85e70d39ae78b734b0f42660126100c6d458fdd3f8e6b20ab8f73b2db2a02a0ca8d38d40b6b2544be6491243703c5770cbce76385c2e3a9c791f36"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule base64_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bmV0c2NyZWVu"
    $a1="bmV0c2NyZWVu"
    $a2="c2VyaWFsIw=="
    $a3="c2VyaWFsIw=="
    $a4="YWRtaW4="
    $a5="YWJjMTIz"
    $a6="YWRtaW4="
    $a7="bmV0c2NyZWVu"
    $a8="YWRtaW4="
    $a9="cGVyaWJpdA=="
    $a10="cmVkbGluZQ=="
    $a11="cmVkbGluZQ=="
    $a12="c3VwZXI="
    $a13="anVuaXBlcjEyMw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

