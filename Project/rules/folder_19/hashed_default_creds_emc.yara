/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_emc
{
    meta:
        id = "JSge0Sl8L1dmMj8d56s7f"
        fingerprint = "83f1dd2c173fdaca3065324b57cb57525fbd1aa4cda5fa538be12905172e0f68"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6597d9fe8469e21d840e2cbff8d43c8b"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="20ef7eee1a0a2d1fec9aa7bf4a2b2163"
    $a3="ce5c7d0cadb3759fff94a538868f724b"
    $a4="0e2cdab5727c1e8079b9cc1b27d354cd"
    $a5="e1daa6cbc45a19807adf8d35e92e7ba5"
    $a6="6597d9fe8469e21d840e2cbff8d43c8b"
    $a7="86ac17999294d3eb7896c43cade27b15"
    $a8="4163ea3838183f7c4c209a535514bb6b"
    $a9="00b56d57e617705868a256e455a83759"
    $a10="46d2d4c24beafdf7063a8e32473345c9"
    $a11="c717d3d6938bfb0614cae483dd122baf"
    $a12="1053f6259c781a0c247da712cfa665ca"
    $a13="329153f560eb329c0e1deea55e88a1e9"
    $a14="6597d9fe8469e21d840e2cbff8d43c8b"
    $a15="329153f560eb329c0e1deea55e88a1e9"
    $a16="065675866a2397120024e08d06f235a0"
    $a17="776d59d041cee7694a0e88d40da7bce3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql323_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="16d7f906289d77b3"
    $a1="43e9a4ab75570f5b"
    $a2="3bddeb931f8eeede"
    $a3="5ae13bf65efb4e4b"
    $a4="2589c6b11a5f226a"
    $a5="7edb51880433a2b9"
    $a6="16d7f906289d77b3"
    $a7="7b11c80522accf00"
    $a8="4217c78666f07ecb"
    $a9="2deff7b92004fc45"
    $a10="765d8c050dca2c7b"
    $a11="57217c04615a3276"
    $a12="78b91e8c2868f026"
    $a13="67457e226a1a15bd"
    $a14="16d7f906289d77b3"
    $a15="67457e226a1a15bd"
    $a16="67cd04f17742d92e"
    $a17="0f68a4ec5ff09f3d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql41_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7ACE763ED393514FE0C162B93996ECD195FFC4F5"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*23D207B80CB399DD90E671C00F3F1FB1F20A67EF"
    $a3="*B52668B9B4ADA43952CAB9B242CA008CA08DDFD9"
    $a4="*9CCA84C4AE365820016A08F7538B25CE700186D3"
    $a5="*6B867EE27B1BE0B7EAADAB4E09B8E769CCCC046B"
    $a6="*7ACE763ED393514FE0C162B93996ECD195FFC4F5"
    $a7="*1C1F1256BEC224F7BD6E95DF9B5C08CCCC90EE7E"
    $a8="*12B746D03606F1CACB981323320BCE34D375B818"
    $a9="*FF2B052102DB87AB79B0CAE304320342F3095543"
    $a10="*0AEA1DC2EE67FF76BCE16CB00C8A225205875988"
    $a11="*18557B67649092787DE0A18CB05F4B006B9E87FE"
    $a12="*F75DE5DC83E9C80AFEB0332A56078058EA482C9C"
    $a13="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a14="*7ACE763ED393514FE0C162B93996ECD195FFC4F5"
    $a15="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a16="*601D6082D86C8FF66045AD4867BEEEC9B1389CFB"
    $a17="*37E95B7CB2FB12D94D0DF8022BEBC24521640F3C"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_md5_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}TLnIqASP0CKUR3/LGkEZGg=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}Gp3/FfmBUEQhdCcaIj0B5A=="
    $a3="{MD5}ful1KyzIz3kWaHPaE0rHYQ=="
    $a4="{MD5}A58rrK0kWjWcyI9Dv0u9Pw=="
    $a5="{MD5}XamHRzlzqZbzA9zPowgWDw=="
    $a6="{MD5}TLnIqASP0CKUR3/LGkEZGg=="
    $a7="{MD5}N94k1EAoWljYbmg5o+sqzQ=="
    $a8="{MD5}BIwhtxE3rZeIYLfmfl9pwA=="
    $a9="{MD5}ZAD974uH7d5GcUV4+LWocg=="
    $a10="{MD5}yVw22qFylsYxfz/Gdd42CA=="
    $a11="{MD5}womC9SZCF8ms+rIxR77+MA=="
    $a12="{MD5}B4SqWGXY+/9Roq3UX53gUg=="
    $a13="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a14="{MD5}TLnIqASP0CKUR3/LGkEZGg=="
    $a15="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a16="{MD5}aFPVAdlva/HiUp6mfyMyOQ=="
    $a17="{MD5}scW+mNfojBlkeKGVvZzJNA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_sha1_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}+pvrmeQCmtWmYVOZ57uuITVghrM="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}KSzi/COlnp0ojlbsvJn94ZyFse0="
    $a3="{SHA}cVo5hbOXSoLeKqXuSNcHpyDDJWY="
    $a4="{SHA}7/0r/LwDkOQ3DgZl2YQe+k8YrFk="
    $a5="{SHA}WI16qbupT+vW5NEyUdvpc0TJBcQ="
    $a6="{SHA}+pvrmeQCmtWmYVOZ57uuITVghrM="
    $a7="{SHA}0tcQ+UtSBdNent0LDZFNycn3DOc="
    $a8="{SHA}wLluvb1Gf0gu9qAmg22L7KXzoKY="
    $a9="{SHA}EzkNcdMmNvZd0Wh39j5uiYG+HVc="
    $a10="{SHA}QXVK91l4PjhJHXGcw/HB1e30boI="
    $a11="{SHA}JL9KgCYlDOqUOTZSKbXPUVJMh9o="
    $a12="{SHA}5BNMDBtATbIBUc8gW4wWoos+FKA="
    $a13="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a14="{SHA}+pvrmeQCmtWmYVOZ57uuITVghrM="
    $a15="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a16="{SHA}qMUPtuSIL4tq6Fkwjhv1+xDol/Q="
    $a17="{SHA}KhdeIjK3SF1tYRa8S/3Npy0mS6I="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule md5_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cb9c8a8048fd02294477fcb1a41191a"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="1a9dff15f98150442174271a223d01e4"
    $a3="7ee9752b2cc8cf79166873da134ac761"
    $a4="039f2bacad245a359cc88f43bf4bbd3f"
    $a5="5da987473973a996f303dccfa308160f"
    $a6="4cb9c8a8048fd02294477fcb1a41191a"
    $a7="37de24d440285a58d86e6839a3eb2acd"
    $a8="048c21b71137ad978860b7e67e5f69c0"
    $a9="6400fdef8b87edde46714578f8b5a872"
    $a10="c95c36daa17296c6317f3fc675de3608"
    $a11="c28982f5264217c9acfab23147befe30"
    $a12="0784aa5865d8fbff51a2add45f9de052"
    $a13="63a9f0ea7bb98050796b649e85481845"
    $a14="4cb9c8a8048fd02294477fcb1a41191a"
    $a15="63a9f0ea7bb98050796b649e85481845"
    $a16="6853d501d96f6bf1e2529ea67f233239"
    $a17="b1c5be98d7e88c196478a195bd9cc934"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha1_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="292ce2fc23a59e9d288e56ecbc99fde19c85b1ed"
    $a3="715a3985b3974a82de2aa5ee48d707a720c32566"
    $a4="effd2bfcbc0390e4370e0665d9841efa4f18ac59"
    $a5="588d7aa9bba94febd6e4d13251dbe97344c905c4"
    $a6="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a7="d2d710f94b5205d35e9edd0b0d914dc9c9f70ce7"
    $a8="c0b96ebdbd467f482ef6a026836d8beca5f3a0a6"
    $a9="13390d71d32636f65dd16877f63e6e8981be1d57"
    $a10="41754af759783e38491d719cc3f1c1d5edf46e82"
    $a11="24bf4a8026250cea9439365229b5cf51524c87da"
    $a12="e4134c0c1b404db20151cf205b8c16a28b3e14a0"
    $a13="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a14="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a15="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a16="a8c50fb6e4882f8b6ae859308e1bf5fb10e897f4"
    $a17="2a175e2232b7485d6d6116bc4bfdcda72d264ba2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha384_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d49d02c105312b2b69de69141b27de1f4f4c202b4afb19d7ff7ab9849e9ce2da165a87eeec971bca66c8eb8a9243f5e"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="5ee1d08abec5d818b59b0e22d5ded61a05e835fe9ea8f68ca9d0210800e3b4adfbd56ca4648c918a6e4ef74b1e3ecb91"
    $a3="189026f3f234f462081bec6ca8aec82b2d0405369836e45e358555d61cccfe4dd35d39a85e67d06fd9239bd29826d6b4"
    $a4="abfcd51107009802bf80ef9890046f35ceb0b0e0025ed356201caab7ec8737cb5ac2f34c2be25810dcb72bfce15caec2"
    $a5="997d685c0ab93f3714463271d73b5f7064a6ec43806615adf6e9bd8e1a4abd2cef990dd60f135410468fa5571580db0d"
    $a6="7d49d02c105312b2b69de69141b27de1f4f4c202b4afb19d7ff7ab9849e9ce2da165a87eeec971bca66c8eb8a9243f5e"
    $a7="7a9cac3d082c3375ebf63ef9de32c142fe23117a1a23eb5b24037d3da85db7de7d21176bef4e63d0b78f325e0ad17533"
    $a8="a18e313ce6550be03c864a81eb16c38b507e2c4142bfa2eb4c3b25053614ce1da4e435d7cc610f78dc62feb4701738e6"
    $a9="56b4f1b14027ef9b7d102a99a9f5d68b6b6a69f7d7fe89c97f9ca2aa524304ae96f929ffe66ffd6bfb18ad82842d5143"
    $a10="a008bea21ec79efe3e8d690a1156d8361e38f5b99b85dd26084c1a94640f8448c56e3848fa5ee3f07aba440ab9b2454e"
    $a11="b3bc118b96622f2a6cc6f1690877a834694522f799f4bc14c1e624f40bc9a5cac5c8a9daa5cf982a1512ab9d93e61ae6"
    $a12="b2aca9aaeed84dfe91c250a4ca19e03c631fd868b6306e7eb9b28f54ae621dca34bce15c6c104d3e41f56cd2b9f2662b"
    $a13="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a14="7d49d02c105312b2b69de69141b27de1f4f4c202b4afb19d7ff7ab9849e9ce2da165a87eeec971bca66c8eb8a9243f5e"
    $a15="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a16="366176015e92031d29279a1931fff636af422057ba28f8bd90fc5ac06c377659fb2266bf9e1e3028f3d76e0a5152bf43"
    $a17="773531f1235a3c4213d2362fcc216b29924bc178d7636e5a1008ea3103653c812bdd96a6074feffcb86f3928334fef0a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha224_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d44d697d0b8ad27b1d3b323b1b438db88058ec1f0f21cef6a6629875"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="3d7ea88d6c869df3c7326230d4a3bbe76993f67ebade69e0e46b2bbb"
    $a3="6614945760a6568582ca94104cf566dd4931a41ac1546ea73acbd9dc"
    $a4="2c0e54538d2582098103c41da137dce369f51b8690cd1b8bcf3e0228"
    $a5="17d3983e8297628a6400a5e441b65c22372de7535f468ba18e889df2"
    $a6="d44d697d0b8ad27b1d3b323b1b438db88058ec1f0f21cef6a6629875"
    $a7="974d62c38ad1996671df727d71e53f442fdba9f21bc35d4ff8eb5348"
    $a8="e2b1240397465c81daa159424a02be50867e0ba28da9a8748da91c89"
    $a9="4653c13e58206009fd28db9b079ee85d7b6238b422cd48c891bcb7bf"
    $a10="9ab8ba636aa941f12a5a2cead78f1464faad9d25237ca6ba3cb6674a"
    $a11="4a21a97d5cb6a370f3dc60470c542cef6ea268cc1df14a1b4e9f76d0"
    $a12="f459bcf13fc1869d739145c2cbe37d9ec0905f7310c1986f96718ace"
    $a13="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a14="d44d697d0b8ad27b1d3b323b1b438db88058ec1f0f21cef6a6629875"
    $a15="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a16="38ef1fe54a7fb1d97912261fad5be7d9ebb1d65da721c1ce3674eb5f"
    $a17="365e8da0aeb4aae7d3e9ab76558f6a7263c2f8eabbf79dc787a30210"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha512_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1891cea80fc05e433c943254c6bdabc159577a02a7395dfebbfbc4f7661d4af56f2d372131a45936de40160007368a56ef216a30cb202c66d3145fd24380906"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="cd21033a53e53cf1e75586197e7a8d5e3fe4fda078df7d65f140dbd143ed8aa790e69f2361f967ec144e22a3cdf4ee036e45fee9175172b78e7c9aa5a0a2b72b"
    $a3="163c6a1bdaafba69f12796f88cb16e5a4af4e06637a11310f1118fa8e888c50317aff856349d051543e5588083ed733c5865dff83ef5edf92f2c647a7e0f8dd5"
    $a4="eb1eda81f69634e240f96160e0b9464e3402683b8d52daff4d80a15832ec1bc2e70cb011414e30d406633c68adddf7d22c9b670985867ffb7e658ae00b1e898d"
    $a5="673f0a743257229d67871e335e91ecd462b52037e3eb6995d7e5f65db830efbea268bff710f30bb8f6f46ba6cb0fe24e7da470ced7ef12dbf3741dbb358e54c2"
    $a6="f1891cea80fc05e433c943254c6bdabc159577a02a7395dfebbfbc4f7661d4af56f2d372131a45936de40160007368a56ef216a30cb202c66d3145fd24380906"
    $a7="be8c78b042354e5b2baa51894b1d19ae4466db4cd1f5d0ac43d0a5ca60f7a6f95413e4f2c3351a4f87bec8042768ef5c96b7bba85061899b9d3469ee17e43fdd"
    $a8="aa8b616e40c0d952b0f3e19e475a9532fe831671e7c0744ec406df190335c465635f837ce995d996b7416c2aa75ea9b4196b7258c5414f558b59d65a7ca37d5c"
    $a9="3d6bf92232152d62c47ef6c15d2e179980618d11af8842bb84be76f4cf1be69d4309a7172eb3f3b8bc9f2cf036f2bd3436e133f2b38b1f81108155a09d50fd6b"
    $a10="386c44482bd536e4d671408dbd399dcdbd00bd4c8e3946f123e17e5f68147900ac1d9737b1dd4cecb4b0036892538385bd92912f81f021fb64ee6dbbe3bfc618"
    $a11="614952accbf592f1a3ae026621836761a7848865b2e3b5b38554f9bfbd91d059e036b7fa84cbcef8868a1c8147f090d429a6eca8c99d9aa5e915e216a051bcf7"
    $a12="2a891b2e1eb6c38f1075bf5fa91b48ea1d0236383f6b6c7278aacef56f0ea58d961d702642f24df2d3c5821370f2d623bb79d00c19f9300db46adff8649f728b"
    $a13="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a14="f1891cea80fc05e433c943254c6bdabc159577a02a7395dfebbfbc4f7661d4af56f2d372131a45936de40160007368a56ef216a30cb202c66d3145fd24380906"
    $a15="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a16="91cb40580a3ce80da44b2ba9268acd1ef48b6c8eb514913a397e4e5b1e22726c450477b601572727b9885b13261c9b6b4aaf6a02abf48f348ea2739b964135fc"
    $a17="e9b118451ec08fac35c6e60f80e5718a132290186a18c9e4aa56e7bc98c586195035782407028f5ac1c91c19db66c1b5d8e8f1a6a0d6005c58704937a910677c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha256_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="90d54bfba6ce83053e381a1f25ef79623ba173dd2da1efd0d8012c59ae35c469"
    $a3="0b2087647dbbe70aabe73080cff1b0d8c57abb814b98e3be32b981afbb4e4154"
    $a4="a732f6cdd70a5011b295ea183f68822491eccc0b861dbb14d63023c6d83f0ba0"
    $a5="d6c23081e62be3824f64d440f8857855d0f4743a0551012ab1ed00960faba149"
    $a6="057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86"
    $a7="3f307a9a1f690cbb0898051c943548043edb143d777248190a9efe613624f7ea"
    $a8="a6317ad3260928e8a244330703cb86786f823e85ed1e20072f28163a3e99a984"
    $a9="3c29ab9823defa4c1e4a77dd78e3a8a4fa29e7942401a66f4734fa2f7a0c1bf9"
    $a10="4e20152f0b52d424815059d5cc82ba9b9413b82c9ffa7fb09b4a57de7388cd0b"
    $a11="235e1ec32d2db775a74afe5994b9de8a16fc3df5a80d08c9b8d10606650e3d55"
    $a12="b26c1994a343adb04d4fb3d253e0bf29263fe36755cda2b7754ef65691532582"
    $a13="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a14="057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86"
    $a15="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a16="97e5a2f661a8289c12dbb8f8a71db88c874ce235f038e2aa97ea0cfeb1b93e33"
    $a17="b1689f3e85811e030024b1ec6e1a1f0e7cf0392fe5b0f1ab3764acb4c30cd242"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2b_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc8653499aba9b909eecec568e20a1855cfc87f30ef8e109ef4e6d4cb9fff8aa9461d5c3092fb1e5f3950ca5fdf986cc52927a2b1d7bb30af201f2ff95f34d42"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="478cc3bbbddedb27bab8d1b670a86380f92a53e33f9637e27ec4fe67bd093f7749f2a4f7fc77b0490dd2507433c982829ae8814cc89014a3ec1df5064fa04536"
    $a3="009f143028d34d1f7f79c6c674faa58d9b0b33fc31b78b6b560b5c8dc953f1a7175e87d8d01fa107da3d534062904d7e3356464497ed7b43419fa2ceee348a6c"
    $a4="2ae6a28c0d3ebc14e236bc9c21f70a7ce2830dd3c28f536d342888244e780e3bd14e38abbe59c18827a60175c5bd52f4cd82c2f0816587cb6ba63b9fafa6558a"
    $a5="80aa441595cdb25275c04da116a500a6ddd59d36dee7b6a41e2f9aa7ce86727e90037b3b4234d9c357981c2620958886226157b50ad94f5cc9b21bf8cb46ca93"
    $a6="bc8653499aba9b909eecec568e20a1855cfc87f30ef8e109ef4e6d4cb9fff8aa9461d5c3092fb1e5f3950ca5fdf986cc52927a2b1d7bb30af201f2ff95f34d42"
    $a7="9be0382b6dae8d7f2936b96bb74d1999750af836734d7128d62554f42d3f5c4d77e35a5d95d95d0e141ff43d976080d2de2dc01f7ebb3fb9daea374f841cd83c"
    $a8="06bac88d56ef044ec6be1ccb3d7cbaf60d76b43aac94a5758c4d0dd4065e9298daaec1ea422fc508e08ad46f91cce3ab51846b5ff3335c4eb2b32faa4da3afa6"
    $a9="71db035183bc0c08edc1865b71832435ffa333ddb7b2b28b35e011f31de4f3a7a3c5b2a1e248af7689a59f4ba91795d67cd700d9dbd29ba7331226f8dda30329"
    $a10="62340171752901228fc3cc903f2ffbe634b64e2fbeb19556e9564e24e86fc24969344e04069c25204b3a492ff0cfa0c92d75082a47d29ba09d87d03f064a5658"
    $a11="e23f3df559069a8c34e5fa474aeedd701d32f3a25ba01ccdb9de5575045e9fdd0dbf6172a2d31c7a57cd110bd6baf210c5f344b3de701f5c95cfe7c070a12f57"
    $a12="871bfc6c0bd0e35c2dc9c289a3f3966437644869fc781c494bf88aba4b1aa5d98a36bb6b29e2cb14807176c1a80f5a0e4550f795421da6a6e07971d6e98397a8"
    $a13="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a14="bc8653499aba9b909eecec568e20a1855cfc87f30ef8e109ef4e6d4cb9fff8aa9461d5c3092fb1e5f3950ca5fdf986cc52927a2b1d7bb30af201f2ff95f34d42"
    $a15="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a16="bca4107957a8ba8de3402bf54643d01b3e30794db6a347c54bc4cf65abcdfccb62116b23ba9406419133c4f86b8c62c71ef683487e2bf16410b2555eeae6a1ea"
    $a17="b622c98d488ee11d924919e2f44bdf287aa6b086b2855e3e2626a03f2d44f3f4daa3cd08de5507f92d0eb4d1ecf04e3e3659ee0a9deb7e8f0a03643331584ce0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2s_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f7eae1ee1e4295ab992391eea5d33a45e869e50fabf367779086eec821b2698"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="17067af1913eb555b0283e597e251d154b151d88512be8ddef7c6cb750e09499"
    $a3="872f9846489099e98dd539c29063595b1590a7333961746e29054c242d24b482"
    $a4="7aee28225dd16f75dc40bddbb3d9a6f45476dea164dfc0953530f24a5cdc15f9"
    $a5="fd61773db521a571f1db89f81fb6e6c5380237d343a752ab1c7aa8bdf4fca339"
    $a6="3f7eae1ee1e4295ab992391eea5d33a45e869e50fabf367779086eec821b2698"
    $a7="c35cdcf198f234375ea1d04b1ee224c5586963be534fbab5db534a7f4c41e1a6"
    $a8="62ffebfc7d98cc4cfb2ea5eb239ca64209686a0a0ee3ca6ea62a0f8ba8e99004"
    $a9="db8e41d90b60768cb3a8f0e336ceff6e8cd671bfea6f7dd44e4d571fb94d68f9"
    $a10="7dc1fc2f021c639d21a5fa23845b8ad42b4b8e4dc577126a2c822e6edf53ca4e"
    $a11="f56d297ea2d4a133e0eea828167858cc057619c1376c72f5c6b06d11f4be7e3e"
    $a12="950d9a459d063f60b3bb95fb09a0697e91dd4e389b3c95edb7beabd5765898fb"
    $a13="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a14="3f7eae1ee1e4295ab992391eea5d33a45e869e50fabf367779086eec821b2698"
    $a15="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a16="71b6dccf48c8ffaaaa5e98a6b66d7edeb700618217887720ad4315dda386a3ee"
    $a17="b767b860ca27311c09f830fc93f10568347a163512ab201658abf899984e4c6b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_224_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3580d8fca5a3d7def6d1bbb076d8192b806ba4155c7569c89713d606"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="2c3d933efdd16ae731789df1d9e16ee2fc7f82c146d3492164bd984a"
    $a3="a4c1d857adda5dfc809d113954d97dd83bf14beeec1fe283efa7668e"
    $a4="7ccd52406c65fa2750f2af98b7311f83d4095a1f04e97e979ab80c3b"
    $a5="a1b536ef35e2aca9c8bffe7db3fbbec1ab544343b442f9c207d8deb7"
    $a6="3580d8fca5a3d7def6d1bbb076d8192b806ba4155c7569c89713d606"
    $a7="78f2aea7408e0b140637310f02db6b51f0945e043346db1066c7e93a"
    $a8="cf75acd4f8a6ce88b00c963476b6e898136d3d5d1b007e48b251a25f"
    $a9="b4f65596e7a34b361c97db96506bdbd7b14ad1b16cbd673fdd81a789"
    $a10="e655ba80b0eef8d6875c5d329d9f2ed681240262aa70deb9734573ac"
    $a11="de85fde5226f589ff9d73c1e6e2ce53663c1d30a441725f1f63e3be6"
    $a12="bb6c0932ed44420658738a0194f31e5b9f80c26637cc45efae18181d"
    $a13="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a14="3580d8fca5a3d7def6d1bbb076d8192b806ba4155c7569c89713d606"
    $a15="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a16="292b5d3b0b5c90e601b72e957c11063331ae6fb53864f25136280cdf"
    $a17="bc0f4fd22fdfbfbeea5edcb2d480fcf1bcb97195f76862f12daa5558"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_256_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f4d6ed1b56b50792c161e7b440f2931279901d1fc97791c69af7d3d2381980f2"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="8e90033587dd20136a0a01f5fd60c9c5b3dbd4c7a861fe3a5103770f5bff00ce"
    $a3="85f8cb58213e29c45002fd406a44330b8f7f2bdcf83f8f75e415aec20d6e67c4"
    $a4="360c6fa6f091e13c7ebe465e778892f5619baa6a2207e70193d49d23b56fd6e4"
    $a5="de56b22441814353123f3f44762a6627fc4ffd8098f99e9832430a1f32d75304"
    $a6="f4d6ed1b56b50792c161e7b440f2931279901d1fc97791c69af7d3d2381980f2"
    $a7="8bf690914ecd52802990ce2299d4a6f370d9b412cfae6fa9a13de5710ec200fb"
    $a8="9c86bd4a1aa16e8389fbb5d8e26a4ee7996cb3e983206dafaa408cd1d3f445e7"
    $a9="d29734b14647584c84b83be00c0cbaadf37d4047296f3669cc10604b7bb0b705"
    $a10="7cb024b68f5fd8f14db8f0312c8c3c9f493e53965506736e4ee3d397da06d56c"
    $a11="9fc4a62b0da15acffa43ecc9785b713e44232ecf2e8e9bb30b7a638d90ba2ab6"
    $a12="ec892d8c22086b42f17af010d9a8db93464697f29b27df30a73679f9d867ed4e"
    $a13="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a14="f4d6ed1b56b50792c161e7b440f2931279901d1fc97791c69af7d3d2381980f2"
    $a15="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a16="974984b884d014413e0f38d1266b13dd45821d796c0fb2a39d7603b76eb3ac74"
    $a17="c4c2fb2f0a693d7fdaa22d59a988855d57ab900db35c8f82abcf0dbad564bf04"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_384_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d58bfd306307b517f58bda7326e3570b9e38ca9cff807e9023d8c3af94c89c0cb1c5216038bc235e8ff6fcfb86fcf6c"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="e5056f348fbae4dce2fdcd72782a040f7cb96d4182e56470d86de8b0297d1a99ef6e9f22187f01a164e75789a902c5cb"
    $a3="9f6e3a5a86ab5e0fc8d721d32028c610a3555b077f3a2d6f48c36a6a7d811f25eb3a1849b202a5ec93bffe57533f415d"
    $a4="390370553b9701729502c071325707136e00c66254354810413142cf4e1b53dd4012a41a46941fbde20b0c2fee632164"
    $a5="39954ed9bbe8f2430596f56c7d9e1e2608ff3b5a72137ee5b13de5152151627b7cd7984c86ebaa3c7cf6413d31be4c28"
    $a6="4d58bfd306307b517f58bda7326e3570b9e38ca9cff807e9023d8c3af94c89c0cb1c5216038bc235e8ff6fcfb86fcf6c"
    $a7="3832258cfd38ddad07cbac3e2096570fe0d62f3ef422de0ac24bb04d0a0b375ad5a55e5d14055ebe28e92f4901dd36f3"
    $a8="658e9dfde4ebf1355126c0372b5dcd9ef83307c49bff1423bcee8fa7cfd74e09b6cd09f00bbcfe459b12c47a44a2a02e"
    $a9="918a2fc933aa7b47d43ee85682d32d29601d256aa0f768a9c974dd5db9c8c5df5d3a78602e51ab8c3f409690f910e316"
    $a10="d388910b9edeb37357b801ba430b5675e84e47dd07f49731b7efdc7f77c8ae88e7c3f28f1a7a7e0eb9c37a9e445e81db"
    $a11="ee27bf37b19416948601ece82354a16f45261823dc67fa50572c26307a9461c324db70d31cfa6d9224831d0166669529"
    $a12="10fb06fe1d152dce31277d56a48e2ea545df7c655f6d4028c31931586060a09db3e16151c673ddec2fd3cfae8b8ff0c3"
    $a13="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a14="4d58bfd306307b517f58bda7326e3570b9e38ca9cff807e9023d8c3af94c89c0cb1c5216038bc235e8ff6fcfb86fcf6c"
    $a15="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a16="8c2660f01503a611da0e444a97e9c17b026a56396ce2dd4bd646ac0cc5f4c0b2dfb39c6746c306b777cb5eabd3c02449"
    $a17="273e59ebf559e1e5b94c785777a7edfd4b4f8b09e11b8db7f24b94e84acb7e48ef120e234c21ef9d319e41c9188e5c83"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_512_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="83ed150dbcc9700521ccc2f7d67243c3d4000c8228281488dccd6c6753f48515dcb24714d5a294df27eeda834e9242e1ce4014fc38df3e0439b999fe3efa0765"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="e3ccb7422f440e9f4e464ecf6fd3f69b9ef5efd3448625ef29d1c82b7215f9456e8399d684dc403579a900dc7962a46f65e4ea8d1666674257b126ebf70ad8e0"
    $a3="ba4c691f14207bd2bcd1314176d97b795ecc2b61f261ff48b1b5245d5318c93e5711b211833d5081ff04a22fed2fbb6a82801cc7a83ebd384228808f264cb3f8"
    $a4="83f1f1da61a71fc57c3b4b2c5196ef5cfe7f1d506b19212a41d1b4c3b9136f4605ba8a8bc1cc24c59204e08413f69ecd34ae0cdc0e868b4c001158d8378282d7"
    $a5="efb01d0eceba7b3ccb985567824db6170bc00e9c29dfa4e6e5643943feb49ab639ac22472f68aa9fd1a1340e71f8ce886db11f4009c6a32323983862826b1cc9"
    $a6="83ed150dbcc9700521ccc2f7d67243c3d4000c8228281488dccd6c6753f48515dcb24714d5a294df27eeda834e9242e1ce4014fc38df3e0439b999fe3efa0765"
    $a7="b82c66a4f8a2b805bb315c40465f216e157164e716b6b0dea600132202bc1ac0521539533c097d1e708475909759665acddb36e4dcef2b17e28df3767caaae9c"
    $a8="863e5ef5105db8947791993ef181c07bdaa4d7b1f14d1cc43aed0a027c9723efac67ba308dfba305ecd00a8aa72a16271ae328050afef1b4a54c889177a20d53"
    $a9="1bcf12e5109130cac5e78f1f3296caaa10605924c0d77f5c429a3de4408036e469abacebc54e977481b4a7305cd99d99851de19fbc70e739a91571fab89352d0"
    $a10="2b3bdec64899ec96609cd4ff4b3a39df3fbd128f7f857d77f44e635075cb6fb9b68038355edf181a2b4d8a069cb53490f8e8baf0e64e06629adac18a4bce90a9"
    $a11="b6a2fc55acbded73f8527e4e22d1e494f6784e7760cd3ba014247232e0951b4687803ae811a6feee114be388a548c0e5fb1b110413f86d2c0157579db120eb33"
    $a12="e3ea65ecba52c25f19938b6f3cff7177195f8a199f1fa19a2eebae839b1c72d86346560a4c553e10f235581c2445a33e1031ee0f8ec530fde80309a09265f19c"
    $a13="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a14="83ed150dbcc9700521ccc2f7d67243c3d4000c8228281488dccd6c6753f48515dcb24714d5a294df27eeda834e9242e1ce4014fc38df3e0439b999fe3efa0765"
    $a15="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a16="536da9f7c7b811fba8ca119765aa125a60519a781ef2e91427838c3874856abe38a7554ede12509e235a8348ef5a11a8e8294a9e1ade440555e0f39c794d0ab5"
    $a17="a70087b5bd5949eb671a831c5bf393c65bf19e9fc780f9511744f4accc657bd5a8a894c5fb4385b483f40073998790b9ffb0c19ed15f5d1451e357d905a12412"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule base64_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="Y2hhbmdlbWU="
    $a2="YmFja3Vwb25seQ=="
    $a3="YmFja3Vwb25seTE="
    $a4="YmFja3VwcmVzdG9yZQ=="
    $a5="YmFja3VwcmVzdG9yZTE="
    $a6="ZHBu"
    $a7="Y2hhbmdlbWU="
    $a8="TUNVc2Vy"
    $a9="TUNVc2VyMQ=="
    $a10="cmVzdG9yZW9ubHk="
    $a11="cmVzdG9yZW9ubHkx"
    $a12="cm9vdA=="
    $a13="OFJ0dG9Ucml6"
    $a14="cm9vdA=="
    $a15="Y2hhbmdlbWU="
    $a16="dmlld3VzZXI="
    $a17="dmlld3VzZXIx"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

