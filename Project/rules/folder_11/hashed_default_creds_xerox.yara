/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_xerox
{
    meta:
        id = "5BuowgjRbo5ufXFur9EMo2"
        fingerprint = "47620bbe90640058335279b00bebb35bf8e0ffb6cd31c6fd0e196fbb18455b47"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fefe07fb9c1ab627d9545a8f911b87da"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="76178e956fc1907df6d1eb623675f1d5"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="e0b6de1a35921a09e3b75fc198d5b5e8"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="fefe07fb9c1ab627d9545a8f911b87da"
    $a9="e9fceff7358f2d3bbac2b31841e874f2"
    $a10="e84d037613721532e6b6d84d215854b6"
    $a11="209c6174da490caeb422f3fa5a7ae634"
    $a12="443af5b862b902ba97b6def62d1a5830"
    $a13="d144986c6122b1b1654ba39932465528"
    $a14="80da48545ac26a0770181bc8ab157847"
    $a15="2c9c743c52af1da6715934f65100e7d6"
    $a16="af120e1553d7b5b5bc64d65df627cfe8"
    $a17="99ee32461192994ff6e77a49b6dc36f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql323_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76274ae801fb95ce"
    $a1="43e9a4ab75570f5b"
    $a2="465ff47d58c823ca"
    $a3="43e9a4ab75570f5b"
    $a4="43e9a4ab75570f5b"
    $a5="43e9a4ab75570f5b"
    $a6="0a4c13b504926a4d"
    $a7="43e9a4ab75570f5b"
    $a8="76274ae801fb95ce"
    $a9="623df14f1fd6c1e4"
    $a10="45271aba0b765d95"
    $a11="43e9a4ab75570f5b"
    $a12="6eddce4c69159e8f"
    $a13="58f7ee435f925abe"
    $a14="7a28321826fa4591"
    $a15="70cbdcb81fe7cfd1"
    $a16="58444a6f34d81fc3"
    $a17="027d49ca469919b3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql41_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*461283C5A059A86BD70A2608DC3667C66488D217"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*45F2C3B4476FFF9AE3E6335C54339C17B96DB83B"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*D142A988197D6E8B1D3D0945283450811637B73F"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*461283C5A059A86BD70A2608DC3667C66488D217"
    $a9="*58D24DFDC5B5D55D6F6A25496AB51B74AA0FF7C9"
    $a10="*89C6B530AA78695E257E55D63C00A6EC9AD3E977"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a12="*3A0DBA2C24FBC9D85443D97FF94330F9849976ED"
    $a13="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a14="*C6931826B245492D0A1A9B85962056929D58D7AB"
    $a15="*16FA3DCB4D4C38166EA11FAB7E857CABEA529D4E"
    $a16="*4CC0EC3FE70B03B950EBB31C5F1845E05D6A2D5B"
    $a17="*412AEDD6E7286B8D539751787A0FA1603091C3BC"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_md5_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}izLjNuljaBOS+w/+8HKCmg=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}PSFyQYzjBcfRbUsFWXxqWQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}k0tTWACxy6j5al1y9y8WEQ=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}izLjNuljaBOS+w/+8HKCmg=="
    $a9="{MD5}sLrunSedNPod/XGq25CMPw=="
    $a10="{MD5}tZxnvxlqR1gZHkL3ZnDOug=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a12="{MD5}X1J765ut8eT7hEtAIfbKHg=="
    $a13="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a14="{MD5}jSqVnmsVTskhWIK4LyjPyw=="
    $a15="{MD5}VK9gQiqtssPeHYfs3jBwDg=="
    $a16="{MD5}3Kqf1PI6rwwp9UC+zzW0bw=="
    $a17="{MD5}AwPKDS7QWa2iAuv7KWvQ/Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_sha1_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}PyJ+pWWiGVYeJTvfrdu/uk987T0="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}GpuVCLYAO2jd/gOpyMvEvUOIM5s="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}/qf2V/VqKkSNp9S1Ne5eJ5yvPZo="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}PyJ+pWWiGVYeJTvfrdu/uk987T0="
    $a9="{SHA}eyGEismvNb4N2y1rn8OFGTTbhCA="
    $a10="{SHA}ARyUXzDOLLr8RS85hA8CVpMznEI="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a12="{SHA}IJRqXpBwZDb8b9I6jkwq5WJAFyU="
    $a13="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a14="{SHA}YGGGNiP4Btfbesj6j543C7vpwJU="
    $a15="{SHA}Ifv40ulXd7npPd9Gr8KUU/gjNaw="
    $a16="{SHA}L8fxRSN0tuNB1ncX8DKrvg2g9KY="
    $a17="{SHA}4sYk5k1H/CgYRd/CDCxV8VLIwUA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule md5_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b32e336e963681392fb0ffef072829a"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="3d2172418ce305c7d16d4b05597c6a59"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="21232f297a57a5a743894a0e4a801fc3"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="934b535800b1cba8f96a5d72f72f1611"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="8b32e336e963681392fb0ffef072829a"
    $a9="b0baee9d279d34fa1dfd71aadb908c3f"
    $a10="b59c67bf196a4758191e42f76670ceba"
    $a11="21232f297a57a5a743894a0e4a801fc3"
    $a12="5f527beb9badf1e4fb844b4021f6ca1e"
    $a13="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a14="8d2a959e6b154ec9215882b82f28cfcb"
    $a15="54af60422aadb2c3de1d87ecde30700e"
    $a16="dcaa9fd4f23aaf0c29f540becf35b46f"
    $a17="0303ca0d2ed059ada202ebfb296bd0fd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha1_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f227ea565a219561e253bdfaddbbfba4f7ced3d"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="1a9b9508b6003b68ddfe03a9c8cbc4bd4388339b"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="fea7f657f56a2a448da7d4b535ee5e279caf3d9a"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="3f227ea565a219561e253bdfaddbbfba4f7ced3d"
    $a9="7b21848ac9af35be0ddb2d6b9fc3851934db8420"
    $a10="011c945f30ce2cbafc452f39840f025693339c42"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a12="20946a5e90706436fc6fd23a8e4c2ae562401725"
    $a13="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a14="6061863623f806d7db7ac8fa8f9e370bbbe9c095"
    $a15="21fbf8d2e95777b9e93ddf46afc29453f82335ac"
    $a16="2fc7f1452374b6e341d67717f032abbe0da0f4a6"
    $a17="e2c624e64d47fc281845dfc20c2c55f152c8c140"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha384_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f59f3f003168cf3be04c773948548df167d122d9b467e255afbae5168f20788ffb7910c8d2800bdd976f0f50cbf523b4"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="7ffd57cbcd46bc1359d376fd84a4301e2937322afdfd716933db49a5aae2aa59511dc8d3143e2cf55d00ef0135b1a7cb"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="340cf197b38cefb4d11c6cb751420d74c8b024c3cdd01d40834d5e6111abfebfbf7ceb932ce625a7d5598fe3ab4c366f"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="f59f3f003168cf3be04c773948548df167d122d9b467e255afbae5168f20788ffb7910c8d2800bdd976f0f50cbf523b4"
    $a9="378f4991427116129ad28742b83054e3041950d08287036c8651d997ce79a143c361e3ace84e622ad22625f6145cf114"
    $a10="7318735a5559d423f7706bbb8b6f10a610cb1b74b308a0e17849ace4bb3a34db34b3b126aa3a8d73b117f98be0e4af67"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a12="d333628ea675f551d8a68df16749c52c746948c8a1ab61b0031400d24968290bed7787df5eabcfc07d630a4a967a9480"
    $a13="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a14="dd6be5a723c7fc7089ca2d379497b850f5f77c1800a590723e79399615f0f2898b745067325bfc45fa802d3ad6653edb"
    $a15="87726115cd03a1716d3bee518edbdee41a7a2d7fa490cef94a0a930ca2453a9befec57895fc5adf594562f5f1a293e4e"
    $a16="f18fdbedc2b8086d72723695340cabe698ca1897494f4bce94d1b53b2de2a802f90e09c0a7ceb762f4472c7f5a7348d6"
    $a17="592877d731e1a78fdc1be0fe20e47b95b1da70f8423186a693368b221d2f408fd3987e82ebc3ba77aa51dd512084ccbd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha224_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f0aa5eeec6b9c07a2698c62ffa65358a0864533cf67669224173277"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="2cfcbdc839cf550004a0115a366cd5260becb7269f038e2a1911f44d"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="cce54f1ae2a54b7c3ac10d67ce99e2784b17c62a97273b7ac5258922"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="5f0aa5eeec6b9c07a2698c62ffa65358a0864533cf67669224173277"
    $a9="dca08c944a652fbf0131bf7b15ecd38fde5539d5a6226171379a1816"
    $a10="9cb7b5b974b6df070cb60bbeb134ea461541b92187d54372f4b144de"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a12="cb46f8b949bb5f7c4e9344bff20c643379499671bc47493a91d3bb49"
    $a13="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a14="8a645bd4d213e232e9f9eca4dee9f004d1da2ec0eb02e6b8430f7ab6"
    $a15="b6efc39b10df3df477304e184eee31c26b5cc32c6c82130cc5592d81"
    $a16="efe80e8af9dcf6f64b9ef717251f53057a523a80c757b19c9f3edf18"
    $a17="972d86c7854a40824773b4bd4b148d518672b4130370b1e2d41f8b7a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha512_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ee6198ce703bbe1f4d1b590aa4d04595d20dbbcdd8716352ff01435a0c31ac4f10d2d084b3447a7977de1643ea94ba619329ba9938c9364e187c71901f64fa9"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="4cf5a5be41f417cb2087f1f17e44734ae9b1677dc6b0ed3b80de422cc8e5607980ed08334540c15966485db039927bade22d3dedd5fd3b3f7d9743c20310882c"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="a8cebf1698dc14282c507b1e1cfb7f2c9d5216aa7bd0854b50561e02c2b99d9a38945ec0f81e55f9699062b1eac6d0083411c839ba2b27c6a15b494463bc5c73"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="8ee6198ce703bbe1f4d1b590aa4d04595d20dbbcdd8716352ff01435a0c31ac4f10d2d084b3447a7977de1643ea94ba619329ba9938c9364e187c71901f64fa9"
    $a9="22e7e9d85b7fe6004f7b9f3aa592ea9ec9ce098682e8192fa83785f1784c768d1d1ac3b8afcae88666f66aec24739ac133e9d4adc7506f1a5f1f6078cb27c674"
    $a10="33275a8aa48ea918bd53a9181aa975f15ab0d0645398f5918a006d08675c1cb27d5c645dbd084eee56e675e25ba4019f2ecea37ca9e2995b49fcb12c096a032e"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a12="1eddd7d92d849b0079fb72f1d6bf1741b27de66f86323a8bfe89d819b612dbc650d16057aabcabaadc2841381c3e01562ce0e41676b0ce0fc703826cfa080cf5"
    $a13="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a14="29cd389bf5f205db2d07fda3ca1d59c2b80818cec60ec33a057e33eaa2f93c7f0a2bf1ee097a16813c25c511aae13e7919187c72d48b27195abd506bae8e8d3d"
    $a15="9e3ac18b9783c8085820ab23e368c503ae89bdce981dd601b6415ebd752e8244c065041576085cab6726ed50182f2e1dfa1a93e570dc91148a96315fcbaf477a"
    $a16="66d941a90d78d937c221b6ce8c5d66c1d196d7edc487dede0fc260bb43acd32df1306792683a7c294fa47e3df74a9ca5fad1a20f4bc07e743f2a35bb8590a1e8"
    $a17="982c9dbf38b5f40dbc699765beabd86bd156b7aeb6059173174c983b378985777a41a969d064a4715ecc016923f3eec5fbed71f1034d56e22c115b2179402ddc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha256_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="efc5b01efd64fe0c823867261b71664d98a0e07e298d10298b41c6cb75f37e5e"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="cc399d73903f06ee694032ab0538f05634ff7e1ce5e8e50ac330a871484f34cf"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="edee29f882543b956620b26d0ee0e7e950399b1c4222f5de05e06425b4c995e9"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="efc5b01efd64fe0c823867261b71664d98a0e07e298d10298b41c6cb75f37e5e"
    $a9="d17f25ecfbcc7857f7bebea469308be0b2580943e96d13a3ad98a13675c4bfc2"
    $a10="0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a12="133006b874688f82232b7520a582ca1cae8c6587df2a959ed0bc738078a71d77"
    $a13="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a14="bc86e3cd94a18e6232a48e2e6ae7ebdb30232e2859935f3c6acfa5fb90c31636"
    $a15="00197d6aaa1b2e6203523e21311fb4825149f9cb404f54605eb974e8a24b95e8"
    $a16="cdb2e0d0f873ce5326e87cf7dec48de8da3043cfc950a7eba05a059150e873f5"
    $a17="644c189710ca0d5f3bfc755fabfbc59899aaa5dcb8331c384d24d35fdc0bdde1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2b_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db6854fea5fac85d30ef587ebb5102a07368697f69831d8bdaabd9552f24b482cf0121a0c0546e408be98929c9af5e95ec44e549bd72c6e4efac78e54a83f01e"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="368124278d8ad5057ce1abafac2b9b1f840600db8f7714cdd636017624dec28d3af1dea646c382b638b40c09dc695e9222f864e6b249f7afa5ee51ebdd5e533e"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="4c011c69b6d5b01e60440b15dee2b967cff12ef3db200aff3852c924a2f45b463d45457992168807ee010c1eaba0beb18dc7e0c561a6f5d4535fe60e02207697"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a8="db6854fea5fac85d30ef587ebb5102a07368697f69831d8bdaabd9552f24b482cf0121a0c0546e408be98929c9af5e95ec44e549bd72c6e4efac78e54a83f01e"
    $a9="64f9d310670ad23505d3a003343464c2444e840728acdc9b4516e5b09458abd29d65dce90359935ceda3103e0afc60be2069e8a60ecb077efb7771d28ea48c57"
    $a10="fdb4a51521836024c96c66eb49b1f7156464818d27bf8f5f4a4feb6a6c31a5d7d6bce4aa1542047f126cd13eac4cbee1750d2643ebbd461db9c7f10ce19677c4"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a12="ba5d3def34972ce89029192d6e880b795feddfc2e1a7cb659840bfc91b0f25eddfeab32f1fde485a3ab32a2cd83fcefb963005afa615b0fd6769ee18d774dd03"
    $a13="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a14="1bec4b5d5e44e873282bc53e7e51fa596ebc32b94284770760c1390ed5e7475b61c3a1e787429d688f9d4bfb1b90b69c645a8a7d450b7ad09760e12c8772dc0a"
    $a15="08dead1a59feda40a6194cf223398a5b73457b53c6a098cbbde776ba283991a9cde23ba347872cd20ea23705e27b7465515bb13286ea9c2f35b472190e226afd"
    $a16="40f8258346e26011a206ef482e91a973e0b71b702ebd5df8a458a45d5cce8322e124e031180d2769dd05c5745c6d9a6de01a3ebf7cf36578b7be8b2616f9867f"
    $a17="b0730326fbca54e3c1304bc11ed89fc9142dda491f96dd81495e867ce77c666b820216f087dfcd0c9b3e5f335c450d17c1dab00c16e0b2bd5ba519d378fb3e7d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2s_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3534f2aa348f386857bfad959514c74e1598d06c82ce2ce610f09033777cedd4"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="255de72527d9901c4324c7af5a920740097360f284a3de8cd907e0bd91c7bd59"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="df5b62c942121f6226e89bc08949226027803958d6e8f39496d1cfb971493483"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="3534f2aa348f386857bfad959514c74e1598d06c82ce2ce610f09033777cedd4"
    $a9="b9b53865e6e605fe3244198542594c759db8a2c7f77f8ec6ef1400664dfc6c84"
    $a10="b29d405f772295c6b2be416d3cf56c95b67bf07ec5b42d0d597dc90b98806930"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a12="f7d6d802b1b0d6bda7d6a87d0ce4e0d1b9e9e7800d064c5f832714d578442a95"
    $a13="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a14="c07781b352d6b22914b99df930dd6129be5095a9b04763e01c119cf15d4e3cea"
    $a15="61395674c65294b533cc20e5ee0614e0d98747d496cef7f269417aecbb64d16b"
    $a16="574c6e7b47a83822ac14a06a4582ce71287771c20879c08066b4f6ce416c7728"
    $a17="e7b7368b8bad45b6f71a3b6eed4e61fdf671a9311b9fff3400913925112cb36b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_224_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="92126b5f10eb58e6c88b6b5c8b47da1967843694bf61417ff8a98a9b"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="bf5b5c7f32e8b4ae23803af71b0f1c6eab4508378e00ea966d652979"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="8d5e24056d144fb0c63f871536f662e41be1e107c88ef7bb5a75aea4"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="92126b5f10eb58e6c88b6b5c8b47da1967843694bf61417ff8a98a9b"
    $a9="a499dc297b89876e6a2645927c301fc0349118363aa0e7e7db152e5a"
    $a10="11ff8a7c0d7a2ef4c85f82ab8bccf0dc695c34d4e8e151e0751e9d58"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a12="f18751d561f0172d63a18c94e090333f9d4016f359a1df43d1881f9a"
    $a13="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a14="a855549fc101de3f16de627e8cb4519a632ebbbb8280d1c16b5958c6"
    $a15="d486b6a2b4dc2665ea144fd7c2afd44fe9dac04661d70f9d0f821e3a"
    $a16="1884f849613e913f0dd164ac80b45c7802673ae3452bc43d8724ee45"
    $a17="cfcd4c76eed0f00898a5013d1b6d340de6c24b66e5b1fd4de7e4aecf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_256_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8b7bf81434969692a76642194c4f25fbd31b6b1e7ba3085ac508445171ce0be"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="37b0edec323a7fc924dec259de1b1c59164e2ede27fd51e830dbd6bde7d00839"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="5db035077ffa9ed87f7a9d8f5317a634728faba1906e8f008d76700ef51fcc30"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="d8b7bf81434969692a76642194c4f25fbd31b6b1e7ba3085ac508445171ce0be"
    $a9="7814d1fa7209582328327cf2a11fbcbad2b14991f10bb9dc6ad4ec0dc6d950ed"
    $a10="b3464291a58f65050d16b715a13e1c4d422785e733f7a9c44e381dfe620b5855"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a12="e7f39b4119337380e823f0acfd559e77d0a770e93d62c3e9b07aded5a642088c"
    $a13="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a14="9bfe14c9798fc1c606d8d8d00564bcff734762c8b93dab25a60ce5b965f802d0"
    $a15="b4a26922e0b4a5fbbb62fbf14af3cc5fd2d44fe0462ca15b1439914ab2f920cc"
    $a16="14f360e79af9e6a55b25347d8e5dc1fac1ed4255d83efe35b52fcf404e89c84e"
    $a17="51fe81804398b0a51cde487ee95b758a6d2e77c151f4d6d0a3752fa2e2c62e31"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_384_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aec075258ad7a6fe83b0453b94dd216ec951ae6545ea701dc1c76c9a233d6aadeabd4add0e992f86d0025acf30880379"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="6bdc1b784f4a65070782b0168fe535716083235d6de618c10a913145b5d78669e7565a1cdaba90a417d4641d95dc02c0"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="8857455b879a24793921ec64736a5eb978e9ce9e6a47c73fe7a8e15420370a713e20b3d1e8e115f0284302c3c46263f3"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="aec075258ad7a6fe83b0453b94dd216ec951ae6545ea701dc1c76c9a233d6aadeabd4add0e992f86d0025acf30880379"
    $a9="644dd0adc6062a0cec429a7b3b8a4f79c2575cc65ed9ffc7511bf73b372e8226e3ef3a0f659f9c1e166c0ccbe66b4f56"
    $a10="2e4348136442e08ecf7a1656b5ad070d095716ad847b6f739e697212992bce735f774f735608746a3cecfb20f616a9ef"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a12="e1e616c25b1593ceb17e42259fc284ce80bf053500c82ebea7f864320ca06a480afe552f5d3aa3c55192ebc9d156a8f6"
    $a13="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a14="ad6dc23b401f000f5bbbf52a042f23570d0159934484c027a92d896851d391fef350e45ae50f72d6386647c670c32136"
    $a15="7e40afdc7980de0d3472799faf22177c6f61744bb1bf908375581b3c87e07733e6a87ea3683675d430832b1ed0955882"
    $a16="319f206d6ebcd3da5c811884af78811c11e487c3a89610d99c4948fdb166ecf6d20c5b624184fd41d6c87573ce88d2e6"
    $a17="e07ecbfcdee3199bb8752a4db479ff37e8bd51f0a670a50cb28681b0829c3f5eb7cead25f48da584ac0accbaa2e6ed70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_512_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="326a0e6a2c968de52f44ef954b4da68b3f136b21f147e00c72ec21b4ee5a4829bb91509e24fbc9869b6265c45cc90c37bf3f50084994c485c8ed5e7afc70d289"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="cdef0c740bfc6224a650219c6266edcc491f6535c9444f21591423b95cc7d63344b2cf83e2c81f0143141f0659b3aa31996319b932fdcd6c4da531684bd58de9"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="2a967d7cf49ca20a07cc414ee5759ff02043e6ef92ae33a5174cd6f496ffc83d4a51e19109ce01a801d7b264947a0951a5f4c845a3aa8f3193dc540bda21caaa"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="326a0e6a2c968de52f44ef954b4da68b3f136b21f147e00c72ec21b4ee5a4829bb91509e24fbc9869b6265c45cc90c37bf3f50084994c485c8ed5e7afc70d289"
    $a9="7d6e49927bdd21d4bd76b0fa6d3afd1d5edc89d464e0e867e32b8948fc0a83a4dcef3936a325a227c77bcb5ab97e76f3f4006b97c0f8ccdeb89a24f05b505aa9"
    $a10="21f9ff061b755faaa06d71434f31330582901810871c228a4d67f9e52f2adf82ea6b445bb4c98d49da68fb140717911e4fc5e1c49ec0becf0aadec0f7517f8bc"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a12="31ff452e79f34fd0da4d15ae598b46c22e9a1cb82eb9f583fd34b0f055a5b6c560f6b75ffd25d5a9011f2e259196d93c68907493721b2649c3b4205aa07407dc"
    $a13="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a14="b91bb075d94f28437123f17ccb8904f1108f1e1236286cd3d0452fbacca43d06ef593990cc11127f98157e13d7937e71b7a7414f7510078d85fce664a3d115f4"
    $a15="4c6ba600c61e4f53a86d168277e328d2825e870a5211104f221af4a639a68e940f952627bc6c64742cb155ec16bbb5b0c73c3b26d1c764877059c019eab5dabf"
    $a16="35777b1e4eb9b8e68d1ad46b4ddf0ffdf6abd5234a963d580827586dd72713b99e274b301e2de7c3a20fc819bb2c09c82c304d7d0baf5c869df81668165d5298"
    $a17="00efa2d4f6e53ad2b0e0232bac91e7175b8d58298eac815b382ce2685da170effab4b9b3d924157ca36c2be3debe0368c8ad559689ee7e6b4024a38f4cdb9962"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule base64_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="eC1hZG1pbg=="
    $a2="YWRtaW4="
    $a3="MjIyMjI="
    $a4="YWRtaW4="
    $a5="YWRtaW4="
    $a6="YWRtaW4="
    $a7="MjIyMg=="
    $a8="MTExMTE="
    $a9="eC1hZG1pbg=="
    $a10="YWRtaW4="
    $a11="MTExMQ=="
    $a12="QWRtaW5pc3RyYXRvcg=="
    $a13="RmllcnkuMQ=="
    $a14="TlNB"
    $a15="bnNh"
    $a16="c2F2ZWxvZ3M="
    $a17="Y3Jhc2g="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

