/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_amx
{
    meta:
        id = "4rJDUwYQup3uaKpOCw4iNV"
        fingerprint = "d6ed5677d7bbb98fa34768371c5434493e7aa9e20814e5fb498225bd6ee2fe9d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c811a1c05af7c5485a6a5eaad8f9e481"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="a4141712f19e9dd5adf16919bb38a95c"
    $a4="714f83f9c3ac423fcee1b8f980937a9b"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="8846f7eaee8fb117ad06bdd830b7586c"
    $a7="bd02c0eaff2a8b1d107b7d280c0899e3"
    $a8="c811a1c05af7c5485a6a5eaad8f9e481"
    $a9="a25b2710ba9de114396adc7dfb0a7235"
    $a10="823893adfad2cda6e1a414f3ebdf58f7"
    $a11="823893adfad2cda6e1a414f3ebdf58f7"
    $a12="209c6174da490caeb422f3fa5a7ae634"
    $a13="209c6174da490caeb422f3fa5a7ae634"
    $a14="8c5660f518240f264fc71803105b01e6"
    $a15="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule mysql323_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47233db00d467fa2"
    $a1="43e9a4ab75570f5b"
    $a2="5d2e19393cc5ef67"
    $a3="7a7eeba37575fe5e"
    $a4="3ee702572177881b"
    $a5="67457e226a1a15bd"
    $a6="5d2e19393cc5ef67"
    $a7="05daf8884f15b95d"
    $a8="47233db00d467fa2"
    $a9="4077eb0b03ddce3b"
    $a10="57510426775c5b0f"
    $a11="57510426775c5b0f"
    $a12="43e9a4ab75570f5b"
    $a13="43e9a4ab75570f5b"
    $a14="70ee3358296fac94"
    $a15="58f7ee435f925abe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule mysql41_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7E682321B58D9234F716635FBDEFE8EFAAB0C6D0"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a3="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a4="*038A80AA404773E54BA74AB8BCEB438C5ADF6FAF"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a6="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a7="*C7238EAB7295E3A650AC7C07962F9D81F6CEA01C"
    $a8="*7E682321B58D9234F716635FBDEFE8EFAAB0C6D0"
    $a9="*D89A99106002D77C1D327FC41E005919505638B0"
    $a10="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a11="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a12="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a13="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a14="*E0909375B6EF6F1FF017C957172CE2E8D0E068A5"
    $a15="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule ldap_md5_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}nXMRukWfnkXtdGdVoy3NEQ=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a4="{MD5}6EJ5Wygik/1hvClMSe2xKw=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a6="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a7="{MD5}bFYFFNzBj5wxv8HV0pp6oA=="
    $a8="{MD5}nXMRukWfnkXtdGdVoy3NEQ=="
    $a9="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a10="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a11="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a12="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a13="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a14="{MD5}PpWzXfFNh5/v2gzNCJdERg=="
    $a15="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule ldap_sha1_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}PKz9nH+5y0y56X+VEH5eVr8CDF0="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a4="{SHA}KGube1CrieM5e031QAIbUx9Ff38="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a7="{SHA}9N6AT6QlUcsk3+81KfBFSG76ipw="
    $a8="{SHA}PKz9nH+5y0y56X+VEH5eVr8CDF0="
    $a9="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a10="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a11="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a12="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a13="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a14="{SHA}p8ngEWmPCqw9QrPyqgj/Q1aPopE="
    $a15="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule md5_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d7311ba459f9e45ed746755a32dcd11"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a4="e842795b282293fd61bc294c49edb12b"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="5f4dcc3b5aa765d61d8327deb882cf99"
    $a7="6c560514dcc18f9c31bfc1d5d29a7aa0"
    $a8="9d7311ba459f9e45ed746755a32dcd11"
    $a9="e3afed0047b08059d0fada10f400c1e5"
    $a10="084e0343a0486ff05530df6c705c8bb4"
    $a11="084e0343a0486ff05530df6c705c8bb4"
    $a12="21232f297a57a5a743894a0e4a801fc3"
    $a13="21232f297a57a5a743894a0e4a801fc3"
    $a14="3e95b35df14d879fefda0ccd08974446"
    $a15="7b7bc2512ee1fedcd76bdc68926d4f7b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha1_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3cacfd9c7fb9cb4cb9e97f95107e5e56bf020c5d"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a4="286b9b7b50ab89e3397b4df540021b531f457f7f"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a7="f4de804fa42551cb24dfef3529f045486efa8a9c"
    $a8="3cacfd9c7fb9cb4cb9e97f95107e5e56bf020c5d"
    $a9="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a10="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a11="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a12="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a13="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a14="a7c9e011698f0aac3d42b3f2aa08ff43568fa291"
    $a15="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha384_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2542deef989d1d2b2b4bbcffc71faaf79d5f9c39757bd144fada5cdd3458918baea790f593e5ecb6aaa0294bcaf6a426"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a3="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a4="52bbcd4dabab2a3dcd87e8c424ebb77754b1eee7a0fa79fe08e2be7a52c023a0429f2a452d3f53a6247d8eb4aa8919f8"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a6="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a7="ec0ba2af63c288d40f5d90ca75a24ff7b5c9c888f16d8c5b980fda0f34bda213122c1a0058580159e10f612ebe7c4508"
    $a8="2542deef989d1d2b2b4bbcffc71faaf79d5f9c39757bd144fada5cdd3458918baea790f593e5ecb6aaa0294bcaf6a426"
    $a9="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a10="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a11="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a12="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a13="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a14="9bff74531c3420862af71ee4c284c6054d3f0f9ccdbb8a6caddea9a06409c7af92818ed6b58e0df362478e80c7399011"
    $a15="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha224_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="565b28acbc67449d22921a34c23d26ad5a0fddcd86d999d0686f83ff"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a4="280c4134e6100040ca1456f1d5ba0a833db60029aca3971ae15cefe9"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a7="8180227f15373c9ed1a11e1fd9a884587e07d7038f8b9eab9c135f04"
    $a8="565b28acbc67449d22921a34c23d26ad5a0fddcd86d999d0686f83ff"
    $a9="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a10="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a11="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a12="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a13="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a14="c2333afcaab4396298702ee9448f334f110a1e4b5bac225854097aa4"
    $a15="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha512_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3dc542f6294a471ea2d27adf01cfdabbf03cad3eec7ebb76c5d53560a3e6284f6928efb80327f6c7126b9fb20437da9f51993f30596799acbe36653153a2ecd2"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a3="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a4="49bb59aa7dbfaaf5d6c824626db1c5609d888a0fbc62644e92dc4da7b2e0201fd4d17b3815ae0c67e51214744480577c580ed0d7150c3a73c7d0e6254c684012"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a6="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a7="cda8915c72fe814e306477d3c6e4f2f9d44902e99a89291eccb38513f0d1a999ee46d728aae28ed4c1ed5e9494fc48058451846271883c83997cf2127b1ab5e0"
    $a8="3dc542f6294a471ea2d27adf01cfdabbf03cad3eec7ebb76c5d53560a3e6284f6928efb80327f6c7126b9fb20437da9f51993f30596799acbe36653153a2ecd2"
    $a9="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a10="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a11="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a12="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a13="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a14="62072ed386110c3fb1f54779996111377ea28fc0f013707d5b4c763b6b7c0945954bc6fedb5445487882cb46d8750ea2417b5782ebb06e3b3026d268bba88abf"
    $a15="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha256_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8266498d969081c29737b8daeb5b51d60e56d008fff243a39d16c3032d42f6cf"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a3="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a4="06fca49e873e311ce7dac2de09b1f01193b94248daff30b9ca7a1ef7c6dfc471"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a6="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a7="561d783eee77e186a7e8a94c6af636008af834bf132076b6bfbda6262ebb13d3"
    $a8="8266498d969081c29737b8daeb5b51d60e56d008fff243a39d16c3032d42f6cf"
    $a9="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a10="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a11="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a12="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a13="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a14="fb2a60c740b3d6f54cf56474994270720193dbbb4d377d59def86bd8c2b2cf1b"
    $a15="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2b_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abb15f088144d7401ef624cc54eb8e9b2d863f4690d6f541f6427b9d403dc44ee4604ce358fa851328d6dae9f5b8abb68b7f510798748c02ad14f79da0dc1b10"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a3="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a4="d3fc130c40e3110d33346148ae796fcb776b9a4ef2eba3be8dc7fd765c94d13b3d2898a4dcc2d596a312d453e4e98c42e8b4f375880f7677bb17575511a0b333"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a6="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a7="62ae42d03554475050fdc8918bc5042c5683a58c31d744f1111ea425ac042f689eda819e26b61e7ed79f1c63761f8c1babda5551162ab4b1892f9e78293b1b48"
    $a8="abb15f088144d7401ef624cc54eb8e9b2d863f4690d6f541f6427b9d403dc44ee4604ce358fa851328d6dae9f5b8abb68b7f510798748c02ad14f79da0dc1b10"
    $a9="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a10="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a11="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a12="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a13="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a14="e617c41a6494d6ee27adcc9c20f2ec41755d47431cae2fb4a90ae8868e0acc9fcca5e8415bc770e2b0f42fdbe90f29f79783e24416781315f8ff6cdccb7599f1"
    $a15="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2s_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03fc8d59d6b5a9f62dd44815aa63d10304a26161d160c4267154720f042bff74"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a4="cf2848441b9f636d2a3e1282398458553aef39b4a0f13a40bfcb7002900208d3"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a6="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a7="09b4c35e02d477cff74ced2016b86ab8c42cee447e68223d47664fdc8156ae40"
    $a8="03fc8d59d6b5a9f62dd44815aa63d10304a26161d160c4267154720f042bff74"
    $a9="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a10="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a11="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a12="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a13="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a14="dff3661798d59ce527eeb19a465c261eaed25af96b4d0faea1abbf0349865ff6"
    $a15="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_224_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ec975035b74d3a52a2e13b59981bedfa0b0f39b2fe72401e087c23e"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a4="dd5b22874e0ec4cf5dd62ca0e3f2bbad52ef87202f1a55c56aca8dc4"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a7="1d0dcd2309aa0d40106415568791bac15615139338aa8781d2668d00"
    $a8="4ec975035b74d3a52a2e13b59981bedfa0b0f39b2fe72401e087c23e"
    $a9="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a10="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a11="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a12="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a13="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a14="a65c27ca3b0fd0b303dfd926fba3008533eb4b029581f4d5a8effb67"
    $a15="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_256_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6679d39bf756451847170594230a4121694f6b966706a4b036db54099b39216b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a4="de18c28289c33cb1bafdc6ff6b61919322daa5776bbd11f3e4beefadafde08e3"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a6="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a7="4c4b52f6fa95b4553ba3b0b228eda9f5eb5d301e31c7c9f5805156264059c25a"
    $a8="6679d39bf756451847170594230a4121694f6b966706a4b036db54099b39216b"
    $a9="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a10="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a11="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a12="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a13="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a14="4cecd33ddf53b9f89f6b9d27ecbb56447f6e064dd125104a7ae7c15d0f43835f"
    $a15="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_384_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f61219d80891a55b24ad6742980cb7c12d3a9ddb04ea972931028954962608398d21691ed5f4256ce3bf3fb689f68d9e"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a4="df153dec95b75fc87007b1705d3442617e3d3a306bbaea6b8df578d16bcbb3caccc1c802599dab783382e9ea99fc1758"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a6="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a7="6948939ccfb3cdb059a2f437a2c91b53bef81a99a7362516ea1a1b0d6744465cfad4eab29ac5c450075953458df7ae9f"
    $a8="f61219d80891a55b24ad6742980cb7c12d3a9ddb04ea972931028954962608398d21691ed5f4256ce3bf3fb689f68d9e"
    $a9="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a10="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a11="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a12="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a13="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a14="424ad0009aaa24347eb3505c431b2782c0e1e59463849208efd4649ddf904429b4c88923f51ad9bbd967e977e1f37855"
    $a15="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_512_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c036e0e93a7ee60275b35f04debb7f357e1213d7f4fa028014ca787335821154bf35e709f995923ac4a9bcd1c449385317ebd33261e7bd1f1ff13cec196908e4"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a4="4f2b32c88ff5fc42b802aa38b5440f87ded97d183113313af39524451995bd84851afd5bf3cc37729c7c4711601b721661f24dd17870faf366f23e93a17ddeba"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a6="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a7="0c313b0e43da1209e5154dfc434ea64036263643188406cddf3d57b91160366e58e68d32eb854af421aec5ed99fd7bf61f7633da71e9a6f53d149d3eb21ee4b3"
    $a8="c036e0e93a7ee60275b35f04debb7f357e1213d7f4fa028014ca787335821154bf35e709f995923ac4a9bcd1c449385317ebd33261e7bd1f1ff13cec196908e4"
    $a9="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a10="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a11="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a12="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a13="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a14="d20e30fe5f59a80167b822eacdf3bf1018b2d06d516d556c43f6556f47deeeb246c581873fb78900bc3f4e6608e94c9bf16a14abed5a4fa9a82bb4d05c1eaf33"
    $a15="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule base64_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="MTk4OA=="
    $a2="YWRtaW5pc3RyYXRvcg=="
    $a3="cGFzc3dvcmQ="
    $a4="cm9vdA=="
    $a5="bW96YXJ0"
    $a6="TmV0TGlueA=="
    $a7="cGFzc3dvcmQ="
    $a8="QWRtaW4="
    $a9="MTk4OA=="
    $a10="Z3Vlc3Q="
    $a11="Z3Vlc3Q="
    $a12="YWRtaW4="
    $a13="YWRtaW4="
    $a14="QWRtaW5pc3RyYXRvcg=="
    $a15="dmlzaW9uMg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

