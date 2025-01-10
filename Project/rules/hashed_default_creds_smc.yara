/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_smc
{
    meta:
        id = "1wMqjW22HhiuWS4d3ezECu"
        fingerprint = "190196ac9133e17651a65432b6f315110861f9b7534baaa04858e8f7e1f067b8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6febcbb8580e37608c064d30d172c34"
    $a1="15d7564478f326d273fe61e638502a2b"
    $a2="ddf8302fceeb363186d9aea153b941b0"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="c6febcbb8580e37608c064d30d172c34"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="1365f3c68d81a3a228b27e4e4031c84b"
    $a7="6c5ec0cf3aa0cfb9b96139eac847b13f"
    $a8="209c6174da490caeb422f3fa5a7ae634"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="c6febcbb8580e37608c064d30d172c34"
    $a11="d144986c6122b1b1654ba39932465528"
    $a12="bd110912eb662082d5ec523012665631"
    $a13="d06f57db3352437dc24b89e528a5c3dc"
    $a14="ac52736ba2b458e075e0228ec1bc855f"
    $a15="a25b2710ba9de114396adc7dfb0a7235"
    $a16="2cc4709c395e1fa3c40b2c03c79ea9bd"
    $a17="7d891ab402caf2e89ccdd33ed54333ac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql323_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ec171f20aef068e"
    $a1="7891ef712633df41"
    $a2="0208faaf411675cf"
    $a3="43e9a4ab75570f5b"
    $a4="1ec171f20aef068e"
    $a5="43e9a4ab75570f5b"
    $a6="6c986ac36a448ba5"
    $a7="31563c0a19953d16"
    $a8="43e9a4ab75570f5b"
    $a9="43e9a4ab75570f5b"
    $a10="1ec171f20aef068e"
    $a11="58f7ee435f925abe"
    $a12="297432c65fa13086"
    $a13="7a62673526be536d"
    $a14="33ec930f2369c4cf"
    $a15="4077eb0b03ddce3b"
    $a16="452c15e815ade654"
    $a17="0a1838273cbc9961"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql41_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8EA099E806B3D43C39F873894644ED6F8C1FF595"
    $a1="*E27BC0101464728C8D522DEF58E2C8B15516618C"
    $a2="*A8E896212A8AD24B232C65A024D85FC915920D9E"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*8EA099E806B3D43C39F873894644ED6F8C1FF595"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*B5BCA08DEF0B4B50A063686469C75E1E98EA172E"
    $a7="*8CC79B5FDA8D438648AE41FD2B305F0967FF0F44"
    $a8="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a10="*8EA099E806B3D43C39F873894644ED6F8C1FF595"
    $a11="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a12="*935316BD547A545CF2403470F23391E41D912294"
    $a13="*0D10A5934E14CD172316029F1AFC699671462B99"
    $a14="*740825EA241A579531FE4C808CF8B55A8B10F4BA"
    $a15="*D89A99106002D77C1D327FC41E005919505638B0"
    $a16="*92E895AEAEFF11F14DC80282DBEC981AEA330E16"
    $a17="*69156C3775BC63A03BDF56AD0B48E2BE5DF601DD"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_md5_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}s+r3FWHWuSVG6M8popaHPw=="
    $a1="{MD5}UsaqyiimtiGrri2yDoh91w=="
    $a2="{MD5}oRF9DqWQIROqzO2TF59bBA=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}s+r3FWHWuSVG6M8popaHPw=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}lH8BMxqw2xsIak/JHnvakw=="
    $a7="{MD5}JXwtGgQjpqfBCGMqj5Y5Mg=="
    $a8="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a9="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a10="{MD5}s+r3FWHWuSVG6M8popaHPw=="
    $a11="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a12="{MD5}P3fKlvtx6UQ7pANPrID8JQ=="
    $a13="{MD5}n9l32tiw4iMbeiES+qiJ3w=="
    $a14="{MD5}iyYwgdgXDWfvD55WdQjO9Q=="
    $a15="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a16="{MD5}mzQ6tjWGrAI7fY0qdUmOBg=="
    $a17="{MD5}wh+Wm18D0z1D4E+PE252gg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_sha1_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}zyHYWEMAJjrVnYFTIXwv4+h/8v0="
    $a1="{SHA}uGydMy+A1orjwnTJhCGfu5mate8="
    $a2="{SHA}T/3U206xvVhlqNO3qc2/tYdGXfc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}zyHYWEMAJjrVnYFTIXwv4+h/8v0="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}7ONid1ADqizEUu0A08H6Xg9793o="
    $a7="{SHA}jxmPrYXBreLB+ldRWHJmcteJ7uo="
    $a8="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}zyHYWEMAJjrVnYFTIXwv4+h/8v0="
    $a11="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a12="{SHA}vXHHG06gJXHJ/gWLfpsqouoszKk="
    $a13="{SHA}Aofm9puNYIoeTkWCUZ9BVNGgRAg="
    $a14="{SHA}9Y8cm7vO0kGYGKCiFR40CtzAzIs="
    $a15="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a16="{SHA}X1Ag1n0LYz5Z+BwKk1P8Z/MosN4="
    $a17="{SHA}dQXWSlTgYbes1UzNWLSdxDUAtjU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule md5_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3eaf71561d6b92546e8cf29a296873f"
    $a1="52c6aaca28a6b621abae2db20e887dd7"
    $a2="a1117d0ea5902113aacced93179f5b04"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="b3eaf71561d6b92546e8cf29a296873f"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="947f01331ab0db1b086a4fc91e7bda93"
    $a7="257c2d1a0423a6a7c108632a8f963932"
    $a8="21232f297a57a5a743894a0e4a801fc3"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="b3eaf71561d6b92546e8cf29a296873f"
    $a11="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a12="3f77ca96fb71e9443ba4034fac80fc25"
    $a13="9fd977dad8b0e2231b7a2112faa889df"
    $a14="8b263081d8170d67ef0f9e567508cef5"
    $a15="e3afed0047b08059d0fada10f400c1e5"
    $a16="9b343ab63586ac023b7d8d2a75498e06"
    $a17="c21f969b5f03d33d43e04f8f136e7682"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha1_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
    $a1="b86c9d332f80d68ae3c274c984219fbb999ab5ef"
    $a2="4ffdd4db4eb1bd5865a8d3b7a9cdbfb587465df7"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="ece362775003aa2cc452ed00d3c1fa5e0f7bf77a"
    $a7="8f198fad85c1ade2c1fa575158726672d789eeea"
    $a8="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
    $a11="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a12="bd71c71b4ea02571c9fe058b7e9b2aa2ea2ccca9"
    $a13="0287e6f69b8d608a1e4e4582519f4154d1a04408"
    $a14="f58f1c9bbbced2419818a0a2151e340adcc0cc8b"
    $a15="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a16="5f5020d67d0b633e59f81c0a9353fc67f328b0de"
    $a17="7505d64a54e061b7acd54ccd58b49dc43500b635"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha384_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
    $a1="6e802f47b8d123f24b93f8d5cfcc091b76ae2c87411a75e6be23a2394f06944658bb9b300086ecdeb63d34db974846ce"
    $a2="4bd8d4ae7789627ae3cee9192ea7e13b26db483040f47d1c8fe094d66cb09b6807fe72cc700507afaea10f5fcd60ffdb"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="f87c1ebc04f901041f18dfb7d24bebc6d45e1cbbb2d9f005605e47afbc6d5d56356e3ee5f7762c5373219eb2ffd6554f"
    $a7="e576cef8e16baa7563bcc99495e677faff3ce7afe1104066285cb16331e90f5ab0df126cb04d4b262f8df1ffd8af63d8"
    $a8="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a10="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
    $a11="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a12="2340e5007830436d3e20f2b682ce17a72e6a4fa429e1c7004bd9ae9ebea5c43cf9ebd01f10397b6baebdd8b3410ae926"
    $a13="4b616013976cdc35c752303ac396019ea3e5b50a3c3cf8ead6efdff067e0c4f19fcec3fb37ed5298a51d644c968feac2"
    $a14="ad2649a34d1b07919a1c5886c89aa74809274c3c54cc44b0a18cdbf433e04172f953bd243da3bb6965681404f40b59b5"
    $a15="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a16="3e333bdcd4a8e043ca4d1266960829915639577294c9cec1743e0430234a8a779516642c12dc94adc4051e5f594dac6a"
    $a17="42f7113044c011e770740189f408d58fa50b795bd67a83a5dffe7b31a6463841de17df777ecbd9666ebb69e3a5be7d32"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha224_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
    $a1="5fde807d89bc98fa829ab5c847c25c93c96faba025cd2e5a7f0d1ff5"
    $a2="d02105ca0dbbd0cc327b9e08133f58c8a8f0cde6f53ed0ed71d2e6de"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="cd67b76f75f4577b8c0f9541bb4658e24a34ee90a9fbe4f3a46bed80"
    $a7="a244a67f51a1100c52553ea5397c3590343c27b53d2f35bee284e47d"
    $a8="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
    $a11="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a12="464a4808d15d53e3a9ef3f3351a2dc9b59bf2ef819823f35c2948322"
    $a13="6e9642705c45d7b717574d3fa6ac9e0db4f5fb59253b3485d7881872"
    $a14="82d9c3ee2ca2513164aa2e8fa3c0d25e07f2d7393e816b4bedaf9415"
    $a15="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a16="d7fa4220dbdba075c082e72b446d4c022ecef55474fdf085de543015"
    $a17="f0e8b3c2dda2512b55e4dc5d4859b1877e98109c7c4e755ccd2a5763"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha512_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7da90cc415307e664a142d87a2de14c02a08fa0c8a2b90b4135cfa026715f89095bf711e65fb4485725f0d0d72b58a4d0108ca2e9ae2f38ab5efbd57728f889"
    $a1="c50b2a559d87967ed9b83ffac046e58e4079b17a18e60e74324760b9452d7bb0ec91f2de20131aee28a31234a760714493717abeb494e7818dd5665a156ca0aa"
    $a2="234916c8a5cd620971052069ba73927b79c45485bd31054a1b32209aa905a783e45d692f779c8526c32b0cf84b5bc69a2ceae2b2520598714c37ab0ab9484a84"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="a7da90cc415307e664a142d87a2de14c02a08fa0c8a2b90b4135cfa026715f89095bf711e65fb4485725f0d0d72b58a4d0108ca2e9ae2f38ab5efbd57728f889"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="dc3283f0dcc070a4434448ab2bf8caaa3b546bb32ea44a1173c7f7fb896d21c087786050eef69ad3e7541b546ee7a8f61e163a5749de0089502a401e51f19b9e"
    $a7="4054fbcf8983db0ee83431df3913ce238d05177e8650a3a39c78394aedee99bd1efc32a8f96648bf00267c805bd82d5f6b870ee2a2eadb5314c5dcf7eb1f9e35"
    $a8="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a10="a7da90cc415307e664a142d87a2de14c02a08fa0c8a2b90b4135cfa026715f89095bf711e65fb4485725f0d0d72b58a4d0108ca2e9ae2f38ab5efbd57728f889"
    $a11="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a12="523fac79ac1dca3f3aceb5524e57a61c4af19c59a448f16a7ec1ce3d20f23b3893e3703f202cc83a2bb59269e786cd09faa8950986b24bf4a8db50c559bf28ae"
    $a13="d06c22252cd3bfd3f487da8f33ff50c7ed5e537e71bb34006b7aefaa7d641ad8f52c7530887c3ac7303c54cad419398df124e02c29c56d60f4c71963ab295a51"
    $a14="10ae165956e0cf9f3159c052bd39f781f39a123c150ccd82bb0dad7a9e038b42a9ba432e62fcbdf9caa1e3e73a149a91ecbfb965f7dab3b45c90fca653f4f4eb"
    $a15="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a16="7486d08905d6a2342bcc9535add0a70e783cd9a566d492bc538f2f444ff78f7b9971ce5bbe6e82009777da78003cbbff1aae5aa4cb36a288d2e0114dda5121d4"
    $a17="1625cdb75d25d9f699fd2779f44095b6e320767f606f095eb7edab5581e9e3441adbb0d628832f7dc4574a77a382973ce22911b7e4df2a9d2c693826bbd125bc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha256_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
    $a1="6f166e778d3e08c067dfe733f47e38f74c59817c268e7ec633c74d34e6deb56f"
    $a2="8189746886056ee6d6fd972305266512644d5160ebf412fe049157d4458a2a36"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="92563d2553584ef62ef475e3600bb4acb6c40ebd3ba5262e764272a05074a7f2"
    $a7="d489934ca5788e0ef6804a876ccebc50a28fc28496c801e1c3e91ca3143abf0b"
    $a8="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
    $a11="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a12="324dc0fc79e6ed2f5ba548e90d23e7600e5a7d0cf072dc2dbe17013d66534551"
    $a13="f73c1c8e2facc4b6f4cacc8ec891c55c2f7363bb9f84ebd007e7c947d63381f3"
    $a14="3a5364b82c10fd33a3676e2e99ef5b46d8c93c9ecf115ebbeb09d5adde45fe47"
    $a15="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a16="89292d1b3103ac3cd6a0dec5c9168e9b636e8e0346c940bcea67d1c343a97585"
    $a17="37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2b_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d370e850128bf8e0e7ced28d2168009877e8ba4e3f34d060ba376911e63dfe0b56a05094d70a02e220a4d8a6c051eeae612609c50fc50b2921447ce484d0aa03"
    $a1="a2efb8e42ae1cf400bfb9bb0504a0db1a5e15e6887ed502bd0c9159299dbe1e09f39adfd7981681e7284b7294bb08f716e2c88cc3aa77529d0555b45a925e5a5"
    $a2="84fad0f12fb8bc5196e490dfaeb95caab93c5d37e81f1191085cf5c4a3203f9c73ffe7234c9577f69a37ef87512c556c9ee417c3334add4de91a8516639af1a2"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="d370e850128bf8e0e7ced28d2168009877e8ba4e3f34d060ba376911e63dfe0b56a05094d70a02e220a4d8a6c051eeae612609c50fc50b2921447ce484d0aa03"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="69baf6e415c26242d39904368c39f644eeb36eab71912c8aff38911aabab0ddc03317e9c93d209a8306a8789a51a6b90abd5e04a4454de5afdedc95314ff45c9"
    $a7="4821d6006e6c5f0f1243f7902de4755604f519f7f623f16df1453cbf451bc57ab06e832a494cd5a4e3fc9a228b1cf3f1db63afb97b26468424baa268ce0fafd0"
    $a8="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a9="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a10="d370e850128bf8e0e7ced28d2168009877e8ba4e3f34d060ba376911e63dfe0b56a05094d70a02e220a4d8a6c051eeae612609c50fc50b2921447ce484d0aa03"
    $a11="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a12="15971acb6dc55aa1f23e3ac4ac09b17016fbb0e98f396609c7fe22ffd41500d7d54d1e62ee4fd4a49e7ab8136f3e45a3233414029fba5dd7f44defa9ea42600d"
    $a13="329dd7e6add3a733b61f11c8058eb9feb8576d283e4d96935b6a18e7fd86b64e32bca47758ed11c54421841464fd19047712b06e61682b810790d7487104a7f3"
    $a14="8ac62a73ded609592ea02477c9c318855e29d60b1bbf836e154d0d5f354568739ed3ecb3638292800054f619efbd6d9c938a529868c42299c1ed2eba5713f25a"
    $a15="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a16="6baf6ae31000c0b078d6aee708e5aaf13cf2c86801a0e983309db234d00d09ddfd0475463f4bfa87c86a873a17bd17a3fcbaa8119c78e37ac3c291927b790552"
    $a17="6a3712e2b92f69ead391b691710a587f21fae1e7b83b94b7835344eed1c463cfe03816e61922646f7aa0b581f3ba35842b12e556b2e4e0644c0f1d1d0549a79f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2s_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
    $a1="551ef0607965136474e543d944d5392e1bf3ea65224f77f90f7e524b7b88be25"
    $a2="4ffc5bdfd33a24fbe95c11c318697b883b15c93ef72d06b45e2660d1d75179fc"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="a3866d06cdac0a0e9d7286439fa10193cc2f8a9991444dff01a5c1b8955ee428"
    $a7="44e183ea2dab65f1b56afd25a3e6912535db21bb81e2a218b960ed0efad41f18"
    $a8="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a10="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
    $a11="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a12="231a00cd8d05fda295e915f2c45410d3b529a0dbed95bdb181a7f1dea5e68a93"
    $a13="0d0ab17836ecbf9bb500e19a403333b23639558fd32ed3d95d2f6b9b8a52259f"
    $a14="9b47cc1fbf17788ec8a5fdc86e2ee8d92068623df36eae7217468620a17f639c"
    $a15="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a16="40fde414b5d75d32c01f34d9f05bd86752a4c3ff4244ae1c4071856eed0b19ea"
    $a17="4f38de7eea698e71df046d36abca9a5d7ce3f82f829f4b8c0f54a6334209985a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_224_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
    $a1="60d14e19989ed5a1b03b31934f189be69766c5692ae815bebceb4390"
    $a2="c40c0066051109e6be0e187914098b30e226d67555b5ada283a95def"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="9976702f28a05a97104c42c54485cc5ba9934c2678cfb760019f2b3b"
    $a7="b0943331ec6d77e02786088264831bfd9538b613526a25657ecc354d"
    $a8="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
    $a11="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a12="798853769d763e8c45a872e54953992c405f029f93dc99a342887a88"
    $a13="cd2a95bf34c36874110599b4da7e44326c8bc8e17e91753dba17228e"
    $a14="cb728babc0fad99e8568d29b85f963fe824744f5fdefbfa2e6645f94"
    $a15="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a16="ef104e45e2248bda1fc499d3b77ebd7e857a3aef8a8bdfcdad077bde"
    $a17="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_256_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
    $a1="06930fbdce4d7fba6cc4c3bdc7f5c2d20bdfcfe9ee51364be81e119e70e6248b"
    $a2="0c251f4f9fb5fa97f7950461c2d2fcbf8c2aa4cd1d86319053f72e90a4a56af1"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="24af0329dd22bcdf3805f1fdd579b30681ebe2c4c0b89eceb528158b64cced67"
    $a7="67974796ed393c0edaca0023b3efd3d2f56130b13b5813354624c500cfd56b95"
    $a8="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a10="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
    $a11="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a12="8763b9749ecb7a87a023d92dd04a60cb7e3443f1cbb040a21145713ce9c70b24"
    $a13="81197174dc203f5440ff4e2abc106556e591648ac6fc30f50803d69e31911633"
    $a14="8b20283aa7cba959cdd356f03d0db09434fa9140a72caeac7677eac37992bcc5"
    $a15="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a16="82c3099b1c7c22250266ca625b7b6294387d3e1b462bdd0b51937032dce79c5a"
    $a17="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_384_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
    $a1="597796fc80368aa98896760b7a2c66de525e5472ffdea59875a4eed2c9b28d8e3840003feb7e3f5124c964fc7632a08e"
    $a2="c488bc88d9a5f41f36fa285cc2b44f8e6f9b171f33be64daf3a74adac3d555b241ff898ba8043f86c17acdefb359c1d0"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="1d243ea48da2020cde4f09bd8d38a01876f099d53bacb37cffed21309dd399c9cd57a4dfa671c06ab2627c6eb5e23f99"
    $a7="768e9f484407d2d3f91ef8ede60886837c48cac9409422b9ac17fb296fe5bcbee2fd72215b97f6b8edbe0c51b3c090eb"
    $a8="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a10="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
    $a11="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a12="e40da1fc6ecbaaed8050379007e33d86bb116367495b90bf7bdd1dc93c3b5578a42f883e1ea9061ab8ce45e895f08c52"
    $a13="8297ad20b40298518832407380132303d05a61a28c2009d16839b0b461188c3bf81df28c0082f0830049ce4a439ae7e0"
    $a14="0429da6051634207233ce1e7a6f5dbd59e56b606138bf1c8b0dba1729129fbf482d3f0ae2804ccdc1ab485dd073a060d"
    $a15="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a16="99c6b10c4aed4f0d55b9ba3a13ee2bc67207fd3bfb3969cf04449b4630d87885844fa701f0eb6aff43b84242182e632b"
    $a17="f437f71603b12fec1a4c1cdf46af48d0274fc3da86d451c00285697137cd82fb803b543f025e4d4549eb5efb514643c8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_512_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3b1b3e2ece320eccb83e1967d31832cda664a0b1aef72abe8c1b3ea2c46c38d5b631edc3573792c84006d245587b19a6e2d94bc36531f7e52b0669874ede7bd"
    $a1="6fd00eb3bc5a865466378bb825d765ccd649b467acdf00761c503d703ce2024a183ac6dcaf40bd6e15adef030826d6bdfb1c4c587da53e10e415b691b7bfbcd1"
    $a2="d42ad07b936dd598d8aa24b2f35007c7219f70c6d0b730d0b8d22cd6125d20836b7db2a2ced7cfa22c911d7650ebf9741b05c593788b33b61087473e981b1207"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="c3b1b3e2ece320eccb83e1967d31832cda664a0b1aef72abe8c1b3ea2c46c38d5b631edc3573792c84006d245587b19a6e2d94bc36531f7e52b0669874ede7bd"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="92412f3f01247436f1201394d18e7ad4ed5d4e378f50e01a0604051924a9470882b53f8cd3818e0d736a2a013d7dd4099c3ee8bcd8b38c3f9c796fe4a915589f"
    $a7="c61d227b39bea341bc41a91886dbd030797f99b8b1b70e00251732f723b446cc6fa5892b8ebd0aa8cb40d322ceb810fc03f770a60b90430f00547b07a7df92f6"
    $a8="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="c3b1b3e2ece320eccb83e1967d31832cda664a0b1aef72abe8c1b3ea2c46c38d5b631edc3573792c84006d245587b19a6e2d94bc36531f7e52b0669874ede7bd"
    $a11="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a12="c62bf0987ce54d22a9e3e9d0951e282776777e281cabf4e1266694c6715f7de7e3204938148442a570fce689bd7b59135aa804954097544ee167f0d6e37d41be"
    $a13="b6060e997af54b34d3f32ea50618ad3aac9dccda5a57e90dc7d78f0209371e32cd6c7acda5d2f8090a4410053b3ca67fecc52765035450f05c3dcd61f6b0d2a9"
    $a14="5e51bd73ff2054acfa90787a02bc083cc163511de9e4df84a51159a22dfd331b38a030a9794705e0e1adffbfbf83dd21501903e964673453ab317025f6d268e2"
    $a15="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a16="5c736114834138dc922314c1f993b6765a8d3ce96ad902a40c294dee828f3bc223e96a3d4c3653a33c3af1133d0db4698f3f9fa64210c0f61d0f557bf63b56ea"
    $a17="fbaf1d3516e4849991e8eaa16e401a9d0cebad944297cd80022f9424c8d9d172f7cc94844f529cca51005498f56ca90672ca918cbbfc06c0071b9c12b98f89b6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule base64_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c21j"
    $a1="c21jYWRtaW4="
    $a2="YWRtaW4="
    $a3="YmFycmljYWRl"
    $a4="YWRtaW4="
    $a5="c21jYWRtaW4="
    $a6="Y3VzYWRtaW4="
    $a7="aGlnaHNwZWVk"
    $a8="YWRtaW4="
    $a9="YWRtaW4="
    $a10="QWRtaW5pc3RyYXRvcg=="
    $a11="c21jYWRtaW4="
    $a12="bXNv"
    $a13="dzBya3BsYWMzcnVsM3M="
    $a14="QWRtaW4="
    $a15="QmFycmljYWRl"
    $a16="ZGVmYXVsdA=="
    $a17="V0xBTl9BUA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

