/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_mitsubishi
{
    meta:
        id = "2ZX7veHhEyLhK3Ww2kZ0IS"
        fingerprint = "1433148dc405cd1dc24e714b7b8288b630e005401d408e7923d5f2db407a6bbb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d0c59435460e021d1824c9040e81e727"
    $a1="d0c59435460e021d1824c9040e81e727"
    $a2="5aca61349100788cad39e26a42646e81"
    $a3="5aca61349100788cad39e26a42646e81"
    $a4="7e88454bc2e541e1e8cedbd954fdcbdb"
    $a5="be36cdc66f71518575faf0da91de47fb"
    $a6="57d583aa46d571502aad4bb7aea09c70"
    $a7="823893adfad2cda6e1a414f3ebdf58f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e8d62d73a0ce908"
    $a1="7e8d62d73a0ce908"
    $a2="4aa2f3a75da62533"
    $a3="4aa2f3a75da62533"
    $a4="3b1dd1382bb45841"
    $a5="5f15e14f21b98c2c"
    $a6="1a486e7929011a28"
    $a7="57510426775c5b0f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FFCA13CB9665CB1C2EA4DBAC5F011440E84C7BCF"
    $a1="*FFCA13CB9665CB1C2EA4DBAC5F011440E84C7BCF"
    $a2="*CB99A0037F478625F065B90A709C9F253093157B"
    $a3="*CB99A0037F478625F065B90A709C9F253093157B"
    $a4="*6C72115F2701D784A331BD290370CED9697416A6"
    $a5="*B10C7E07BA3E1A37B2B8639F19064D2AFB52EF1A"
    $a6="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a7="*11DB58B0DD02E290377535868405F11E4CBEFF58"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}cXePWLIKoqXIljMVvS7mKg=="
    $a1="{MD5}cXePWLIKoqXIljMVvS7mKg=="
    $a2="{MD5}S78bkc9vJMk7DDBPgSeAwA=="
    $a3="{MD5}S78bkc9vJMk7DDBPgSeAwA=="
    $a4="{MD5}0UVHTHCuDWSEjmwtnSEUxQ=="
    $a5="{MD5}CqR5MqIbD0cORUc3qiTgow=="
    $a6="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a7="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Ktt4mj5exTVTJpH3plzY6Vc5TzA="
    $a1="{SHA}Ktt4mj5exTVTJpH3plzY6Vc5TzA="
    $a2="{SHA}/AsgweyOFJc8H0yTWFML1tJXd6M="
    $a3="{SHA}/AsgweyOFJc8H0yTWFML1tJXd6M="
    $a4="{SHA}xyh3xRp3sqr8B3HYIaJipcamGGo="
    $a5="{SHA}tMVNviw06cHL8n3nmjZhcXsf6lI="
    $a6="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a7="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="71778f58b20aa2a5c8963315bd2ee62a"
    $a1="71778f58b20aa2a5c8963315bd2ee62a"
    $a2="4bbf1b91cf6f24c93b0c304f812780c0"
    $a3="4bbf1b91cf6f24c93b0c304f812780c0"
    $a4="d145474c70ae0d64848e6c2d9d2114c5"
    $a5="0aa47932a21b0f470e454737aa24e0a3"
    $a6="ee11cbb19052e40b07aac0ca060c23ee"
    $a7="084e0343a0486ff05530df6c705c8bb4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2adb789a3e5ec535532691f7a65cd8e957394f30"
    $a1="2adb789a3e5ec535532691f7a65cd8e957394f30"
    $a2="fc0b20c1ec8e14973c1f4c9358530bd6d25777a3"
    $a3="fc0b20c1ec8e14973c1f4c9358530bd6d25777a3"
    $a4="c72877c51a77b2aafc0771d821a262a5c6a6186a"
    $a5="b4c54dbe2c34e9c1cbf27de79a3661717b1fea52"
    $a6="12dea96fec20593566ab75692c9949596833adc9"
    $a7="35675e68f4b5af7b995d9205ad0fc43842f16450"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="52da9ff22f2d5627823bd3de3fe8f677e16f808b5612f0e88a9d206de993922d3b15f221c4102d00b5c6d0ebfce4a461"
    $a1="52da9ff22f2d5627823bd3de3fe8f677e16f808b5612f0e88a9d206de993922d3b15f221c4102d00b5c6d0ebfce4a461"
    $a2="254e62dc74ddded1747bca9d68dbb7664de3b9fb88a7096ede7a02aa53c0fe5531f29441bf5e758f79a14a74b04c4581"
    $a3="254e62dc74ddded1747bca9d68dbb7664de3b9fb88a7096ede7a02aa53c0fe5531f29441bf5e758f79a14a74b04c4581"
    $a4="41f45635576e8bed250f7412563d51e834c0da9db0ac84e2e166be8a0398a7875af322a958b8b24824b29e93441b3c73"
    $a5="d5171f7932a127282a9d3c947e66c0cf983a471a987e9eb2891eaf55fd39816ee893bf2a29eeaf8d940627a6085b0f06"
    $a6="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a7="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ecb569643d7baf861d443baddb4da13f38eacb332351c7ebf2621334"
    $a1="ecb569643d7baf861d443baddb4da13f38eacb332351c7ebf2621334"
    $a2="3737994ca1574da975559f9ca959e023d54a05ebde574b213c442222"
    $a3="3737994ca1574da975559f9ca959e023d54a05ebde574b213c442222"
    $a4="9db139931d729312e0a0868e3606df1fa7396685351b5782270e7763"
    $a5="54841f196e3081266db2c2f44cdae8a1ecd29bf46b7df4aa37535bba"
    $a6="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a7="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8e31db536865c0db7745ff6fd3c063d373149140c729f51c9771046615fe27d3e96796c40a3a329fe5c51970e1c8fda216e36f17714a260cb10d1badc89a7489"
    $a1="8e31db536865c0db7745ff6fd3c063d373149140c729f51c9771046615fe27d3e96796c40a3a329fe5c51970e1c8fda216e36f17714a260cb10d1badc89a7489"
    $a2="deba6ff0c2f0c2299b0b676e42f2b36a599ed6db2d864b7c85f28898ef36b7b29505fa89a4d41c6d97702fa367d5c4b3b03d65f5feeb777b5b67046b4137e086"
    $a3="deba6ff0c2f0c2299b0b676e42f2b36a599ed6db2d864b7c85f28898ef36b7b29505fa89a4d41c6d97702fa367d5c4b3b03d65f5feeb777b5b67046b4137e086"
    $a4="85336f9d2134e4e28f47ab082c7e01c95fe0a230b8ab8f95016765fcd9d6ff688481a2c3541e5fa166aedee259e755ddd17158eb4aae76a2033956c8b805ba4b"
    $a5="b0d21a54f973ec5ea25bbb8bf96fb91fad30ed785661d204bbffe002a069475b767dc1608497598ed04e1c59f510b782362489291f4a6ed4dc78f513ede26845"
    $a6="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a7="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d4c7328a3f7407c636b2ccb97830294c162147f814d96af2de0b1c84e95eb77"
    $a1="9d4c7328a3f7407c636b2ccb97830294c162147f814d96af2de0b1c84e95eb77"
    $a2="a1f259c43f119e8b79115828a9c87f4c5a31b412f52befeef0f2067c70ead090"
    $a3="a1f259c43f119e8b79115828a9c87f4c5a31b412f52befeef0f2067c70ead090"
    $a4="ca3e729584e18937efe6fac042de759769e4c1459c5b685d62c29567d58b00df"
    $a5="671216546648d8d608fd0e62a36b30801e8ce6406fb2b41bed3c20dcd553f671"
    $a6="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a7="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65ef365534689612114bfa85545d52af56b013429efe83b2edda7e32544463d97b01c0ebe680f6f6d4993bacef22c243e1d4ffb4cbfd513a61fe450ec2d6e2fc"
    $a1="65ef365534689612114bfa85545d52af56b013429efe83b2edda7e32544463d97b01c0ebe680f6f6d4993bacef22c243e1d4ffb4cbfd513a61fe450ec2d6e2fc"
    $a2="765dcea4b5abea439c5fe9cb6b8ecde3019a3f4c441953189f9a87090291b195d049f83cf0eaa8e34b924ec518b89589f72a2b2fcbdb1393757c74e6d1552103"
    $a3="765dcea4b5abea439c5fe9cb6b8ecde3019a3f4c441953189f9a87090291b195d049f83cf0eaa8e34b924ec518b89589f72a2b2fcbdb1393757c74e6d1552103"
    $a4="dc26455eebc5a142bd2299041811bf16fc1c902374a0db57a919ac4d0d0f6a22226c4743bc866a9eb53cfafe816e3289ce8380c1bcbde05f9e79d84abbd926d3"
    $a5="97e8a7ec7be2ee207348d4be4772561844f8bea34dac6fe6b390d055a3254edbadc42335720d203b3a7cc69c7fc09981653bd5b437f0556189c182c03bb10f89"
    $a6="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a7="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="594ce045611b47c6d86239f802c479c17a4f73e78935db061a6419274af5e892"
    $a1="594ce045611b47c6d86239f802c479c17a4f73e78935db061a6419274af5e892"
    $a2="933fbf8af5648c30eff5541ac9a66afa5c44e150b7692545ce361f32246976c9"
    $a3="933fbf8af5648c30eff5541ac9a66afa5c44e150b7692545ce361f32246976c9"
    $a4="a69de6e4ee4b7877991bfb9e6ae7778e852e299050a96c3e32e555f7ef5c135d"
    $a5="ea13726e06548d9258a632f9bf5f062cc58e402db8650030689c2c4c92b46923"
    $a6="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a7="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4b9c404bba7e23ae6e86dc8260931e016f4f066fb6f80036fd78712a"
    $a1="4b9c404bba7e23ae6e86dc8260931e016f4f066fb6f80036fd78712a"
    $a2="70d8652689d23882313799bd223a16b9f2d17ddd5997c5fdbd488bf7"
    $a3="70d8652689d23882313799bd223a16b9f2d17ddd5997c5fdbd488bf7"
    $a4="dcf22cc69e63a23360f92909d477a244cc6e351e0253a4c8a0f9cf51"
    $a5="0b6439424fdc07128efc5abb505eb04bfcd556032bae9e8bca95824b"
    $a6="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a7="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="118d62788fcddd499bc489d5b336964984a7485b86bb01d6c85744806a3f774a"
    $a1="118d62788fcddd499bc489d5b336964984a7485b86bb01d6c85744806a3f774a"
    $a2="c938ec247e796d99a07cd0194378b84b8e278738db327869d727c410d03dc603"
    $a3="c938ec247e796d99a07cd0194378b84b8e278738db327869d727c410d03dc603"
    $a4="1253fad7b73d72305c0671b459069d5d7650fa54aad3d6dc3071a75a1a2bd079"
    $a5="a93c785803401e328d1936421418fe9145a12120136490247f878e26c7afe1af"
    $a6="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a7="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e99e97d7bae314cda30b32c6dea69e9d0ede5e08bb6cc6e148b1a906b4918f505160039e75d88fae822feca6c1b6ceec"
    $a1="e99e97d7bae314cda30b32c6dea69e9d0ede5e08bb6cc6e148b1a906b4918f505160039e75d88fae822feca6c1b6ceec"
    $a2="fa0e7a2411343289471cb5b4ce2e5dfff1c5a7ddab97f16df343010ddeb0abc9004dd34711ff790e75b7e378228b4346"
    $a3="fa0e7a2411343289471cb5b4ce2e5dfff1c5a7ddab97f16df343010ddeb0abc9004dd34711ff790e75b7e378228b4346"
    $a4="e956d70ef6cb655b32bc47b4e15e316c2dd2f8e40d3f989d302f5427e563f5add6fcc428fd4597e7353625d99f42ca2f"
    $a5="8a95ee7f3fdfdee68288a25c947a6f8f13f7ae84760faeec41339eb9d548131483a95668b704a6bf83a509c0990cfc41"
    $a6="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a7="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a1d8ea16c3e216655584a73e7ff34cdd43b53580188d8c81d46a150b37cd60a8535fc61ab1c9d3f8f92c537773755cb920e4255edb1a940e28cfea3879258c0"
    $a1="6a1d8ea16c3e216655584a73e7ff34cdd43b53580188d8c81d46a150b37cd60a8535fc61ab1c9d3f8f92c537773755cb920e4255edb1a940e28cfea3879258c0"
    $a2="845bf9cda691594d82a31c6992d8497a46df1052ef25192d6aba4ee8672b4696f2ee3ba373f67c548dee77409a6848dcbead81aa12fe56b8cce44abd2344462a"
    $a3="845bf9cda691594d82a31c6992d8497a46df1052ef25192d6aba4ee8672b4696f2ee3ba373f67c548dee77409a6848dcbead81aa12fe56b8cce44abd2344462a"
    $a4="de4ca5f8774453c9f4de6dcd460201e621cdba7f0b6e152a049cde5b3a46c0fea58e6abb5347f9923b01244ffc37832e048918f5fcbfee745c86a444315160de"
    $a5="3a1042b612a907b2a776584598e1c9638c87f749821926e4568c7772009f5a305f03c1e1fa8fa83561bed14550828f1d9468b4f670d07d35f4ab97af1ad7d912"
    $a6="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a7="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="TUVMU0VD"
    $a1="TUVMU0VD"
    $a2="UU5VREVDUFU="
    $a3="UU5VREVDUFU="
    $a4="ZWNvVg=="
    $a5="ZWNvcGFzcw=="
    $a6="Z3Vlc3Q="
    $a7="dXNlcg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

