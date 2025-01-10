/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_telebit
{
    meta:
        id = "6ggTV4PUIbOGhHBUMjvEHD"
        fingerprint = "6cfaf03c1ad7ed2ea4edf6bc89b994e3c541633642be22af2d6e82b1b70ca14d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6aebf95ee750d35a58d279ad1fbf32b"
    $a1="e6aebf95ee750d35a58d279ad1fbf32b"
    $a2="1c4ff44400517285296ff2ad764c064a"
    $a3="27db353b7291d17f3ebc1fdc672a4630"
    $a4="39fe310c851e7b1e7f4aa1772787724f"
    $a5="27db353b7291d17f3ebc1fdc672a4630"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d89770b0d299d60"
    $a1="3d89770b0d299d60"
    $a2="4e3261527dec15ee"
    $a3="6af6992c7e70f8d5"
    $a4="7e888a35354f24ff"
    $a5="6af6992c7e70f8d5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*18ED90460331B8E9FC796D9FF923A720D3EF8592"
    $a1="*18ED90460331B8E9FC796D9FF923A720D3EF8592"
    $a2="*2309AA61C73F02E54890747EAD6FFCB927A66565"
    $a3="*A5AEBB616D92AE56DC05FE583CE000F34072E007"
    $a4="*6F2192D95FC8369B70A989445154CD58E7D34C7C"
    $a5="*A5AEBB616D92AE56DC05FE583CE000F34072E007"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}oPhIlCzoY89TwPpsxoQAfQ=="
    $a1="{MD5}oPhIlCzoY89TwPpsxoQAfQ=="
    $a2="{MD5}nOIdjzmS2JoyWqnc9SClkQ=="
    $a3="{MD5}lvmWPiVSCpARyCQBkgeU8A=="
    $a4="{MD5}oyw9POwg9aCVlbhX5FtHfw=="
    $a5="{MD5}lvmWPiVSCpARyCQBkgeU8A=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}gEN6RKZh0UEXQgkRnVQSWlmmSyo="
    $a1="{SHA}gEN6RKZh0UEXQgkRnVQSWlmmSyo="
    $a2="{SHA}0Ybo2sSKJNARW1aNCrLJ6Lguats="
    $a3="{SHA}yFgkdXo3PJjRe1a06ppWScW8tV8="
    $a4="{SHA}xvzZlVm3uGJvYiB0F4VB5M1PbNA="
    $a5="{SHA}yFgkdXo3PJjRe1a06ppWScW8tV8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a0f848942ce863cf53c0fa6cc684007d"
    $a1="a0f848942ce863cf53c0fa6cc684007d"
    $a2="9ce21d8f3992d89a325aa9dcf520a591"
    $a3="96f9963e25520a9011c82401920794f0"
    $a4="a32c3d3cec20f5a09595b857e45b477f"
    $a5="96f9963e25520a9011c82401920794f0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80437a44a661d141174209119d54125a59a64b2a"
    $a1="80437a44a661d141174209119d54125a59a64b2a"
    $a2="d186e8dac48a24d0115b568d0ab2c9e8b82e6adb"
    $a3="c85824757a373c98d17b56b4ea9a5649c5bcb55f"
    $a4="c6fcd99559b7b8626f622074178541e4cd4f6cd0"
    $a5="c85824757a373c98d17b56b4ea9a5649c5bcb55f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a1="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a2="3b67410b602c36730b8572f9cf49383caf0d936a14e7d93d4f0906a3f27d839964a7bf6dd3ffe74f541788c10a53ce6c"
    $a3="4da496741d104cfac77f429b2c14ae0875a89837302361b7d8dc65dbd523ffa61f850d7ce38b27818299d2ada1aeb99c"
    $a4="cf8cb7bd641fa46a496514440e4b0698b56e94aef126b960dbf81290fad7117511abfb9d2fa882225cbd94463f549e33"
    $a5="4da496741d104cfac77f429b2c14ae0875a89837302361b7d8dc65dbd523ffa61f850d7ce38b27818299d2ada1aeb99c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a1="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a2="052eb93c022bca225a99cab966bc361080005ea17fa6ace1982c9f6a"
    $a3="9770983b66e595f0ba5f261161c1ae7847064a4a3a4ad7791510733b"
    $a4="c8237ed786e1430e7a31c50bf3b9206634d35ddfc039c36c58ea0790"
    $a5="9770983b66e595f0ba5f261161c1ae7847064a4a3a4ad7791510733b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a1="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a2="877a07cf4b7e1301aba8a5ce13caa61d06f4c2d3954f235c952797b44cccbc509e02a1c0482489ba76ec5ded767b1b010d34f05fc27f2fda115a35a9c023bbf3"
    $a3="1baad5fbab2d620deec1b4abf254e871c1112c3909b89fe299a49a1b8b2531c99468e20eca5b3dd26c136743247570dbab7f817f78b614d47687c22b84a7c43d"
    $a4="773080f9e04346d4f0e9d746fd2b04beb1bb9491894eafd580f9e932bbaa59de4311d953a608290045ce3c0ed9185f09502f4dbb999ca045113460a2aa78495b"
    $a5="1baad5fbab2d620deec1b4abf254e871c1112c3909b89fe299a49a1b8b2531c99468e20eca5b3dd26c136743247570dbab7f817f78b614d47687c22b84a7c43d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a1="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a2="5912d5590ceedd61724ee20d37b515427916c915081bccad29e0c684476014c4"
    $a3="9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a"
    $a4="c797f6834c354fedaee9e19bd52583f73ee2255bea1d6cc412168eff78675c99"
    $a5="9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a1="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a2="98b4a448b288bb9f66e508139df2576b4101285caccf6db6c65ae82fbd9790cd57d46789f86907741add261719c41791f5607b4a5cc0002ff0f594efe636e3eb"
    $a3="c9364aa9e1e42c37b427dafac704d1a803c60e8d9fd433dd9b69248c25192b4b586a7f8723adf572dbccb308f4c60d433c7ec4a093ade50412ee180c7a7182b7"
    $a4="8ba3a9ba1f70a08a652a6c98bea64a11dced25819903e5f21eed7db692fa1e382a3f4e9d0c24e18baacb42c7cef6c35349a61804451bb2f208623d39e8a26986"
    $a5="c9364aa9e1e42c37b427dafac704d1a803c60e8d9fd433dd9b69248c25192b4b586a7f8723adf572dbccb308f4c60d433c7ec4a093ade50412ee180c7a7182b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a1="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a2="450c9a03e5369c74b49b59ffb044e8dfc50fdbc7caf31b3b40b17c6b0cc2ae50"
    $a3="d0f9a7487b9993af9e680124b91a9f3b7de5839d3a7045fd459696932c991c1a"
    $a4="20c86bb90d595717f02c30e7e36eabf994dc72a5e99aa728bccd75e52495f52d"
    $a5="d0f9a7487b9993af9e680124b91a9f3b7de5839d3a7045fd459696932c991c1a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a1="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a2="9d8d2e356e3c878f51ccfbba09de41199b1c71d25bc20e3a806ee3e0"
    $a3="99e9dfd41c89f21695b6117deb842ac61e71f2a2e2ee4e248d7ed54f"
    $a4="e1f96d03c34f6a579e09118b4f75614614bc2b255f02ac94cb91cc04"
    $a5="99e9dfd41c89f21695b6117deb842ac61e71f2a2e2ee4e248d7ed54f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a1="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a2="74558bcfe17e7179bda0280ae817029860716d460733f9726fd632f34518b8f7"
    $a3="e239de1942d79eb9759b60e6b7e98e9cd17694616af0b38c8816b4ceba6a9b77"
    $a4="ab3096e75a21696828f78fae2ea6de1427c28a63a6d1a25f15855bb257ce91e9"
    $a5="e239de1942d79eb9759b60e6b7e98e9cd17694616af0b38c8816b4ceba6a9b77"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a1="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a2="ddfe867f7428f649622b80d66e82861531a6290f48ab2abaf22c5ec5bc00f989c99fc4ab86c5c8407aeefaa03c852ef8"
    $a3="0efb5a9d99b64ce5a808754d55eed93b4c65b6307484c298bdc2d3732999f21eca47129421c162423cf115e5e733b088"
    $a4="6eeb9a005a6a196390f7ab8bd7477922b7fd89c5b3768bdd27bf4da035206840900139baedabe0d888207bcdae10584c"
    $a5="0efb5a9d99b64ce5a808754d55eed93b4c65b6307484c298bdc2d3732999f21eca47129421c162423cf115e5e733b088"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a1="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a2="4da5e755ba5f6f7c50c35a026cce0ad2502305444d99ed680925fa90cfb3de48b537855d6e554ea0ac808eb6a1bbc853476065ed79b768b371868482bb0f4718"
    $a3="3544701b1b3c664c4bde932492c6ef3bef31dbe7d16ad4a0ffd1fbae0e91cce47280684989f6353e129438011bface3102304efc6df34585241148b5d94f2977"
    $a4="d8daf7b12c0ad18465b4804f8889649405fbe2ca3caa3b54a2dd1ea0ea5b41b56fd8df455308ff67212267a4ac45c109a2b0076680c39f347939228bdc640950"
    $a5="3544701b1b3c664c4bde932492c6ef3bef31dbe7d16ad4a0ffd1fbae0e91cce47280684989f6353e129438011bface3102304efc6df34585241148b5d94f2977"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2V0dXA="
    $a1="c2V0dXA="
    $a2="c25tcA=="
    $a3="bm9wYXNzd29yZA=="
    $a4="c25tcA=="
    $a5="bm9wYXNzd2Q="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

