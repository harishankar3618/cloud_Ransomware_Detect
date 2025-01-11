/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_hp
{
    meta:
        id = "2DXuVTUAbsfRf8wdoDykGi"
        fingerprint = "8be9467dfd3ea92aab1e59f6f45428fff011b352df59e38be5724aed8d739229"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="26c1dbbdd50f555d5a23dd9d79fcba82"
    $a3="f80ca594861bf6e652164cade78e89ee"
    $a4="de2c13ee8d8b209e671629bb28783541"
    $a5="51b447c257949292c6c55e4e98fa06e7"
    $a6="47cda1e3ab2c33e7369db5a86f251fef"
    $a7="51b447c257949292c6c55e4e98fa06e7"
    $a8="969de145905a696de8e5f37e292527e1"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="880aa8beaef65966121e8d79ed8b42a6"
    $a11="d94dcf92d61d9df33f60a402b4d61755"
    $a12="209c6174da490caeb422f3fa5a7ae634"
    $a13="d144986c6122b1b1654ba39932465528"
    $a14="209c6174da490caeb422f3fa5a7ae634"
    $a15="209c6174da490caeb422f3fa5a7ae634"
    $a16="9e056d37ecd6346a9116e35456f148a2"
    $a17="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql323_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2e19393cc5ef67"
    $a1="67457e226a1a15bd"
    $a2="1416b82b47841842"
    $a3="59609e62287da4e7"
    $a4="1f6fda9414d32602"
    $a5="70072ea81fbd7474"
    $a6="07ad1420274d966c"
    $a7="70072ea81fbd7474"
    $a8="700cd614639f89fb"
    $a9="43e9a4ab75570f5b"
    $a10="5e2b7cd912a2d912"
    $a11="58573d166f8f9ddf"
    $a12="43e9a4ab75570f5b"
    $a13="58f7ee435f925abe"
    $a14="43e9a4ab75570f5b"
    $a15="43e9a4ab75570f5b"
    $a16="2a401d943e6d083d"
    $a17="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql41_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*C939F8C8467C763C7984A21A6CC1000582839600"
    $a3="*C1BCFD6877BB358C0518ECCD6D5A70BFF7D0A174"
    $a4="*1498C151149DCDA2DB6E1E28CC27E04DBFE7CB20"
    $a5="*1952E410B54EE6E4222111218C81D600AB3CC3B8"
    $a6="*E3C67C0A0ED8EC35163802D97EFAB3511544B5BF"
    $a7="*1952E410B54EE6E4222111218C81D600AB3CC3B8"
    $a8="*2EFED6D1DEBBF99C0BC752E8BCA3916768AF71A6"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a10="*EE8326FC0570CF3A62B5CEF5A6798965A1CEEF8E"
    $a11="*BD24DD1014E4A2AB76DB684D9A536824285D533F"
    $a12="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a13="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a14="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a15="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a16="*91F9D745AA2947EBD8AADCD0C1942754C1D29631"
    $a17="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_md5_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}tfx89xdTET10OEnsvNpD2A=="
    $a3="{MD5}62HurZDjuJnGvL4nrFgWYA=="
    $a4="{MD5}sULxoIkFuJnBsWuS/IM/9w=="
    $a5="{MD5}C8TA5L87Pmnz8JFgCEoSDg=="
    $a6="{MD5}9nDHOCF+4M/UaQQFzzLHuw=="
    $a7="{MD5}C8TA5L87Pmnz8JFgCEoSDg=="
    $a8="{MD5}gI111mh8j085io01pRMHbQ=="
    $a9="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a10="{MD5}CZ6+pI6pZmp9ohdyZ5gxOA=="
    $a11="{MD5}HG6YDg7uc6mpUSQ59WZlxQ=="
    $a12="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a13="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a14="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a15="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a16="{MD5}0NUPv2NgfJPsKfUVrE5YDA=="
    $a17="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_sha1_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}44tJAuy4GYKm5TOu95PHuG7kJoA="
    $a3="{SHA}xl+Z+MU3atrd3EbVy89XYvnlXrc="
    $a4="{SHA}EkRIVZ9HdZl5HyBo8THb5smk5Fc="
    $a5="{SHA}+0NNOGmIMqWZ5B4+xVSV+IbijLs="
    $a6="{SHA}qC4SboYhQdDsuADL2Jw03lTrO4c="
    $a7="{SHA}+0NNOGmIMqWZ5B4+xVSV+IbijLs="
    $a8="{SHA}75ke9gfmnf3RGYNDt2FBqPtMI18="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}8iMdKHHmkKKZVwT3ope9e8ZL5yA="
    $a11="{SHA}5HubECEDSla31fcNktBIFSTnj2k="
    $a12="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a13="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a14="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a15="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a16="{SHA}lm4E2SVQDmw17Y+oAo8z+jvbncs="
    $a17="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule md5_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="b5fc7cf71753113d743849ecbcda43d8"
    $a3="eb61eead90e3b899c6bcbe27ac581660"
    $a4="b142f1a08905b899c1b16b92fc833ff7"
    $a5="0bc4c0e4bf3b3e69f3f09160084a120e"
    $a6="f670c738217ee0cfd4690405cf32c7bb"
    $a7="0bc4c0e4bf3b3e69f3f09160084a120e"
    $a8="808d75d6687c8f4f398a8d35a513076d"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="099ebea48ea9666a7da2177267983138"
    $a11="1c6e980e0eee73a9a9512439f56665c5"
    $a12="21232f297a57a5a743894a0e4a801fc3"
    $a13="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a14="21232f297a57a5a743894a0e4a801fc3"
    $a15="21232f297a57a5a743894a0e4a801fc3"
    $a16="d0d50fbf63607c93ec29f515ac4e580c"
    $a17="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha1_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="e38b4902ecb81982a6e533aef793c7b86ee42680"
    $a3="c65f99f8c5376adadddc46d5cbcf5762f9e55eb7"
    $a4="124448559f477599791f2068f131dbe6c9a4e457"
    $a5="fb434d38698832a599e41e3ec55495f886e28cbb"
    $a6="a82e126e862141d0ecb800cbd89c34de54eb3b87"
    $a7="fb434d38698832a599e41e3ec55495f886e28cbb"
    $a8="ef991ef607e69dfdd1198343b76141a8fb4c235f"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="f2231d2871e690a2995704f7a297bd7bc64be720"
    $a11="e47b9b1021034a56b7d5f70d92d0481524e78f69"
    $a12="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a13="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a14="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a15="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a16="966e04d925500e6c35ed8fa8028f33fa3bdb9dcb"
    $a17="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha384_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="5ad35c172348a4dee599679196b2ec308f5ccbd575eddb4d21c37c6932802e4f25841882e7a278b9d44f2f95ae71164a"
    $a3="338ef44a9ff34626247ec1e36ea906ec09dad827cc3e931bcc090a76767a9f7c3131e7900eaf4ba34d3fa58f3e0559df"
    $a4="15a46dceda9fefd948db2e6eca47bed3d7ae64fe465fa26b30630296ebb6afd127b80f9ece97ff81ae3e7873c046db9a"
    $a5="0219ed5747e8868d635618d1f31e78d06c52846eacc07b0b29965073c0dcb4547cd25024c28d482591101624bc4d2842"
    $a6="baaee88f2c768f96015300016466582b550154738d10383eb086485a9bda2633937ade2dda507b7157e10cecbc925b89"
    $a7="0219ed5747e8868d635618d1f31e78d06c52846eacc07b0b29965073c0dcb4547cd25024c28d482591101624bc4d2842"
    $a8="57438364fc03adb40e633549e091fb4301ee9806bea075cef8f2ed1676147c42df5cfabd2352d2e1c62188c1ee19cde9"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a10="f5889a6a118d1f3968a0216060e6d861eb3b2fa05fc5423674908d92a0c80c335750f12790fa95e03976ab94cdecca47"
    $a11="73114c7a760f92362ccafc80b500ae704167906e9509d6997906df729b4f86e678dc8a9ae7a7f926874920b67b2621e6"
    $a12="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a13="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a14="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a15="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a16="fd6c09e15817e414401f46d1d6e4199aac71a2000a0cb139d9076b2ec294a8436d9f4177835f1822aa02c476be2aa64c"
    $a17="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha224_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="422eea0f677a9db3139f4b3ee62e5bcbd1b7b9790ebe5df7c787141b"
    $a3="ddb584a8a86bf5f4b700262bf5901f473d133869fac0ad86215ed2ec"
    $a4="b112ede8c42151cf6c818f0e3c916ecb1571efa14706eadd68ebba86"
    $a5="a6f50e761c4b9123d69e182b24c3f1741f1c9a7e522f5869ad331a2d"
    $a6="850c27f367d8f2531f59ea6c9bec6cb46f7ad5c3525121a87875e6ad"
    $a7="a6f50e761c4b9123d69e182b24c3f1741f1c9a7e522f5869ad331a2d"
    $a8="b0b8d261493551a5547df0683d64ebed2a054e5ff1c9bc2687bb4057"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="e0537f07091ae104db4a8b939b3c47b1b8c2f4f38c55ee45f871b22b"
    $a11="d9013712ed33598db5fd4ce9b8ed8709bc807fa71b361e9c7e2089a6"
    $a12="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a13="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a14="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a15="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a16="aa0aa1755df23ef15fb3315053fe450b489417933276cf16b71170e6"
    $a17="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha512_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="c83ea6f5d6969ec74b328b33c24eae28063248ce31a514b182cd1d8e76bacf37a659e6c692441a34e06f237f5679c218f9cda23071ad0985e7036dbd599c1999"
    $a3="33df2dcc31d35e7bc2568bebf5d73a1e43a0e624b651ba5ef3157bbfb728446674a231b8b6e97fa1e570c3b1de6d6c677541b262ac22afda5878fa2b591c7f08"
    $a4="6bef213757e5e55afb30df047e9f184540a265c70b4ec81aca44d11f220f3ca2bb89454d7336950adb1cdfff9fd6ad63356550fdbae69d50f07ba420cd6cb38e"
    $a5="c5fd7fe71a670e3936ebd103f501d9ad9ac4053d95b743f01ad9ece7c2593ee321d08bcd832b4562b8c8941ae1426ec9aa196c7a0f5b46883696a5306a8b29a5"
    $a6="e2cb708cfcafc329b761f054f0fe9a41a086edf5bc55ae3cb6029c6e34780265d48597d7cd38c0b8b8c77e36b154c442b5d88fd3a1d5c9aa9b94557abf628397"
    $a7="c5fd7fe71a670e3936ebd103f501d9ad9ac4053d95b743f01ad9ece7c2593ee321d08bcd832b4562b8c8941ae1426ec9aa196c7a0f5b46883696a5306a8b29a5"
    $a8="61f884b03cc8fde3d6a670187589df8475a31dd581798bc195f136ae0ebbae9a79648e177d698e0bb1e1fa74c6870aad35ecba53fc114c16c877c980b77a0904"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a10="8ea15870987d34972ee28de0e6b8ad0217970d473bb0414911753e8a1101cec81ba9f6b0db7fec16b2d0b9cd4c91337896ebdaa033b47955f620834761415c44"
    $a11="5938d9afe029dfd7976b6a64a0535d4abd93801616424098b81ff72daa04cb1c24daeb6397ce04a542405513e4c35746756d328a7f21dd99d5fada7261a25441"
    $a12="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a13="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a14="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a15="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a16="c081a17087cd1e8c2c48a10b344823948044be4ac680a0224b953e1734f8fd9e645deee5fee364e996e5e9af0d4948ea2f98f95857e4ef070942bdc86da8cc25"
    $a17="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha256_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="6150912cd17f0a52f820940039abcea92eeb8a1b434324117d04f44459666359"
    $a3="3733cd977ff8eb18b987357e22ced99f46097f31ecb239e878ae63760e83e4d5"
    $a4="156cab4396aff1999e21a9b077b7df3ff66c947c4004b37e2bcef1732db038ca"
    $a5="56e2321b61fac819f060801eee7557b3d4f584e383a4511dbba261955b496c8b"
    $a6="342d646aeae5b32172f721ba886314439c64e6a81d287cf744b2fd71e863ce6d"
    $a7="56e2321b61fac819f060801eee7557b3d4f584e383a4511dbba261955b496c8b"
    $a8="b462f38412acf13ea9771139375c4af03699aef7b773f0810b553db88c77d5e5"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="f76043a74ec33b6aefbb289050faf7aa8d482095477397e3e63345125d49f527"
    $a11="c4b97afe643da8e91b649cfabdffe821d270de093e189e264b369c329aa3a82e"
    $a12="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a13="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a14="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a15="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a16="5b1ea208c3d08373c1e554f12331020125ae52b3d01977461eb734ca80d71819"
    $a17="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2b_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="8619147b93dde4d8133de561b4d4fc4c8cc58715cba48f4bda382b6b7ab777f6dd26133d88c46db455b56e1e2b2970f139db1968e38a93040956946a8d479fbe"
    $a3="d2ccded8666a9d7306c1041662b0ba8afc4a15b534d9fe2a042db069279892ad32dac1fcc4b4447f40fc372e754518e0f228e9a54d99a9a32cf2217b589895df"
    $a4="fd674f33dbb1cfd88ef5bac621cfd0d4c49f87132b6b3d8975a133f4f02fa1173c7969752be129d53ab58c5e9ff33b36940ffc34257fe1d42b4463e031c92688"
    $a5="6c8ea23a82264fedcd02f70ef8420674941b8c70781e1a038d8603218f5a128c9968c0aec92dd49238614463649a2709ee101cb27d41da8f2de84e4be7792a0e"
    $a6="8b8db48fdcb2a0f0c51d51f4334fbd8d57120c1b3eded5429f82a36280d0c2df2434da6829e5452274e870a441a5d155cb45eb8b557f9dc9287af70396eaad67"
    $a7="6c8ea23a82264fedcd02f70ef8420674941b8c70781e1a038d8603218f5a128c9968c0aec92dd49238614463649a2709ee101cb27d41da8f2de84e4be7792a0e"
    $a8="4fc3a5cbb598818ab129f361ab76e51ffcd86df25e95fc589313aef037c8229e38c0bbf94c32094e007a8029014bd8233e7b581c17666c0fbf33e65baa027e2a"
    $a9="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a10="6554dad708a65bd7d3abee2d9c028e2e4c1319fb3ef8a752723b70afd572dfc408d3b1d0d19950f280d8772012d0a35209f5546345c3be1d3367fa34e9bb1e92"
    $a11="ef3c14a1d14912c2dbc35856ee8d08de8b5cd143f8f2a1b8c236f7ef846756e630803fe34243cf58aafa705e03a99d688ea1985a116ad0d1ee2dacf364e3faf1"
    $a12="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a13="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a14="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a15="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a16="9cc997ecfd936dbe1df21601d8192a498d7f046c3d12c5e781dbb2f3fcee8ee49d3a4e30d7699f42b4b7f655c8042141336f56e0aa5ebd630191178367074bd6"
    $a17="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2s_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="bfede1e34bf2c349910b30ff13ff8f2ee4acad4c26766d0e2714987a8fb995d3"
    $a3="90dede0a7e592fe2c9c5bbd1dbcddd9de3a0247b52569068bf28079ed98b5f5e"
    $a4="d615da88cf76d7901486b4193398d83bdc378f16c0feaf0e6b0a2635a298b547"
    $a5="6935dc80a6d5f6c34f57960c03769bdc4b997f7de78005d7211da593b7b74733"
    $a6="d1a6e6a24703aba7f1a90b821b18ae32c5f446253384528be7a5f9f215198db9"
    $a7="6935dc80a6d5f6c34f57960c03769bdc4b997f7de78005d7211da593b7b74733"
    $a8="6f6a3d2eb1a546dc6128fdfa48f9996c504837e7ea2b6be72c0da2c63085927f"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a10="b9bbb73c490b862e77461f5b12b60ae92c5460901991c39ce31b7da24f1d878f"
    $a11="5616213d19391447e21fd7a3119ebd9ebf17ef493d3760ef89a4a769b62729a4"
    $a12="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a13="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a14="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a15="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a16="e0bd0f313e0fb13640eb5060fb0e8a9cd501c4aa7d82ad39aebf35829b3d968e"
    $a17="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_224_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="3f73a315f6a76f6d1088eafec0bc432037e29e9b85d8a4337ff78fb5"
    $a3="88bd6d1cab4dae85d8c18a559575e965f30badf481d465a6f82a0baf"
    $a4="a96ee36d7eac84d12543e809ea04e233cd37c2a04456675a96d867ee"
    $a5="8ba353b87f08b97351064a0806a18e36e2f342cd26a8b95bc3cdf00c"
    $a6="f1e81b1f7302c580255b498d5490b55c65c57dbbe93a4ec3ea222656"
    $a7="8ba353b87f08b97351064a0806a18e36e2f342cd26a8b95bc3cdf00c"
    $a8="4ad8763adad18393abebfaa5e2393e2446d6377da995a0e0e82b7d8e"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="0f81b51cf2be501fff5405ce1426bab4fb53a8bc0089ad4e19fa38a6"
    $a11="d3b41d589a345a9f032ec864eb83dcf994e92c42a7b7943e12d7a493"
    $a12="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a13="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a14="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a15="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a16="6f3ff412ba937306d6557af1afd5214e9f58177a4cbc4755d9e2d47d"
    $a17="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_256_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="d0d60843b7142bf7732149b080d581f370e034bad57ab3a514523988a254f319"
    $a3="b834aac0f6ecf6e3b2e070b48471bed3f2a4bb18a5c8d793c09f9ddd86738ebd"
    $a4="0afcf13a363f6cb9529764ae95f05aa83a70a0b77e9ca6693174a2d70c06c4e1"
    $a5="d4e45af02b3333234a18a291ab86725cc2aa1d2ad258ab1ca39228e01bc3b7d7"
    $a6="9c04902a5cc7d1ac59e6e541ceaa002df39b2cc379b83462225e31596d317382"
    $a7="d4e45af02b3333234a18a291ab86725cc2aa1d2ad258ab1ca39228e01bc3b7d7"
    $a8="8823face196d1e83888a4c1a0c308676b2ef3d85b9a14e6b4f6d54b536a5c86c"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a10="9e60db57b96a31d91a6e93b7f4416d257d0b22ab081e6b293e7d23301a9521fd"
    $a11="afec5811ca4b60e82f6b4f88b484edd8420f01539205074dd897fe9003c11c8f"
    $a12="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a13="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a14="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a15="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a16="98776bf06ba2c3fa56a5989a76af49e2d36fd174e3bce234b7808f535375c16b"
    $a17="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_384_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="a71433cf354d756a50d1560dfd585429808a30a890d14855d90f3aec12309f51dcfe603539ebe52295ae3102b5b80fbe"
    $a3="07998ba419e8546fae0d5b6643c82b92de5f8e853ac8be82dd855482729fa0ac0af1f0b922f2cfef80742163790af136"
    $a4="045762f9bf939a8d32a5590b66349d6769208c3c62338c34d5ac23cbb776c14c028dfb51bd5a8b699ab7d47946eb66c9"
    $a5="84d4794f63cb8fdfdcd14304f90ec6ba0522fecd32be8f8dade888363d96669b92dd28facd02716c190847d8a583a9aa"
    $a6="e6baae9bd4c39850290f7930a816eb2e0806b267fc92994cc97c8595d7ba2d0ee5f921b1c980b3d7eab3e463613875e1"
    $a7="84d4794f63cb8fdfdcd14304f90ec6ba0522fecd32be8f8dade888363d96669b92dd28facd02716c190847d8a583a9aa"
    $a8="56fbcb8d24edc82497a4c8cd2cdb841a2aa15222133bbeed7582a907ba044cc70b01a74fa41ba74edfca8ad56c5e2ca0"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a10="420677fb158e8c3207566ddda5f7983239b89f99d2229fb03594b034cdc3d7f3a2253f202fe89931b7953bea6497ae5f"
    $a11="07bc09b5d98a45b3a068a1b342c86374b5a5be23a847e706ac5e7827e273fad1baff63eb5f68424efac7f596b5471f9a"
    $a12="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a13="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a14="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a15="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a16="dcb22c52c5e8f8cfe975565f5397b4dd7d6b786fd378eafbf93825820b45e53f49056bbe5a7380db128f150815dc5e84"
    $a17="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_512_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="bb0dfb861aaa288bdc3e61b86311c7d98c8b8ab2b4e603e8868f2b22485655eb7faff92021c8bb2d88dc99c028309e7ba2313817c0fdff46b49c5ead46d5161e"
    $a3="8143d62fff557e3c37e15a7e7e1be8dd031401cd55da9ca74237e70f8c9d0f20bad8a2af7b22986e56ee6a704ee365f79f83fe7fbfe0c359d7caecc8030f6af5"
    $a4="465af57d67bc6c4e26c1a5a1e30ccf6f01e5f995dfb90e831738bc15e8f46acf2cbf814b9f835234dd30eb3f902013e51b9f0bd770d0c792cc55b5c2b916d0be"
    $a5="736eb3ca25c23ad0861cd1b5676b8b2eb2aeef20d38a63edee2c56cff4b8582da93314a9be1bb60760ceb989026e9e01ac2458be97dff16e208e932b7110ffa5"
    $a6="ac45cdffe5f1a2fc06b930dfb2a99b26682e04e2228da715d7f464eb4e06d7a9985ae7d667f6cd8ed96576de78aa4121445fec3efc2c1e97b6cdbb77d7b84ec4"
    $a7="736eb3ca25c23ad0861cd1b5676b8b2eb2aeef20d38a63edee2c56cff4b8582da93314a9be1bb60760ceb989026e9e01ac2458be97dff16e208e932b7110ffa5"
    $a8="8e8bcc6d85575a8f0dfac2cb0e3eb28abff83f81d14304d260ed87ecb4bc046f94b55e7b485d6e88978e9b5ff167c726ff7c11e4c451ac0778fb8c5188d34e6c"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="d887a0e79eb31a236584b5fbc521b86fb5fd317e9d5b381844d65da4e4f318bd354699208fd8f155f70e471e9a5048b815292fdc1f8b772d37410049a9cd1d89"
    $a11="6884d4025cc74257c32e357331c3c876da1609b7009d612d0da5197881e101efceaba542ea7fe1d216d3886a972723ad3cda8865585c29bba6711ceaa23a9525"
    $a12="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a13="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a14="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a15="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a16="a5c2b610ebdb37ccd67781dbef1f802d70477c14ea2862a0a47a0de8c59eefd6b0d52e7775f5b454583fdcc8b3f8ac5bcace2037da7f7fd1ba03286069a701a7"
    $a17="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule base64_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9vdA=="
    $a1="cGFzc3dvcmQ="
    $a2="SEVMTE8="
    $a3="T1AuT1BFUkFUT1I="
    $a4="TUdS"
    $a5="SVRGMzAwMA=="
    $a6="TUdS"
    $a7="TkVUQkFTRQ=="
    $a8="YWRtaW4="
    $a9="aXNlZQ=="
    $a10="RmFjdG9yeQ=="
    $a11="NTY3ODk="
    $a12="QWRtaW5pc3RyYXRvcg=="
    $a13="YWRtaW4="
    $a14="YWRtaW4="
    $a15="YWRtaW4="
    $a16="YWRtaW4="
    $a17="IWFkbWlu"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

