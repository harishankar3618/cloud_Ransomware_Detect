/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_apache
{
    meta:
        id = "UJtyHGJZEXOGAOyYb2Km3"
        fingerprint = "252f68a24414d2e87ecfdae24023e390e85bfafefa337feda4bd5ff7b6cc4302"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ead38134b84c88f62c68b60521fccd5"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="1e0154a9860f303dab543376a058676b"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="2455f99b8add81043a8b3e54684a22e7"
    $a7="4f3cc040ba06cc0a79df1189b75cc24b"
    $a8="d8ce5e0233e3e6aa0fff4040bebc8231"
    $a9="d8ce5e0233e3e6aa0fff4040bebc8231"
    $a10="2455f99b8add81043a8b3e54684a22e7"
    $a11="329153f560eb329c0e1deea55e88a1e9"
    $a12="329153f560eb329c0e1deea55e88a1e9"
    $a13="329153f560eb329c0e1deea55e88a1e9"
    $a14="2455f99b8add81043a8b3e54684a22e7"
    $a15="1e0154a9860f303dab543376a058676b"
    $a16="1e0154a9860f303dab543376a058676b"
    $a17="1e0154a9860f303dab543376a058676b"
    $a18="1e0154a9860f303dab543376a058676b"
    $a19="a09f29e47e8e45492e84a54855598485"
    $a20="1e0154a9860f303dab543376a058676b"
    $a21="d8ce5e0233e3e6aa0fff4040bebc8231"
    $a22="0ec6d486dec1f4e3d8333e24e07330b9"
    $a23="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule mysql323_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="016537a06c496eaa"
    $a1="43e9a4ab75570f5b"
    $a2="43e9a4ab75570f5b"
    $a3="43e9a4ab75570f5b"
    $a4="22e3be3e311d37ea"
    $a5="43e9a4ab75570f5b"
    $a6="65df5fc82365a505"
    $a7="674257506a0ff8e8"
    $a8="2515f02914fd1111"
    $a9="2515f02914fd1111"
    $a10="65df5fc82365a505"
    $a11="67457e226a1a15bd"
    $a12="67457e226a1a15bd"
    $a13="67457e226a1a15bd"
    $a14="65df5fc82365a505"
    $a15="22e3be3e311d37ea"
    $a16="22e3be3e311d37ea"
    $a17="22e3be3e311d37ea"
    $a18="22e3be3e311d37ea"
    $a19="1a204533660f1fc3"
    $a20="22e3be3e311d37ea"
    $a21="2515f02914fd1111"
    $a22="10804243026ede9e"
    $a23="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule mysql41_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6F0ED9E61F43CBF6647418D70A97A149338FEBD8"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*BC76B32594D63CEE07D4144CBFD349B88E2FDBBB"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*C890DD6B4A77DC26B05EB1EE1E458A3E374D3E5B"
    $a7="*960E463B2897909631E12148F23D4F058F2F3D87"
    $a8="*6A098B711D62610701289A2D425BEB8D83E390A0"
    $a9="*6A098B711D62610701289A2D425BEB8D83E390A0"
    $a10="*C890DD6B4A77DC26B05EB1EE1E458A3E374D3E5B"
    $a11="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a12="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a13="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a14="*C890DD6B4A77DC26B05EB1EE1E458A3E374D3E5B"
    $a15="*BC76B32594D63CEE07D4144CBFD349B88E2FDBBB"
    $a16="*BC76B32594D63CEE07D4144CBFD349B88E2FDBBB"
    $a17="*BC76B32594D63CEE07D4144CBFD349B88E2FDBBB"
    $a18="*BC76B32594D63CEE07D4144CBFD349B88E2FDBBB"
    $a19="*3D7E355454A7687A99146E9C293F4625E5BD89A9"
    $a20="*BC76B32594D63CEE07D4144CBFD349B88E2FDBBB"
    $a21="*6A098B711D62610701289A2D425BEB8D83E390A0"
    $a22="*05E8C43F4F09A918A77C8CE2113518C220985751"
    $a23="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule ldap_md5_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}4cdZrdC/qII4ehvFazHo5A=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}klrSZ5sJWBbPwM93L0ZyKQ=="
    $a7="{MD5}KafpZGe2mp9akzMuKemw3g=="
    $a8="{MD5}MbhktVRpE92SiklBahC60Q=="
    $a9="{MD5}MbhktVRpE92SiklBahC60Q=="
    $a10="{MD5}klrSZ5sJWBbPwM93L0ZyKQ=="
    $a11="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a12="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a13="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a14="{MD5}klrSZ5sJWBbPwM93L0ZyKQ=="
    $a15="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a16="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a17="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a18="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a19="{MD5}9ss+gWSWUo1Bh9tTvGZWfw=="
    $a20="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a21="{MD5}MbhktVRpE92SiklBahC60Q=="
    $a22="{MD5}cUs5P0ssKVYdRMXgqQ/9uQ=="
    $a23="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule ldap_sha1_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}RPTybnrJpO8exuh9+S4dzye6tzg="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}zbDnbBpphzy9zb4KFC1WwCPcnyI="
    $a7="{SHA}jcpGQo0AWi9MLgOfslCWTWE5qLI="
    $a8="{SHA}kbGlNpWQurEABm4cg+IxehrbKnY="
    $a9="{SHA}kbGlNpWQurEABm4cg+IxehrbKnY="
    $a10="{SHA}zbDnbBpphzy9zb4KFC1WwCPcnyI="
    $a11="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a12="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a13="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a14="{SHA}zbDnbBpphzy9zb4KFC1WwCPcnyI="
    $a15="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a16="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a17="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a18="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a19="{SHA}/Dmxjyh9i7+s6uAg9KTrMqxcHnA="
    $a20="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a21="{SHA}kbGlNpWQurEABm4cg+IxehrbKnY="
    $a22="{SHA}81JJrcoRYD8yKScs/j9slaGuCP8="
    $a23="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule md5_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e1c759add0bfa882387a1bc56b31e8e4"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="1b359d8753858b55befa0441067aaed3"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="925ad2679b095816cfc0cf772f467229"
    $a7="29a7e96467b69a9f5a93332e29e9b0de"
    $a8="31b864b5546913dd928a49416a10bad1"
    $a9="31b864b5546913dd928a49416a10bad1"
    $a10="925ad2679b095816cfc0cf772f467229"
    $a11="63a9f0ea7bb98050796b649e85481845"
    $a12="63a9f0ea7bb98050796b649e85481845"
    $a13="63a9f0ea7bb98050796b649e85481845"
    $a14="925ad2679b095816cfc0cf772f467229"
    $a15="1b359d8753858b55befa0441067aaed3"
    $a16="1b359d8753858b55befa0441067aaed3"
    $a17="1b359d8753858b55befa0441067aaed3"
    $a18="1b359d8753858b55befa0441067aaed3"
    $a19="f6cb3e816496528d4187db53bc66567f"
    $a20="1b359d8753858b55befa0441067aaed3"
    $a21="31b864b5546913dd928a49416a10bad1"
    $a22="714b393f4b2c29561d44c5e0a90ffdb9"
    $a23="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha1_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44f4f26e7ac9a4ef1ec6e87df92e1dcf27bab738"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="cdb0e76c1a69873cbdcdbe0a142d56c023dc9f22"
    $a7="8dca46428d005a2f4c2e039fb250964d6139a8b2"
    $a8="91b1a5369590bab100066e1c83e2317a1adb2a76"
    $a9="91b1a5369590bab100066e1c83e2317a1adb2a76"
    $a10="cdb0e76c1a69873cbdcdbe0a142d56c023dc9f22"
    $a11="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a12="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a13="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a14="cdb0e76c1a69873cbdcdbe0a142d56c023dc9f22"
    $a15="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a16="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a17="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a18="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a19="fc39b18f287d8bbfaceae020f4a4eb32ac5c1e70"
    $a20="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a21="91b1a5369590bab100066e1c83e2317a1adb2a76"
    $a22="f35249adca11603f3229272cfe3f6c95a1ae08ff"
    $a23="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha384_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e59dc20e2eeb258a8347a590a2e40be973fc018899a47190925c5dd88bab783e8017d201e4f8fb3dffc8489c81787b7d"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="06398a1556e8b7890d09872506ba5bd4f262cb8f21b244f792d5511e4e9d73e8e7de8ceef7fa497b730b0d7a4b24c3d1"
    $a7="b4a85c5c35a16d6e36c16b21834b1b21c68a263499fc3092ff27c1ca1a2a5c88d0344b31130a03b8b74317754cf2d9aa"
    $a8="a490369260a3a7c150bb597583110c7f0c8c99812ea4ca73760920b8ff18a7c3f9943d3c3203cc13cea0a19fc222d0e6"
    $a9="a490369260a3a7c150bb597583110c7f0c8c99812ea4ca73760920b8ff18a7c3f9943d3c3203cc13cea0a19fc222d0e6"
    $a10="06398a1556e8b7890d09872506ba5bd4f262cb8f21b244f792d5511e4e9d73e8e7de8ceef7fa497b730b0d7a4b24c3d1"
    $a11="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a12="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a13="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a14="06398a1556e8b7890d09872506ba5bd4f262cb8f21b244f792d5511e4e9d73e8e7de8ceef7fa497b730b0d7a4b24c3d1"
    $a15="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a16="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a17="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a18="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a19="6f9e97f59673406a33ebfe62c041d77c782ffc3187b90d0d7d9523be81e2430250d2753eb2d6bdf94e0a96414ee0d76e"
    $a20="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a21="a490369260a3a7c150bb597583110c7f0c8c99812ea4ca73760920b8ff18a7c3f9943d3c3203cc13cea0a19fc222d0e6"
    $a22="c849e711ad8b1bed6e23bb4cac212e4bd8b4ff3a9a3fbcece8525b783e3cc0821c2011ac8cd939a27a098480a28aef14"
    $a23="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha224_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7b6d21913933d111b7d38a6f2554e86b76d128acc15a588310f0f15"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="4f262d752cac96a9ada895719bb1ffc3c0e916c16fff93db5e716b7c"
    $a7="81dab7300100a9e496e95d1194690fe14401c3ae8dae4b1f79addf23"
    $a8="d61b015e13032015cf9630b6d4d156bd163b33865c5630653976b965"
    $a9="d61b015e13032015cf9630b6d4d156bd163b33865c5630653976b965"
    $a10="4f262d752cac96a9ada895719bb1ffc3c0e916c16fff93db5e716b7c"
    $a11="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a12="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a13="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a14="4f262d752cac96a9ada895719bb1ffc3c0e916c16fff93db5e716b7c"
    $a15="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a16="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a17="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a18="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a19="b8af66a764892e747457a74abb87bee75c0818f70c364c72e1e51ee2"
    $a20="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a21="d61b015e13032015cf9630b6d4d156bd163b33865c5630653976b965"
    $a22="4289543e5f9bb50dfbed9a8ce4fd47d2b9d5a8af87d46b9eae6dad0f"
    $a23="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha512_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12e56030fa27a05d2576a19fe7ad93812cc18a5b25cf8d24c87be64dbf8bc27b44f0890e7dae2ae21dcb2a6fa2b942cedc448c1fefd58db7dd84b93a22285c8b"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="3f9c78835c19cd6ebf0cc32f889002a38df51cda21bc8a1c063ba380c223dfbdd4934a7f723b38041f4cb4b44ab90b711e6feed23241241de47a1cc72e430e25"
    $a7="1d10da3967b0efd570cdee10a68a8eb08fbbce0985e838fa82e8f24cd439c308649b550e9e843ed2aa478b903b00ac8d5f28b97db7ed3ee1d0ea06274e86e9fa"
    $a8="baffb97f439eead41b57785cc3fd39c30d4c3e8794828f468875bc2c9f89deba60721a2b758176fda4b014c7e704150e95901ea3f8c233dc4ba3cdd8788ea974"
    $a9="baffb97f439eead41b57785cc3fd39c30d4c3e8794828f468875bc2c9f89deba60721a2b758176fda4b014c7e704150e95901ea3f8c233dc4ba3cdd8788ea974"
    $a10="3f9c78835c19cd6ebf0cc32f889002a38df51cda21bc8a1c063ba380c223dfbdd4934a7f723b38041f4cb4b44ab90b711e6feed23241241de47a1cc72e430e25"
    $a11="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a12="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a13="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a14="3f9c78835c19cd6ebf0cc32f889002a38df51cda21bc8a1c063ba380c223dfbdd4934a7f723b38041f4cb4b44ab90b711e6feed23241241de47a1cc72e430e25"
    $a15="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a16="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a17="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a18="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a19="c07be648d2567a2f9f2f4111480bfcc72cba9f216e52502f6d7521825781bd0ad18322e38f0b56593802665be05584dcaeb7803f3cebf7eabe494e65ebdabe3f"
    $a20="dbfb11615e2c89588580cc564adad47794662d667bf92e47e14a493b4935ce171fde035e2799a22fa388a0e0e163afaaf6a6605d288ef2b631df38ca8916fd02"
    $a21="baffb97f439eead41b57785cc3fd39c30d4c3e8794828f468875bc2c9f89deba60721a2b758176fda4b014c7e704150e95901ea3f8c233dc4ba3cdd8788ea974"
    $a22="277ae7881360f9b763d0ad7d591b7d3d40f3477845db64001eeec1dd01ff6f54a91a4092ee90c300cebabdac73c46f11ab7175de1d1eb6579789ffedd48b8ef5"
    $a23="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha256_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56c38f358879bb1795ed9207167936d94710eee6d6380798ec62c9d10e40ec01"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="62f196fe59c6f78d7f332ae80f55e6e869d8e7fbc589855b5a1a21b9249408ca"
    $a7="4b168d88dc872a7753c2bc35b36a2d4249487af55baf78f247f38cae2fe962da"
    $a8="07ffa23817eb0c999f8e126a39db481e61fe4cd14a47b700ddf8c9b31718f912"
    $a9="07ffa23817eb0c999f8e126a39db481e61fe4cd14a47b700ddf8c9b31718f912"
    $a10="62f196fe59c6f78d7f332ae80f55e6e869d8e7fbc589855b5a1a21b9249408ca"
    $a11="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a12="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a13="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a14="62f196fe59c6f78d7f332ae80f55e6e869d8e7fbc589855b5a1a21b9249408ca"
    $a15="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a16="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a17="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a18="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a19="ff7772053abf7d817d6eec229a09e14f0d1552f1cb0aeedb2ac73784ac2d2e39"
    $a20="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a21="07ffa23817eb0c999f8e126a39db481e61fe4cd14a47b700ddf8c9b31718f912"
    $a22="51352afa310882a95a923680d65d44fd33fb1468849914882b474273ddf506c9"
    $a23="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2b_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18f12f5c1a56ccdfda8d9b94593dfd95933277247e65293e4a415a2b4d554920f46e1022d13e0b06df11d44558e424976e30a6f2eecb23513b72a2c35c5da540"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="3f54213631a128a35fe7e3db6caaad1fd3ce615bcfa681fcd223f455cffeb7a553bfa5cd8a6c8d2bf087c94b600fc72e76972282af2de24e6ef9a70c88a283d3"
    $a7="56135c23154561911ab76716e839d99ff7bc440bfa17317632bda26498c66612d72d65dd4c37c8b5b8998ba9c1ca5ced5c812f9e269fb655dae2251ad8b93800"
    $a8="9578fb2c4c1889028b0f2685c1a1001c37589dfb2198c6f09c7fd2ad0de7ffc77440cc529beb502c925789bd01325c96065adf46f630e8a0213fa69418e505cc"
    $a9="9578fb2c4c1889028b0f2685c1a1001c37589dfb2198c6f09c7fd2ad0de7ffc77440cc529beb502c925789bd01325c96065adf46f630e8a0213fa69418e505cc"
    $a10="3f54213631a128a35fe7e3db6caaad1fd3ce615bcfa681fcd223f455cffeb7a553bfa5cd8a6c8d2bf087c94b600fc72e76972282af2de24e6ef9a70c88a283d3"
    $a11="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a12="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a13="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a14="3f54213631a128a35fe7e3db6caaad1fd3ce615bcfa681fcd223f455cffeb7a553bfa5cd8a6c8d2bf087c94b600fc72e76972282af2de24e6ef9a70c88a283d3"
    $a15="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a16="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a17="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a18="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a19="b5c0a1fb41ff07364f22cd7b2ef91593d568dcd262c1085f9ff62f2fa353d1f47cd760a24a1aac67f6c17bb453b7f54495058cd0c6277086ef5841a7cf7f5f6f"
    $a20="079ecd5104845415dc3618be63202470f82c2b3e323535d5ce98fa37b89dae3cedbc9715f1172749b3b5210743fec7f7db0eb8ec8e768d16663f092cb4501b32"
    $a21="9578fb2c4c1889028b0f2685c1a1001c37589dfb2198c6f09c7fd2ad0de7ffc77440cc529beb502c925789bd01325c96065adf46f630e8a0213fa69418e505cc"
    $a22="ad90c64d728bd62d04b5903c2d4f1a0ec3fbc685905f80c234b617843748729e4877c4ce57b59e391cd60d43001c405b8a9628af327f220320c5165b1fee8cb6"
    $a23="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2s_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3316201dbb4e7f02221ac4d3a884b1807e10ef8c799f21f6db4e46fc8ad668f9"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="5211573598417a43a6cc4faffbe9eecc5e1588a7a26b7068cc6a3bed4d2f1647"
    $a7="caeb6513252c04f10b19e00da9f5942a05f888c15793bfe513194f3ec22f034b"
    $a8="27f8b4c1066188eb30730d02a4f8107738f6a25b43ea0b1e973f0cd5820c7bf5"
    $a9="27f8b4c1066188eb30730d02a4f8107738f6a25b43ea0b1e973f0cd5820c7bf5"
    $a10="5211573598417a43a6cc4faffbe9eecc5e1588a7a26b7068cc6a3bed4d2f1647"
    $a11="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a12="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a13="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a14="5211573598417a43a6cc4faffbe9eecc5e1588a7a26b7068cc6a3bed4d2f1647"
    $a15="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a16="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a17="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a18="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a19="b247485de967c91c22381477ffd22f6d6a47d17840838f9bc82d59ce194ee86b"
    $a20="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a21="27f8b4c1066188eb30730d02a4f8107738f6a25b43ea0b1e973f0cd5820c7bf5"
    $a22="884b1ebe0f69d6c8963abec594114c57dcb5eef5570cbce561fe52131d82e7aa"
    $a23="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_224_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d8e7588707fba48daee7d5c84183abba58d4f50c6e15088642f010f"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="ed42fc69ab147f031e6e8dd087c0a6fcb5b85a09629d74d265759807"
    $a7="3de8fdca6bf5a52ee0ab0c0245531ffae08c7d3e758cec41cd919cac"
    $a8="6d83e0f1cd0affb9f25b7e774dae50debaddaf4fdaaf34ad317a0b3b"
    $a9="6d83e0f1cd0affb9f25b7e774dae50debaddaf4fdaaf34ad317a0b3b"
    $a10="ed42fc69ab147f031e6e8dd087c0a6fcb5b85a09629d74d265759807"
    $a11="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a12="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a13="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a14="ed42fc69ab147f031e6e8dd087c0a6fcb5b85a09629d74d265759807"
    $a15="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a16="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a17="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a18="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a19="ad46837af4f88a6dac6ebe92cd110b90db1f097a90408c319d4f29e0"
    $a20="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a21="6d83e0f1cd0affb9f25b7e774dae50debaddaf4fdaaf34ad317a0b3b"
    $a22="31565b1d31eafd54b573745efeae3b76f95ada17305cb7e21d0c2450"
    $a23="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_256_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4dc8b05b12cd3c49153ec4ab9f8181be5320719e24e2e8f15ef90d3a9912221b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="df6c9c0063d293b2b582b84e6f3c993a4cc358f6cf049d06ec19e00a95059690"
    $a7="78a5fe483b9c1de67f7342ce57fb58e17ce69c949d8ff857e2cc531c323d61bc"
    $a8="dac10a69404388ad62ac4485b200db1e14d043e7a8d2c128ae69c2c1de068f5b"
    $a9="dac10a69404388ad62ac4485b200db1e14d043e7a8d2c128ae69c2c1de068f5b"
    $a10="df6c9c0063d293b2b582b84e6f3c993a4cc358f6cf049d06ec19e00a95059690"
    $a11="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a12="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a13="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a14="df6c9c0063d293b2b582b84e6f3c993a4cc358f6cf049d06ec19e00a95059690"
    $a15="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a16="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a17="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a18="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a19="cc46ba5c3e77e1b482801597d5d672d8e2e7bb01228c8faa44110b3d6189aac1"
    $a20="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a21="dac10a69404388ad62ac4485b200db1e14d043e7a8d2c128ae69c2c1de068f5b"
    $a22="4cfc76b600f6959e2a215fc5c54330e22f698050841e21b90c4088ca30f164f0"
    $a23="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_384_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fbea380be13719486a2bf0e03a60152bc75d89e7c3e9ac25397af9cdb54fd75294ace3b5402452f1e6a02070c71dd2f7"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="435f09fa12c71aac27c792a47a224b24f5affe8b99b3b183e26bbea0802179e9b7c96c24aa2fd9fd93d359a2f801fb87"
    $a7="ac99676e05cf6a08437d21843ea0824dbe23e8a1e399b04bbb21d4a2ca04f3bcc1eb70356f8251702c4cb75ce74b732a"
    $a8="2e3919ec48ad5159368a56e09764a055dffd3371d8b1505058d2870fd6254f22c85ef6fa2d02084b6b74db20e74ace4b"
    $a9="2e3919ec48ad5159368a56e09764a055dffd3371d8b1505058d2870fd6254f22c85ef6fa2d02084b6b74db20e74ace4b"
    $a10="435f09fa12c71aac27c792a47a224b24f5affe8b99b3b183e26bbea0802179e9b7c96c24aa2fd9fd93d359a2f801fb87"
    $a11="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a12="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a13="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a14="435f09fa12c71aac27c792a47a224b24f5affe8b99b3b183e26bbea0802179e9b7c96c24aa2fd9fd93d359a2f801fb87"
    $a15="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a16="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a17="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a18="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a19="a1f5255687bf673ce2b0274732b948132c9e2795ace12b986c5ca721bc80c4283ba6edf00b620c887abe4220d5d57def"
    $a20="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a21="2e3919ec48ad5159368a56e09764a055dffd3371d8b1505058d2870fd6254f22c85ef6fa2d02084b6b74db20e74ace4b"
    $a22="60b3eef0d556ad8db1b1911e337527ae834b29f518a447088c72c4bcc515892f7b1e01a3746b0eb091fa78f797007bab"
    $a23="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_512_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53c1261f538e5549dbd4a7e6a517bf4d4c9b376ef37c9d1f21a8e2b8442293cb25caa679c8340afb3eedf6ffd95b67f6f513041e60f4688d8be2c9cfe00a8a12"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="0096acfe21d72e5b3e141d5a49068288b1926882b06ecfeae7d86c260bdc83371ad93175dea3d3ba01846e8acc3eb5bbc61d1cf5ba75fa9acef42c22946f9228"
    $a7="acbc23336b1e3c84f06eccd8fc0ecf0a9d470570559965c24038948e7a873b3f03208e509f22120098396e7fc3aeb26d4400471c536f7bd670fd2a9bcb3987c8"
    $a8="e41c62cf3ce76d6755bef884a70f2c805530dcb475aa46d38e3b7a5bb9437fcf9f10f0e5dcaf0d372af8a803079f1f55fe5415c5c3ebdda99d730949800de3a0"
    $a9="e41c62cf3ce76d6755bef884a70f2c805530dcb475aa46d38e3b7a5bb9437fcf9f10f0e5dcaf0d372af8a803079f1f55fe5415c5c3ebdda99d730949800de3a0"
    $a10="0096acfe21d72e5b3e141d5a49068288b1926882b06ecfeae7d86c260bdc83371ad93175dea3d3ba01846e8acc3eb5bbc61d1cf5ba75fa9acef42c22946f9228"
    $a11="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a12="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a13="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a14="0096acfe21d72e5b3e141d5a49068288b1926882b06ecfeae7d86c260bdc83371ad93175dea3d3ba01846e8acc3eb5bbc61d1cf5ba75fa9acef42c22946f9228"
    $a15="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a16="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a17="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a18="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a19="214792f4d4eef8c51da4491670ae8bbfd1ddce01cac0b04e0f216fa49997e199b24cf15903a548705ddf18dd489994ecc7e5f4b4f235a5a60192f7bc9ae45552"
    $a20="c88285cd2d822ce855c61d9028b33255bf4db6542b9ffd442865b75576a4c7dbd44c1d3607eb7a74c909958fb14acf3d6581dbd1dee340077e25fab39bd8c6b1"
    $a21="e41c62cf3ce76d6755bef884a70f2c805530dcb475aa46d38e3b7a5bb9437fcf9f10f0e5dcaf0d372af8a803079f1f55fe5415c5c3ebdda99d730949800de3a0"
    $a22="12abcaefa70d2aafa25bde31d10ec1da1f651162ef56a7d72ca6f5b980287190fe2c9fdc9323fa340148d0972623b20d35129d731251067a53ded768353376dd"
    $a23="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule base64_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="ajVCcm45"
    $a2="YWRtaW4="
    $a3="YWRtaW4="
    $a4="YWRtaW4="
    $a5="dG9tY2F0"
    $a6="cm9sZQ=="
    $a7="Y2hhbmdldGhpcw=="
    $a8="cm9sZTE="
    $a9="cm9sZTE="
    $a10="cm9vdA=="
    $a11="Y2hhbmdldGhpcw=="
    $a12="cm9vdA=="
    $a13="cm9vdA=="
    $a14="dG9tY2F0"
    $a15="Y2hhbmdldGhpcw=="
    $a16="dG9tY2F0"
    $a17="dG9tY2F0"
    $a18="Ym90aA=="
    $a19="dG9tY2F0"
    $a20="cm9sZTE="
    $a21="dG9tY2F0"
    $a22="YWRtaW4="
    $a23="amJvc3M0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

