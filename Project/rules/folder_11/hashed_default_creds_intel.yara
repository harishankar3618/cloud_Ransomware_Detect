/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_intel
{
    meta:
        id = "5sX9EdEUKLCJDPlXuqBYCG"
        fingerprint = "7918f213ce23d7d10caf899cf472429a2d1205070ef83f5314227d7df4b3bc09"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6aebf95ee750d35a58d279ad1fbf32b"
    $a1="e6aebf95ee750d35a58d279ad1fbf32b"
    $a2="1ff6c0516b6474949b991080492769c9"
    $a3="1ff6c0516b6474949b991080492769c9"
    $a4="4a946b221b3685ed1b0047d379173cda"
    $a5="4a946b221b3685ed1b0047d379173cda"
    $a6="209c6174da490caeb422f3fa5a7ae634"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="d334ac74f9e3de9750e64b6583af424d"
    $a9="c64157f52f567fe73b7f09a54d83e323"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql323_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d89770b0d299d60"
    $a1="3d89770b0d299d60"
    $a2="513370a2428dc17d"
    $a3="513370a2428dc17d"
    $a4="0c116ea61d0001b4"
    $a5="0c116ea61d0001b4"
    $a6="43e9a4ab75570f5b"
    $a7="67457e226a1a15bd"
    $a8="4690821c3b6058da"
    $a9="428aa52c3f8f41e1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql41_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*18ED90460331B8E9FC796D9FF923A720D3EF8592"
    $a1="*18ED90460331B8E9FC796D9FF923A720D3EF8592"
    $a2="*64A2D91B7CD940EFDEBD95314E10E165FC97CFFA"
    $a3="*64A2D91B7CD940EFDEBD95314E10E165FC97CFFA"
    $a4="*D361459A995F83C86EA7AD92FB445BDC09E18AC6"
    $a5="*D361459A995F83C86EA7AD92FB445BDC09E18AC6"
    $a6="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a8="*868BAED7EAE3307F093BA0D88BE017C1A457EB19"
    $a9="*71A423EE610B82E6695F355B08DD252520BF3E0A"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_md5_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}oPhIlCzoY89TwPpsxoQAfQ=="
    $a1="{MD5}oPhIlCzoY89TwPpsxoQAfQ=="
    $a2="{MD5}ZEOL5lGrsNMh9yj4/9t1xQ=="
    $a3="{MD5}ZEOL5lGrsNMh9yj4/9t1xQ=="
    $a4="{MD5}Tlu66vyCq3qhOFvqjvXTCg=="
    $a5="{MD5}Tlu66vyCq3qhOFvqjvXTCg=="
    $a6="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a7="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a8="{MD5}sSO8CecsFdheyQ4fGty9gA=="
    $a9="{MD5}npX215eYe32g+yk6dg/lfg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_sha1_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}gEN6RKZh0UEXQgkRnVQSWlmmSyo="
    $a1="{SHA}gEN6RKZh0UEXQgkRnVQSWlmmSyo="
    $a2="{SHA}buPCkHsxHwTv7Nn3NSkYqXCk/g0="
    $a3="{SHA}buPCkHsxHwTv7Nn3NSkYqXCk/g0="
    $a4="{SHA}7s3dENe9h9PXZb9lUEYFEXwC6i4="
    $a5="{SHA}7s3dENe9h9PXZb9lUEYFEXwC6i4="
    $a6="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a8="{SHA}LITXpMlsPXb3srIYYau17DlCP20="
    $a9="{SHA}66CC/0VRfAa9Nlwv3h/HfNp6j28="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule md5_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a0f848942ce863cf53c0fa6cc684007d"
    $a1="a0f848942ce863cf53c0fa6cc684007d"
    $a2="64438be651abb0d321f728f8ffdb75c5"
    $a3="64438be651abb0d321f728f8ffdb75c5"
    $a4="4e5bbaeafc82ab7aa1385bea8ef5d30a"
    $a5="4e5bbaeafc82ab7aa1385bea8ef5d30a"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="63a9f0ea7bb98050796b649e85481845"
    $a8="b123bc09e72c15d85ec90e1f1adcbd80"
    $a9="9e95f6d797987b7da0fb293a760fe57e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80437a44a661d141174209119d54125a59a64b2a"
    $a1="80437a44a661d141174209119d54125a59a64b2a"
    $a2="6ee3c2907b311f04efecd9f7352918a970a4fe0d"
    $a3="6ee3c2907b311f04efecd9f7352918a970a4fe0d"
    $a4="eecddd10d7bd87d3d765bf65504605117c02ea2e"
    $a5="eecddd10d7bd87d3d765bf65504605117c02ea2e"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="2c84d7a4c96c3d76f7b2b21861abb5ec39423f6d"
    $a9="eba082ff45517c06bd365c2fde1fc77cda7a8f6f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a1="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a2="3d7c953602338bb1e6a178791c0f9aad85184e41481c5dbcc36687ac3b1b946d9a87e9b247309bcbe76c825871a551cd"
    $a3="3d7c953602338bb1e6a178791c0f9aad85184e41481c5dbcc36687ac3b1b946d9a87e9b247309bcbe76c825871a551cd"
    $a4="c901c28c86086170664e7f141cee6c27274093935d179003f14dc73f282f96da5ed0ad5609c68d035a12ea2f7ebb1b68"
    $a5="c901c28c86086170664e7f141cee6c27274093935d179003f14dc73f282f96da5ed0ad5609c68d035a12ea2f7ebb1b68"
    $a6="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a7="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a8="eaa2adcd989acbb07569f45d3175b6c04619ffcedb57b01d741b171364c530f76972a0fc915f1a6929833a6f55df2015"
    $a9="fba4a3defbe0652995f93f9d8be36443b67d1d959f31f6c9cfcb95f75efd14a0a0f2e67651ec90a3adb7ee7e47aa7c9d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a1="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a2="a2f3de94b2cdb6e42bccdbddb2a49b9044d5a99d5c850a2f2d1ec4be"
    $a3="a2f3de94b2cdb6e42bccdbddb2a49b9044d5a99d5c850a2f2d1ec4be"
    $a4="6eaa7e19d383862d4e6fab499b0ebf952b1ff87fb6db646f53d36d63"
    $a5="6eaa7e19d383862d4e6fab499b0ebf952b1ff87fb6db646f53d36d63"
    $a6="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a8="4676d443ce4e95237fb5ac3e499bcbc18316d1232a9aeec234ce9f92"
    $a9="8c1cc174e604952e5354221d4c6294b63059e873daf690b2cc88a481"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a1="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a2="07a31c3f230c522b53af20859631a510635ec7e75e107f29298d5f05a988a4c7905d06edfa155ae57162a72fd7cf7ac9c1dffa658a18e8529ece6d3efb0fb05a"
    $a3="07a31c3f230c522b53af20859631a510635ec7e75e107f29298d5f05a988a4c7905d06edfa155ae57162a72fd7cf7ac9c1dffa658a18e8529ece6d3efb0fb05a"
    $a4="5a738c9b375511f3219c3b866b10a3aa787dd69d259d756926b5fe6d6ced540cb6671db78b429b14542f89616367c3a4b553c28249ddbf7a5a283dd8db4399aa"
    $a5="5a738c9b375511f3219c3b866b10a3aa787dd69d259d756926b5fe6d6ced540cb6671db78b429b14542f89616367c3a4b553c28249ddbf7a5a283dd8db4399aa"
    $a6="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a8="a5d335fa30ced7505dba4e2c87196c752dc9c6395b03fdfa1097378ede971ce78a0ee4709b75a2a625b74da29952fc01997ac61d619b29216330030094011b69"
    $a9="6d9aceb1053bed5fca83b3fe6bdbb38389f2d952631668e2447615dd1e3100f49445060216879540f96e99b444715e0e2b84075e2dec6d2720c81acd3551676c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a1="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a2="2d0ab8eb2fb9d408d646c1375f788b31b8b5030b5d5052f52d42cd8c375e8e68"
    $a3="2d0ab8eb2fb9d408d646c1375f788b31b8b5030b5d5052f52d42cd8c375e8e68"
    $a4="96eebba49dbbf422d245f02290f9d4ed0eb02da9daa6bbceefb162800ff42481"
    $a5="96eebba49dbbf422d245f02290f9d4ed0eb02da9daa6bbceefb162800ff42481"
    $a6="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a8="1c9aeebe6972c1fed27aae8896682b01cd3a1f035405f59b3702d8c5c90f5857"
    $a9="1ef393f2c0772064cae9403f23e7f8fc6d49bb2939f463f23c4e637231e84da4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a1="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a2="ff54c248b22fe064ec7b2affef94d665a565fb42237cfb86e2faf029ab2bba0bbda8a67c7de04c4ca90bc8016e7afa96e9d8522ad4e572ef308fc98df80689d2"
    $a3="ff54c248b22fe064ec7b2affef94d665a565fb42237cfb86e2faf029ab2bba0bbda8a67c7de04c4ca90bc8016e7afa96e9d8522ad4e572ef308fc98df80689d2"
    $a4="095d371fbfeafb14db15d7875d19eac6a9b33389d79981669b888632d19d3abaa257cc5f00e836e614948735a3b63f2acd91ad6ce441ee8a0a25e0a50f7bd286"
    $a5="095d371fbfeafb14db15d7875d19eac6a9b33389d79981669b888632d19d3abaa257cc5f00e836e614948735a3b63f2acd91ad6ce441ee8a0a25e0a50f7bd286"
    $a6="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a8="caecd7a0664919ab04a5dba41f0c7e43fc339feb003acd177dcda8bfacbee3fc8a2a570d28a7b072f85fe35b6b5c69380c631befecca190bc52aa9ea83c766b9"
    $a9="42a2aa7db9e0866c30bf5765c025781ff1aa2dd444c0a3c3bf175ee7ec604d0ca47a860ac0310deaeb97da88a6657e09c11002884fc188e1117e599e185643a3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a1="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a2="a9ffe918d233b301489e98159551a7ead6fa05a96a3148c1ac998aec9ac4dd7d"
    $a3="a9ffe918d233b301489e98159551a7ead6fa05a96a3148c1ac998aec9ac4dd7d"
    $a4="200fbc796d214e93d09679b5547e73badd85b1a31f2d21262aea7f82bb654208"
    $a5="200fbc796d214e93d09679b5547e73badd85b1a31f2d21262aea7f82bb654208"
    $a6="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a7="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a8="5117f649a9ea85aa30f5aee09a0350b3276dcd11cff0f372f96f321ca3536dfc"
    $a9="5966fc4f2b086214ecfbbe85022bd4f06e8c38a60fb3120ea219a29165ded62c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a1="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a2="55c9a58ca4eb087e81629c41e4eff494ee391919138d7f26530dc03c"
    $a3="55c9a58ca4eb087e81629c41e4eff494ee391919138d7f26530dc03c"
    $a4="319ab48e6fdd5134a5381dbe1d85ae88df203f87993aab3708cfdf28"
    $a5="319ab48e6fdd5134a5381dbe1d85ae88df203f87993aab3708cfdf28"
    $a6="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a8="47074cf4234a97b93f1df3b473877a1485bde791a82dd441684bd8fa"
    $a9="7f1727d8c6a704406c8e4e1de7d4d19b339a8612ecb67342ba65a571"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a1="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a2="ee94029bafba2122214a9d310dbea3b88153e18c03e74ea9ace80fa66f20f38b"
    $a3="ee94029bafba2122214a9d310dbea3b88153e18c03e74ea9ace80fa66f20f38b"
    $a4="75bd51a194f52e0f8f26344c29821b4ba21488db601f06111ea67258c9dc9535"
    $a5="75bd51a194f52e0f8f26344c29821b4ba21488db601f06111ea67258c9dc9535"
    $a6="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a7="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a8="46b8aa14f3a5fe5aee4be26c5e33903e1c67df5a8bb35fec5332f8585b2eb6a7"
    $a9="dd51340386dced8be57309ebdd0a92fae5ad55e1013bca1d19d3e210230229d6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a1="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a2="fe42f6d891df10ae003a6b3e1ddd8ecadfe95588224ea50002d617efdc2410d00c2fe169f5dc0e6e583b35d91e95947d"
    $a3="fe42f6d891df10ae003a6b3e1ddd8ecadfe95588224ea50002d617efdc2410d00c2fe169f5dc0e6e583b35d91e95947d"
    $a4="6c71a396a1be305d3f903d32b0639fe5162d594048a93cd940ac4c536a42d495febf2196478b8dab28b3fa5ed4752915"
    $a5="6c71a396a1be305d3f903d32b0639fe5162d594048a93cd940ac4c536a42d495febf2196478b8dab28b3fa5ed4752915"
    $a6="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a7="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a8="e073fc2dcd9ab5ec92b8aba9a77fea6e75646cfa25c9033a30ad0928367dbf240588a9f5ed0107ddb6eeedfa0115b3a5"
    $a9="1b9bfc4a37fe08188b1a0183be30ee8669002bd2012eda9636f8718bcd389bc7c3612b6c4d8ee2a627d354977c364a55"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a1="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a2="65582c103cfe2fa6e4e23596c7d51ed0da89c9b73252d895699ae657ed44852d1f28817bd30eb0702f3b7704be8e7516c850f1c33a16352cff75e492754f643f"
    $a3="65582c103cfe2fa6e4e23596c7d51ed0da89c9b73252d895699ae657ed44852d1f28817bd30eb0702f3b7704be8e7516c850f1c33a16352cff75e492754f643f"
    $a4="3d7f62b722396d23601c47721a8a83e88d733b4662bcb83da676be4604200c24fec1db69232bff6b861e65fc8ae736d38f7ee22127b574b4d5df330fd9a8d976"
    $a5="3d7f62b722396d23601c47721a8a83e88d733b4662bcb83da676be4604200c24fec1db69232bff6b861e65fc8ae736d38f7ee22127b574b4d5df330fd9a8d976"
    $a6="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a7="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a8="1c6daab50a77e6e9afd594657a053c60091f1560df238156a58444d71765a88dfcd69f2df94f3bf865f67c251168e897507921b7fe31a3f1376c404e8c3a0f67"
    $a9="1b99a6598299e157490ac8e5f71b5254b3a01796a03aa11e0dad34d1bc69a3b080ba58695cd88d49f17ff855035647d964d1617bbb38dd693adb0b0953e75b9e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2V0dXA="
    $a1="c2V0dXA="
    $a2="TklDT05FWA=="
    $a3="TklDT05FWA=="
    $a4="aW50ZWw="
    $a5="aW50ZWw="
    $a6="cm9vdA=="
    $a7="YWRtaW4="
    $a8="a2hhbg=="
    $a9="a2Fobg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

