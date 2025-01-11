/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_wago
{
    meta:
        id = "3bv9ZjFFlLWlLjWma1ndZm"
        fingerprint = "16bb4e62e627c9429f4d79daa1afa06d3e7e0d11616a8845763a7db0d1cedea0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb2b560db95a7f6b1d76eeeb71a65161"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="57d583aa46d571502aad4bb7aea09c70"
    $a3="57d583aa46d571502aad4bb7aea09c70"
    $a4="823893adfad2cda6e1a414f3ebdf58f7"
    $a5="823893adfad2cda6e1a414f3ebdf58f7"
    $a6="4056da565eff865c23687b2d1cef8242"
    $a7="57d583aa46d571502aad4bb7aea09c70"
    $a8="d1554d6a00b55d64a531e3d2c2b3b026"
    $a9="478ef2a76e95338d441f681e20c2077e"
    $a10="fb2b560db95a7f6b1d76eeeb71a65161"
    $a11="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="061e9b2029e44eb5"
    $a1="43e9a4ab75570f5b"
    $a2="1a486e7929011a28"
    $a3="1a486e7929011a28"
    $a4="57510426775c5b0f"
    $a5="57510426775c5b0f"
    $a6="7491b8794567224a"
    $a7="1a486e7929011a28"
    $a8="361ebacd43887382"
    $a9="077fe1f649259428"
    $a10="061e9b2029e44eb5"
    $a11="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5239FBCDF33B7C022281640666A7F70A86961CCD"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a3="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a4="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a5="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a6="*E5CA489DAEC42F3DEE604B064704C788070FEC79"
    $a7="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a8="*F8DD1ECF9A26FBC344692D82E4C030AEF1A178F2"
    $a9="*3FE3EA4DA8ADC44BCAD5588421C4C14C2A49760B"
    $a10="*5239FBCDF33B7C022281640666A7F70A86961CCD"
    $a11="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}eUhBShBvh1iBdOl4eOqHaA=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a3="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a4="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a5="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a6="{MD5}C6944Nyt1RJfu2rlBRSz5w=="
    $a7="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a8="{MD5}KE8rCIqNiJl6KT4C6YDh3w=="
    $a9="{MD5}CxgAeNmUyyte2J186Ofuog=="
    $a10="{MD5}eUhBShBvh1iBdOl4eOqHaA=="
    $a11="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}XX6qt487GNBNfccZGA00w93EHCw="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a3="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a4="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a5="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a6="{SHA}k7YbSCSS7OJHliJQZAvFCT4YY50="
    $a7="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a8="{SHA}vz+NoD3oiQF2cnwT058JOFq6bCU="
    $a9="{SHA}Nj6yJPb/jTxRY6iAUiKsv5OaZbM="
    $a10="{SHA}XX6qt487GNBNfccZGA00w93EHCw="
    $a11="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7948414a106f87588174e97878ea8768"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="ee11cbb19052e40b07aac0ca060c23ee"
    $a3="ee11cbb19052e40b07aac0ca060c23ee"
    $a4="084e0343a0486ff05530df6c705c8bb4"
    $a5="084e0343a0486ff05530df6c705c8bb4"
    $a6="0baf78e0dcadd5125fbb6ae50514b3e7"
    $a7="ee11cbb19052e40b07aac0ca060c23ee"
    $a8="284f2b088a8d88997a293e02e980e1df"
    $a9="0b180078d994cb2b5ed89d7ce8e7eea2"
    $a10="7948414a106f87588174e97878ea8768"
    $a11="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d7eaab78f3b18d04d7dc719180d34c3ddc41c2c"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="12dea96fec20593566ab75692c9949596833adc9"
    $a3="12dea96fec20593566ab75692c9949596833adc9"
    $a4="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a5="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a6="93b61b482492ece247962250640bc5093e18639d"
    $a7="12dea96fec20593566ab75692c9949596833adc9"
    $a8="bf3f8da03de8890176727c13d39f09385aba6c25"
    $a9="363eb224f6ff8d3c5163a8805222acbf939a65b3"
    $a10="5d7eaab78f3b18d04d7dc719180d34c3ddc41c2c"
    $a11="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e03c376a609181232a715ccdd87faa618d04470966597c03861361291268107ae3b5b4fd65d8cb6783d466f17e4d8785"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a3="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a4="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a5="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a6="41f2bf5fa1dd673825951b3d2b52b198dce18aa35d2ee15b4b006d1b5d1e3e49f3b0e3acb1c62276e04c8f51611dc75e"
    $a7="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a8="895600d714261332013b293420a5023a9a79e325e762b5136feeab73a4fd72b14ea28d21cd36120a50096440a05ecbdc"
    $a9="463fee3239947604527ed1590e5d123166f37ea69c70853f969203776521d951fe313f7a999be3acc19ac57093264eae"
    $a10="e03c376a609181232a715ccdd87faa618d04470966597c03861361291268107ae3b5b4fd65d8cb6783d466f17e4d8785"
    $a11="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5058db8efb45b6fba8a158ad8d8e7d809b87315b0daf2c24a4fda280"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a3="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a4="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a5="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a6="d48c889ee24680013b264391b5c794a1a527534eb4e8733282eb5fbf"
    $a7="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a8="81177be99cec7dda68184ab9c33769f5f9fef3abe74b8d1e9f2a3da0"
    $a9="7eecc6d449f6ff8a4ef78fea1bba3ff6c72bf50fbf3b6b004e067b40"
    $a10="5058db8efb45b6fba8a158ad8d8e7d809b87315b0daf2c24a4fda280"
    $a11="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6d3e73a23b4b12cd7fb52544740f5b240581f25a7292c003928403f812620799f24a179fcda4b7aebe74565df4d2ce5f528b24b5dbc3baa227d5582e32e0c13"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a3="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a4="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a5="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a6="887ad6a742d43ad98d149b3c7f3de605c9bdf43dc148e4519cbfa021833bdba78d2a19eaf7dbd4158447651ee7f75dbcbc1f3a3199137c77f6af066216161397"
    $a7="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a8="16f4e2594a05896ab88c07745e74bd6d4343d11b01afba030cba6a0ece87085593e7f21b0044bdaf15b8ec05fde30eb1981c77b3de5e4f7d9d058c4e1f492ecd"
    $a9="26857f0074d5e2393884b7b1aa9efc5e919d1111cef6e3b06c13dba5119cf882c317f8f4987a30e533eb786f138a876df4b3258a195bee819692600b7b6236bf"
    $a10="b6d3e73a23b4b12cd7fb52544740f5b240581f25a7292c003928403f812620799f24a179fcda4b7aebe74565df4d2ce5f528b24b5dbc3baa227d5582e32e0c13"
    $a11="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5882c4effae896478d7eebcf1df3ecd3f3e608cf535b0d5080addc9b2446b50a"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a3="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a4="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a5="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a6="0c672fa72156d86a7410a250ad029ec95d15d7add80605771eb6837574a7443d"
    $a7="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a8="0ed1d558d234da6a62e728e37f7205fe5cbfb6c53a2af11c5adf29990f8391a9"
    $a9="0a64ce10853f25cb3dc3f7d498f62d72b406be37ba8caf5aa7671414d9696049"
    $a10="5882c4effae896478d7eebcf1df3ecd3f3e608cf535b0d5080addc9b2446b50a"
    $a11="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb5f9b463af982c8e64474ce3b34679ef60cfa2e895ecb11b6b9d0ccdd12ef1c7a1dd51c13a2580cdb6a074df98cac450efc6a134a4dcae5d6a634e28281e5e7"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a3="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a4="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a5="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a6="1e9cae59a51fc6b2d71a5d5fa4bcbb07df23d87f1fcb2997d4982b7ff410cd73b4ba347a3043f64c8ef9d2c2c375866a65269b0755175a0ae7c43295c1dc3db7"
    $a7="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a8="bd050c4d6a036e7022b6d3311934b19337999f07826078a1303ce0acc145efc9bebb09fd5266ad3cb6f5728ce71df28ea7160cdb78ddbd6b794dc7583b414b6f"
    $a9="efac5090bb3c1ebf872bfde6e526769e3b5bc5ad581025fb3bddb54b653bd1d69e4b12197ddb85d14798d90250246764006be08ff13194aa5febd07eee5101b6"
    $a10="fb5f9b463af982c8e64474ce3b34679ef60cfa2e895ecb11b6b9d0ccdd12ef1c7a1dd51c13a2580cdb6a074df98cac450efc6a134a4dcae5d6a634e28281e5e7"
    $a11="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5686782e670472f9cf538ae20a25427fe223d6e0b11feb5681eb4fd01ac4b07a"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a3="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a4="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a5="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a6="02ed7824898037758c9cf3edae16ef04a0932876f3446c46879884f20c1b37cd"
    $a7="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a8="b1fb5f6a094d54271a7d67c1f47f3651942e9e71ab99348b1af31f6c482328c9"
    $a9="4d3a97557dd9d9e75802f825908c8bd54e9ac9156174f87ef4c3fcbe8742a2cb"
    $a10="5686782e670472f9cf538ae20a25427fe223d6e0b11feb5681eb4fd01ac4b07a"
    $a11="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84f66ede6f06ada7b0210161cf5cc5bf6819cfc650da89c600c1504a"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a3="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a4="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a5="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a6="ba36e4d79433494c312fb57ae2629cd1522c5eba0a2b22a4af9fe17e"
    $a7="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a8="343db195dd3f58024a57b75e6dc551036b92f9f026100e263530dcab"
    $a9="75f58bac7357eb7212974978e36e03df8be67637b1dc24ef0ece0414"
    $a10="84f66ede6f06ada7b0210161cf5cc5bf6819cfc650da89c600c1504a"
    $a11="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a0087c486e6e947b36c488c8eba752416f6971a15e009fd569c628e9c3211f0d"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a3="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a4="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a5="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a6="cef3a4489d0a1abd84b7919b278985b4d66684576e77a88da28c66a8177c1fdd"
    $a7="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a8="a0b45a54e567f420552b509405bdd745d0b792b202cb019ac51e8e73f434096a"
    $a9="b3e3c91646527478b12e1dcd492a14dd3fdb632f3cc66e798725a272f26b6918"
    $a10="a0087c486e6e947b36c488c8eba752416f6971a15e009fd569c628e9c3211f0d"
    $a11="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59098e471f28c2d13d39013761102d33dc79344a17dae4194ece3e63ad593b80234522ace22218e4e9f3b09c4faa1bfc"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a3="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a4="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a5="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a6="74ee1b4b3e8b9135454e33f86e9bcdf2672c220658b8f70a9802d00e5c93f6440b8df653c17d57df2dd4b391ca8a4dfd"
    $a7="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a8="6f8b88e5cb2d271642c85d1780172d863baa7ae195315e1e2d8eddad74a316753b1003d5e4490dce7c43203a83aa12f5"
    $a9="83060da7f58b3eee6cd44cf2920fa4268037e134924453906ed23db1078031f60ab644f41fae457ca4f357897dec2846"
    $a10="59098e471f28c2d13d39013761102d33dc79344a17dae4194ece3e63ad593b80234522ace22218e4e9f3b09c4faa1bfc"
    $a11="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="effcbbfefd6c2529bf7a6a08c0079a07369eb582d7ea8c2e19f33ca800da4d8a4a21cef109e9043d6e80f63c9230a11661a3642e2f3bae2fa3447b702b9fad1f"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a3="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a4="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a5="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a6="548ff3bcdbaf24d9b020a04851119b8cbb8103c7c4d61acfd306fcd4c357a50e5afa3baf6ca2e9d47d00a30a76eab3d42d8ee052e11802a72a06398731f60636"
    $a7="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a8="be91c99aaec923942c102419395c9a8e5aa85d323cc97f5338f370c48bd41525fc03c6919e52fe3abb5859fe36a3b47d48af535167b38a7bf5bc0486bd5ca9e3"
    $a9="a09b4a3360b01fd5cfa214fe52fa2a62795b43175e8cf8dbf373b5b591852a296d4f7d75e4bd0d4cc77c954927c048055c4db3522b8745aad627bc62fd1982c2"
    $a10="effcbbfefd6c2529bf7a6a08c0079a07369eb582d7ea8c2e19f33ca800da4d8a4a21cef109e9043d6e80f63c9230a11661a3642e2f3bae2fa3447b702b9fad1f"
    $a11="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="d2Fnbw=="
    $a2="dXNlcg=="
    $a3="dXNlcg=="
    $a4="Z3Vlc3Q="
    $a5="Z3Vlc3Q="
    $a6="dXNlcg=="
    $a7="dXNlcjAw"
    $a8="c3U="
    $a9="a28yMDAzd2E="
    $a10="cm9vdA=="
    $a11="d2Fnbw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

