/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_honeywell
{
    meta:
        id = "479cDZpVXuU95zfGPsTwhU"
        fingerprint = "6721c97d53a0344529ad97be7bb6f234ad005480a1d398918dd91c3e595b8db4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="a4141712f19e9dd5adf16919bb38a95c"
    $a2="f6121e705ff655db0198e763cdc2182d"
    $a3="d80e575c290a4ba7bd13b3d96d42ee25"
    $a4="5debcd2e1ac34eb2e7074db0ccc10bea"
    $a5="6edfce593ee38e9741b3ae0ea40a9a2c"
    $a6="823893adfad2cda6e1a414f3ebdf58f7"
    $a7="3d2b4dfac512b7ef6188248b8e113cb9"
    $a8="3a319c268a4be273a28450db17e6c18e"
    $a9="494707493dc9b83a1dab7c6788cf2e52"
    $a10="209c6174da490caeb422f3fa5a7ae634"
    $a11="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="446a12100c856ce9"
    $a1="7a7eeba37575fe5e"
    $a2="4ab42b6640ccbf16"
    $a3="3c6dfccb7e5b445d"
    $a4="775b240f28521e98"
    $a5="3100ffd3503e5bed"
    $a6="57510426775c5b0f"
    $a7="01181bc63be6204f"
    $a8="3416c09974a892cb"
    $a9="760a78fe42022532"
    $a10="43e9a4ab75570f5b"
    $a11="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a1="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a2="*68C04ECC59B0D5CFCD651D36F80EBB2C10474B6F"
    $a3="*90D01ECE1CA9C2266FC268E7728564779F15B041"
    $a4="*FFE3AB81B1C9A5E34E7B33326065ED5C610D6AC1"
    $a5="*34963B1631C5D6E52690C35049C29D34C6E4C961"
    $a6="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a7="*B83A2F73F9E74C1EF54E25B4C8A06A68E40CEDF1"
    $a8="*FDCBEFEDD53D954B16F63DCAA3382A7775051D22"
    $a9="*40A898E13D090D32CE8917AEACCE808024FD60C1"
    $a10="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a1="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a2="{MD5}L2zlFbIuoPMh6LgUvh9rsA=="
    $a3="{MD5}EDarKEjBfZLQQz6M6Y6QOg=="
    $a4="{MD5}IwUv4/W8Yn0VTYWO+0ChZQ=="
    $a5="{MD5}g3Ep/M66Gf6H5MEkT/oHIQ=="
    $a6="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a7="{MD5}rbgxp/3YPdHiownOdZHf+A=="
    $a8="{MD5}tg64O/Uz7s8b3mWUCSWpgQ=="
    $a9="{MD5}oKAsIqigXNp7QNzmfNbmIg=="
    $a10="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a1="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a2="{SHA}kOcz4zguFdMTYxa2FMr/5evWRCo="
    $a3="{SHA}wm7V4pGCAxhPw11Pq6sKOEH8ARo="
    $a4="{SHA}2DoQTKGSkyRmzB4wi0l1e6jOOfA="
    $a5="{SHA}xjt3tGGa6HFtPwqZ4XODwq2OcoI="
    $a6="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a7="{SHA}+s6D7jAUvcj5ggPMlOLokiJFLpA="
    $a8="{SHA}nXU0LBA6BQz7CbBZYLuV1twTNbY="
    $a9="{SHA}vbg/yEDVUNLnsH1VDCLHEvoCiic="
    $a10="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81dc9bdb52d04dc20036dbd8313ed055"
    $a1="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a2="2f6ce515b22ea0f321e8b814be1f6bb0"
    $a3="1036ab2848c17d92d0433e8ce98e903a"
    $a4="23052fe3f5bc627d154d858efb40a165"
    $a5="837129fcceba19fe87e4c1244ffa0721"
    $a6="084e0343a0486ff05530df6c705c8bb4"
    $a7="adb831a7fdd83dd1e2a309ce7591dff8"
    $a8="b60eb83bf533eecf1bde65940925a981"
    $a9="a0a02c22a8a05cda7b40dce67cd6e622"
    $a10="21232f297a57a5a743894a0e4a801fc3"
    $a11="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a1="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a2="90e733e3382e15d3136316b614caffe5ebd6442a"
    $a3="c26ed5e2918203184fc35d4fabab0a3841fc011a"
    $a4="d83a104ca192932466cc1e308b49757ba8ce39f0"
    $a5="c63b77b4619ae8716d3f0a99e17383c2ad8e7282"
    $a6="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a7="face83ee3014bdc8f98203cc94e2e89222452e90"
    $a8="9d75342c103a050cfb09b05960bb95d6dc1335b6"
    $a9="bdb83fc840d550d2e7b07d550c22c712fa028a27"
    $a10="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a1="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a2="193762f438590027af3741560adf2059a6580837d22349d802df83135db6afa2e29db6f7e46a9afc72cbee1a38c77261"
    $a3="2848ec31897ffdaed0b78de7c3b840dc47b956bd93b5a2c0a575e688d371974587fe12d8d6a4e9816120e83e95d23a56"
    $a4="334f7e2ce36ab62f4f8901e016d5061c1b3ce42f2a3d87b5d8025d9b81082c40b917bc88f61909964bd880736f391e65"
    $a5="4d252a6764c1e477d9dc97b9d96ec05f08f755b2ce0990025e0c6228281e3f9db8725d6efe4dce28629bb7b85318cd6d"
    $a6="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a7="4477d2e5351a588186edc3371e30f1cfb64ad5f01aac0c504340342e70dafc3343c0b3e878327a8263e11ecf8dd33b30"
    $a8="f8f3517cf93f00d50e006c6b250f94eb69fbed4232701e9d780eb3877b75ab336add20d2484188247e43396eb1e9a36c"
    $a9="032ca822378998d9b1d551df8a4bd8bf7a5d623c8bacc0764e8e9282d66a0f52505ebf640cffa3bd3bb72bb3c74853e5"
    $a10="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a1="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a2="bb8dd744c35071084cfc017afee9f3a492b762b93a083a6a5cdcdfe7"
    $a3="41491e96da93d03981b6677040d1ac8f94b68d593fadfed5595e0cb7"
    $a4="b0230b784117e470472294d167c34856eaf68d68b7e9307836464c2b"
    $a5="25193ce5c73a17baa8420eed3f8f139f34447ab0e8da490aaeb10d63"
    $a6="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a7="1c95d70b4960a674e2c8a0e86c3a2ada419b9b7534912790666ed9bb"
    $a8="f13509df7748da4564145a66d4f7e30313a4cf0be791d98c344301e8"
    $a9="281f836d7681ad99c1cefd501e0ffd132fde05476adbd584e1c1baf6"
    $a10="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a1="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a2="4dbb441272177a8af5add51ae4c7012225d5f02945aa58c0837c93f8fbdabd5661c0dec1de578665accf19516f1b13eac440e5c72b73b4252e807d1b391a4049"
    $a3="8d1a276efbb3cdfb4aa060818066c78417608fe9f457502388d688335de754f488731f201960849411c68a01c0c01827fff2d9d14fe868e3e8157e8c3ef18caa"
    $a4="4705392774c804670fd1e7e6ee6842456525d6b6ef473d97f1c0db8d70339dcad36159883e0c2554172d0af36e4db63c8259298c69ca87edfb09186ac35528f9"
    $a5="c185ffa1290eb1d9ff7b87cb5fa6b3d0ef1f94808b8cf42e86655052d182128d5609f6e940ef972daa1bde28d9885822ca8e3331a529a270ca6278e93e233f8a"
    $a6="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a7="cc5ec2b61fbbdd18d85dd14ab60db397b21b5548999a6afd3ce9557b19c300494a5fd29987e03a6f06677c209b88de47684388de8250671cdd778799eecd018a"
    $a8="8c9fdcde3a92c52699eaf579fca9d0fc3602852552b67b4d0a9f4a07429835d6f34f375196d73b169d55e313fc3c3e81a2db28779e3a45814704188a40221078"
    $a9="ec80f916d6bb87fad058cfd70adb9381c71cac73b6bf61a50a9bd165835deaf5114f6b6c2a8d8208673cff482f6ed9997f69baa6fe4b391ff4ec15bf31850abc"
    $a10="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a1="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a2="47e5a6cd5d35ae54f7d54b91f1101f8cd19e16d4de81987aebb1797781e57bc8"
    $a3="442e67f339040c13865fa8306cbfff3dbf789f62be42aff7f866f24f20ec9946"
    $a4="210d00ae954a907a9ce1b06c663f702917a6823ccbddd986e9f0a21f51e2af27"
    $a5="8b10163df5c8c0e1068927b0de7b040e8d567f4176da083a2ec059c4b0a36e1c"
    $a6="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a7="5ed8944a85a9763fd315852f448cb7de36c5e928e13b3be427f98f7dc455f141"
    $a8="a55e2e3846a51f6ad0abfdfbdea2ba0e5e0c76b5ccfa8a920895fedeae89a8b6"
    $a9="251d0b11767b751b455af313681b863bef8a9388cda14a5203fcb15215c610ed"
    $a10="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a1="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a2="6740ad43869a805dc9fd6ada5e556bd7dbf0ff27596827eb174e052c61d14ba087677a8872a2d229d8321943ab4ab759d6c74de0a34631149d48dbdb0dbb8e91"
    $a3="b2ad3eae8f8dae047dfccc34afb109d363a895cc71e0540252d6fe37c2674aab2baf21f5b5b2089e7778ffc4165e816da36bb520a0d3ffff0259d14b7783a38a"
    $a4="bd4312ebc64e5aa86e3e8a952b14243c47deb93abb9fe2652679fec67629220868e7d3ac72c9308d119ce3208309ca73d426d350520f8fb33c6133e2e606d8fe"
    $a5="840a88e800876bc4e40f8c33d9e7c293c0e28f48c291398236764b0ba716c09a0276cb798e83f10415341cfc7889802accbeda169135716ba316d0c4afed80a7"
    $a6="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a7="0b38c93bb2e46b2037c88ddccad59cbe1092f2ee7eb24ece6381de92d02f323865d52ac3d5a2a7da513661224b910c258184a1bbe405c9ebe1eabd83633f1e5d"
    $a8="5e759101c609f4b740ef80e765ae365b2af502d28946ffdb14a008ba3b8f3b38d22724597db1a2727631e47be95bf3dbc91421426b178885abb756996aa2ed28"
    $a9="8f439c2423e8065f171eb05842f7b04dfdbe2f22dbfa356edc37c0c3c292c1127dbebeb13fd9bf2fe04e47445d5913545b1702c1358df1e80f5610ba0671167b"
    $a10="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
    $a1="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a2="14b93338406b7166cefd29f6622e20e388c357ba6fc782e5f0b8f46977dd1b6c"
    $a3="83a62c3efce84e77ebcc76ae4132840d21e4fc28bc07a43ff9a67ab5bb58be4f"
    $a4="be5bd5bf4ad1e62310b143736e8fb8899ba1e9f6ecfb76aa465ec12645c0a151"
    $a5="27d1ca9e380f2d4224b5d8505a5715ceec6fca3b03be5a0d38344ab2fec2b116"
    $a6="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a7="df4738b4ed2274b73722607a4d1cc2158eb209ef16b350087d867393f98db685"
    $a8="97366c98ecc5c51c039bf7d2aba720a0c348e5843f136182fa72337c61e28a26"
    $a9="069527e6c0cd6b8c31aec08972a6839e69bdc571f5d95700c1054da7966b1b3f"
    $a10="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a1="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a2="1aeed8455c7e500203c3680c8de04da20829722f02fa56643fde33a1"
    $a3="2a69c0da1a8a203108e7dafdc18d206230bfdadb4e25961c748375cd"
    $a4="3d2465a3f806df2b6ac34f58dae5021a32a0c5b4da45dfcea130aaab"
    $a5="514bd8a2a12d978f367c7f70551e6688af3d72a89997907389df5ef2"
    $a6="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a7="e810597249305f414f75eb5a9d2644820de439bc4647bbbdd90f702d"
    $a8="0452aba97190537aa9211a1911b2384fc81a7f013238c0ef118f6284"
    $a9="f026fbe9c452b660835b33a6c813366b5495c908a46a5449abb4f9cd"
    $a10="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a1="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a2="1b9d3b1526324d37b28648c45cc8f21ad6eafd9a9eea3ebbe24b249a986023f7"
    $a3="56c42e2e7e039ed7d20fcf94b6ea70d383d912d389b510b24f008206ba85fd8c"
    $a4="e67822e59cdad773a782f84ad618c04955ebbfcd4879c75be1126287c7ec5edf"
    $a5="375617b0affce95ce069be5d690b962f3b5994e94ac350eb83d32d2b8b342c79"
    $a6="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a7="2848f07d55acfdd67caf77f276e1f0a529e4026f1708356d77b1ced98326836e"
    $a8="4c678c8303c73293bfcccd1ac543ead33636fbb80427383371699c1cbfb339a3"
    $a9="58e7d8a8e0fcb4a85e4afb1a75368a97faf987e911e5d1a7bba43520603a2404"
    $a10="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a1="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a2="c6afc90044c10cb59276a11284d4e6ee86580691ede399641caf85c110d87e7ed72208b5983e185dc8526bb988d2c1cc"
    $a3="dbc5290bbeac891fe6f56a3b537a318a3a3c5cbfb5cc08995aad9e9dda73c9909b365af079b523538d6f6699c68b52de"
    $a4="5b85d6d6abee0cd02c8e86e8f1582d66d40b91b7f0fb1e1862ee6fef4ab11b2b87d9f5093958248a7677dd7c2ba5eba7"
    $a5="9c22d5ae545171c67130105247577cdfdd60ee834953cd65f26a3598e1dc72944e94280b1a10a73d64b4f222b9a59ccc"
    $a6="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a7="6d2bddea82451f8471ec7642ce69af08a2be6845ab02b2d5094fd89640037515a544044c7fbe733a7d26d6758892e60a"
    $a8="c3e535e3b57e3b4f9dbb9fe73e0fe8553c95693a26c069f26ffcffa2fd86e82fe2ad78de17cfd110a14e26e8df3ee511"
    $a9="21dcfeb22afdbaaf2df9907e068c052fd118674b27889c88eda4e2e521f7646635606e2957a0e5613041c2adb8ae2e04"
    $a10="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a1="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a2="4f746af90aec8458b722248c8c015f8bd8b916bfc4eb07286f86cf9bf5468d8261cf0327ddedb612812ab5006620484625418e4919c81a1d399034270b4da79d"
    $a3="c0e18f2eb2eac30e7e30e20b5f5202f3ecbda35d5921b552b5dfdeff22761585cae92fc6ca496f136056d411350a4a10beaee5aaf29c56240679f5c38b8a780d"
    $a4="9328c5f4ecfdc43027ecc941ae17eb0a2c015e6a75109a01ee123c0af2cd8944b90ca506a2240d460e3d5607090a6e046d6e421143362e630ade139fe58d18eb"
    $a5="7390534efdf99c13932a57e08d226d44ccf8ecba0091ba8866b848fcec8d2437be3bd03ad1f0afa38c6b2057c4152b3fa36070a811ba67f6f1ddd008f0780fb7"
    $a6="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a7="90f2e09d2bbcaec0bf162a060461aa3f49647fec9cd87f0df9ea028e723ce3723fd47026b152f9fadf7af211cec81c285b8223199bce57ceb7aeafa60752a100"
    $a8="7ebf2ec2873c61214592fda44f3b6d2117867a908545d19677179219aed9251622b222ca60e3555d2685ede7e8227affd37404dffa5f54acdb269387ded70896"
    $a9="9f3d24b152bdd8874d0f6914ea5051ea21bf8a24589b41c57365884e82b0f95d09dfa1b5ddf862f42f5a001a56720e6fab1b8010a677f8abc7d07d9f5bd1f875"
    $a10="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW5pc3RyYXRvcg=="
    $a1="MTIzNA=="
    $a2="TG9jYWxDb21TZXJ2ZXI="
    $a3="TENTIHB3ZCAwMw=="
    $a4="VFBTTG9jYWxTZXJ2ZXI="
    $a5="VExTIHB3ZCAwMw=="
    $a6="R3Vlc3Q="
    $a7="Z3Vlc3Q="
    $a8="U3lzQWRtaW4="
    $a9="aG9uZXk="
    $a10="YWRtaW4="
    $a11="YWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

