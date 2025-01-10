/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_advantech
{
    meta:
        id = "6OMk2ryJQw82RxvKLOFALy"
        fingerprint = "e50a3a482b7fe8107b2a13617246452b50049a64bf23596f52dd754f9adc5c6d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="59380d48b907d5c718e714159a57edb5"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="9bdc61db5a3fced6d82d49279f1f0430"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="9bdc61db5a3fced6d82d49279f1f0430"
    $a7="0d17ae3710227fa4cd6b0ee3269c7f85"
    $a8="9bdc61db5a3fced6d82d49279f1f0430"
    $a9="a25b2710ba9de114396adc7dfb0a7235"
    $a10="9bdc61db5a3fced6d82d49279f1f0430"
    $a11="0280777f37d4f4e7c478d21cec701463"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="344e26f86f2d80fd"
    $a2="43e9a4ab75570f5b"
    $a3="43e9a4ab75570f5b"
    $a4="503057354aeca919"
    $a5="67457e226a1a15bd"
    $a6="503057354aeca919"
    $a7="21dac7826bedefdd"
    $a8="503057354aeca919"
    $a9="4077eb0b03ddce3b"
    $a10="503057354aeca919"
    $a11="15f73cd91718b388"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4B561E28424F31FCD13DD9D1DE3B988583620C87"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*2DF3063C523DF16DEFB8A454F9DA045D92D509BA"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a6="*2DF3063C523DF16DEFB8A454F9DA045D92D509BA"
    $a7="*5A5DF4CECE1D2AFA40F5B70DF940300F8E64E77B"
    $a8="*2DF3063C523DF16DEFB8A454F9DA045D92D509BA"
    $a9="*D89A99106002D77C1D327FC41E005919505638B0"
    $a10="*2DF3063C523DF16DEFB8A454F9DA045D92D509BA"
    $a11="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}N9KYAhLFBIrZ4U26qAc9ew=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}3Ush6e9x4SkRg6RrkTrm8g=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a6="{MD5}3Ush6e9x4SkRg6RrkTrm8g=="
    $a7="{MD5}+gPraIrYqh21k9M9q9ibrQ=="
    $a8="{MD5}3Ush6e9x4SkRg6RrkTrm8g=="
    $a9="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a10="{MD5}3Ush6e9x4SkRg6RrkTrm8g=="
    $a11="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}tyy/hBlME7DCTYch1f1PmazxeyE="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}cDUvQQYe2k/zwyIJSvBounDDs4s="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}cDUvQQYe2k/zwyIJSvBounDDs4s="
    $a7="{SHA}6WhXxY9xYQTK6tZI7mqmGrjkHNw="
    $a8="{SHA}cDUvQQYe2k/zwyIJSvBounDDs4s="
    $a9="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a10="{SHA}cDUvQQYe2k/zwyIJSvBounDDs4s="
    $a11="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="37d2980212c5048ad9e14dbaa8073d7b"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="dd4b21e9ef71e1291183a46b913ae6f2"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="dd4b21e9ef71e1291183a46b913ae6f2"
    $a7="fa03eb688ad8aa1db593d33dabd89bad"
    $a8="dd4b21e9ef71e1291183a46b913ae6f2"
    $a9="e3afed0047b08059d0fada10f400c1e5"
    $a10="dd4b21e9ef71e1291183a46b913ae6f2"
    $a11="8f9bfe9d1345237cb3b2b205864da075"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="b72cbf84194c13b0c24d8721d5fd4f99acf17b21"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="70352f41061eda4ff3c322094af068ba70c3b38b"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="70352f41061eda4ff3c322094af068ba70c3b38b"
    $a7="e96857c58f716104caead648ee6aa61ab8e41cdc"
    $a8="70352f41061eda4ff3c322094af068ba70c3b38b"
    $a9="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a10="70352f41061eda4ff3c322094af068ba70c3b38b"
    $a11="9f8a2389a20ca0752aa9e95093515517e90e194c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="279ccc67a91613e7e0fa3164543a3ceef9c93e33fa3eaddc0d408fe4e6002caeee32566a517bf4380adcb0cd21f676c4"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="594f577a573d9517133e09ed29eeb0cbed14ea1b36bd060d13501caa03f0bb2049e6a06b9c919d007afc8e44064d6217"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a6="594f577a573d9517133e09ed29eeb0cbed14ea1b36bd060d13501caa03f0bb2049e6a06b9c919d007afc8e44064d6217"
    $a7="cdb347a3e6fd5b295b638951e19d0908625c711942c8eeb09392a027875369b2247940668af06bcd74d5761c69b057c6"
    $a8="594f577a573d9517133e09ed29eeb0cbed14ea1b36bd060d13501caa03f0bb2049e6a06b9c919d007afc8e44064d6217"
    $a9="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a10="594f577a573d9517133e09ed29eeb0cbed14ea1b36bd060d13501caa03f0bb2049e6a06b9c919d007afc8e44064d6217"
    $a11="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="d777fced94de701abc5e2005f187297700e232ce2d5e3f9093856488"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="3876dd6e14a7097c1c732a8777c26757b5eceb87111cac26a1f4f5c4"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="3876dd6e14a7097c1c732a8777c26757b5eceb87111cac26a1f4f5c4"
    $a7="863d4fea750b9c44504c7a774a6c13a95a4e24675a006b58b78fef9e"
    $a8="3876dd6e14a7097c1c732a8777c26757b5eceb87111cac26a1f4f5c4"
    $a9="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a10="3876dd6e14a7097c1c732a8777c26757b5eceb87111cac26a1f4f5c4"
    $a11="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="76b8852416bb7691d0649e0fafe3332549352f9f158c81801ddcd39eee750565fbc966185d10c011e21a26ac5c50f804319eb82a08f74d78127fbda2de80f9c5"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="ce2a429a1c79d4068c0c7e54f5500ce16285d85730cb9ec0b61240f88ef9c870292200a1c069bd57d5e092874567058c91782513763bc30d86fedca63820c482"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a6="ce2a429a1c79d4068c0c7e54f5500ce16285d85730cb9ec0b61240f88ef9c870292200a1c069bd57d5e092874567058c91782513763bc30d86fedca63820c482"
    $a7="f6fa8f685a4fc06ee33cb5824faec8d994ee2875db645012304b8f23e01aad73ca7ee9fb29bff06e8ce856ae9c3f49f3e58b3edbd7009493f72be079d0ba03c3"
    $a8="ce2a429a1c79d4068c0c7e54f5500ce16285d85730cb9ec0b61240f88ef9c870292200a1c069bd57d5e092874567058c91782513763bc30d86fedca63820c482"
    $a9="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a10="ce2a429a1c79d4068c0c7e54f5500ce16285d85730cb9ec0b61240f88ef9c870292200a1c069bd57d5e092874567058c91782513763bc30d86fedca63820c482"
    $a11="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="2f04672311c5a91443c7a2d68148f46acdaeaeb3e488c587b9172a23f67647f0"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a6="7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c"
    $a7="44cb005ee2e65d9cc817b0a083579369fb6c24a4be728cb43fd9d4c3ca7f4c2e"
    $a8="7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c"
    $a9="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a10="7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c"
    $a11="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="ee276d5d33832a6f05ae3954a7649d1bccc4177cb693d7acdcf423c3e3c5974bb9b5ddbd090ae6929db3cddf9257fff95b212388dd0456dd03a20512aa2d4daa"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="997640bbacba6ece9c0412e7da8646458d1f11202c0a8f162b6a90a962b558ff9ce5ac7721a75b6205338647d6d83ebb9e7514e027917a565445bdedbea9c081"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a6="997640bbacba6ece9c0412e7da8646458d1f11202c0a8f162b6a90a962b558ff9ce5ac7721a75b6205338647d6d83ebb9e7514e027917a565445bdedbea9c081"
    $a7="086d276836c46aa40dcd7d3146548774db2c14fe3d36ac3e6e5a01cc015c6063e23cbce1097cf77a89de52023516baafb55c6f10c425c32fc23b5826fb5207e1"
    $a8="997640bbacba6ece9c0412e7da8646458d1f11202c0a8f162b6a90a962b558ff9ce5ac7721a75b6205338647d6d83ebb9e7514e027917a565445bdedbea9c081"
    $a9="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a10="997640bbacba6ece9c0412e7da8646458d1f11202c0a8f162b6a90a962b558ff9ce5ac7721a75b6205338647d6d83ebb9e7514e027917a565445bdedbea9c081"
    $a11="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="a59a11342336477b3b1ea828ceaf6f2f2df4fdf78175a8acea26d8e389791993"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="cd47e74fbcd689a3a1a85c0bd38cbd1fa05afe4c8f570cc254bfe2b21a19e1b1"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a6="cd47e74fbcd689a3a1a85c0bd38cbd1fa05afe4c8f570cc254bfe2b21a19e1b1"
    $a7="0a3109efa9dd4bf2cf373f62ec66b3c710146fbe51db336f809fa1815758b8c5"
    $a8="cd47e74fbcd689a3a1a85c0bd38cbd1fa05afe4c8f570cc254bfe2b21a19e1b1"
    $a9="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a10="cd47e74fbcd689a3a1a85c0bd38cbd1fa05afe4c8f570cc254bfe2b21a19e1b1"
    $a11="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="83c9df742ea0388364c6d0336631d2bb9f88d42d4d121572e452e940"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="225dedff3d385fb473af2f34ceed57657b24ee8a23b3107fbf8c4557"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="225dedff3d385fb473af2f34ceed57657b24ee8a23b3107fbf8c4557"
    $a7="7a96f4d91945a6fd2a001dc10517a287d1ee569cfdc55f9005e0c21f"
    $a8="225dedff3d385fb473af2f34ceed57657b24ee8a23b3107fbf8c4557"
    $a9="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a10="225dedff3d385fb473af2f34ceed57657b24ee8a23b3107fbf8c4557"
    $a11="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="ae93668c759804fd6f35d12583af33852f87cd0a2bcc0e71653b0de783fa99ec"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="c571dd2139e469c5fe159e58bde1bca4a62e9a843f559c149ec8f69784719635"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a6="c571dd2139e469c5fe159e58bde1bca4a62e9a843f559c149ec8f69784719635"
    $a7="c896da5bbd049f5bb56a48cc3058554ad47d6386c640bcedaa8813df2cdcf51f"
    $a8="c571dd2139e469c5fe159e58bde1bca4a62e9a843f559c149ec8f69784719635"
    $a9="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a10="c571dd2139e469c5fe159e58bde1bca4a62e9a843f559c149ec8f69784719635"
    $a11="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="b64713320b04a6474786484b17e0b59f03c06ee022a65bfbe436b936a08e1a8399c3c936122fb0a43c9c0a030e696eca"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="748e6ba10d65d46666cdf2980381614d19c05b6691c45900f68841a10eeff3bea0bbcefd7dd6cbd99a067c7942ce9068"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a6="748e6ba10d65d46666cdf2980381614d19c05b6691c45900f68841a10eeff3bea0bbcefd7dd6cbd99a067c7942ce9068"
    $a7="be761c325bd65980169af0dff977f9d34a6e3dd9143ec984ff54f193b06aa1fcc49fe997d8769f6052d263b5d59baee6"
    $a8="748e6ba10d65d46666cdf2980381614d19c05b6691c45900f68841a10eeff3bea0bbcefd7dd6cbd99a067c7942ce9068"
    $a9="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a10="748e6ba10d65d46666cdf2980381614d19c05b6691c45900f68841a10eeff3bea0bbcefd7dd6cbd99a067c7942ce9068"
    $a11="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="921c30adb4f6a782eb7e9d5497aac8b85e9d17d000c6c7cbd34ecc48b1f5f4b634a0fbd7e4f1b944a79c5a4ba9b12950c2c444d7b20b47e230d1e8f3b7c7484d"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="17ea18adaf471a26e57a5091f0a51eba3d04a6b7d52331171bf33f2ea6ecd5437edf71c62e15b5f1cdbc3252c12ed57e296011f2af8b58631dbacbe166ff0b74"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a6="17ea18adaf471a26e57a5091f0a51eba3d04a6b7d52331171bf33f2ea6ecd5437edf71c62e15b5f1cdbc3252c12ed57e296011f2af8b58631dbacbe166ff0b74"
    $a7="db8c45335d1cae5f0d6550bf03d1065476852b1db6964b559f2d747de81e912d324576491e7f8f13e95caba7587111d9d5548cbd9eff7348eed3eabc538ba969"
    $a8="17ea18adaf471a26e57a5091f0a51eba3d04a6b7d52331171bf33f2ea6ecd5437edf71c62e15b5f1cdbc3252c12ed57e296011f2af8b58631dbacbe166ff0b74"
    $a9="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a10="17ea18adaf471a26e57a5091f0a51eba3d04a6b7d52331171bf33f2ea6ecd5437edf71c62e15b5f1cdbc3252c12ed57e296011f2af8b58631dbacbe166ff0b74"
    $a11="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWR2YW50ZWNo"
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="YWRtaW4="
    $a4="cm9vdA=="
    $a5="MDAwMDAwMDA="
    $a6="Um9vdA=="
    $a7="MDAwMDAwMDA="
    $a8="QWRtaW4="
    $a9="MDAwMDAwMDA="
    $a10="VXNlcg=="
    $a11="MDAwMDAwMDA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

