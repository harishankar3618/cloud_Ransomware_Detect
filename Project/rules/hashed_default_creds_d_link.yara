/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_d_link
{
    meta:
        id = "3OUrkuDT5iMoYdPANDMuKG"
        fingerprint = "660883a2ff28895363481db8e89f7eae5788b9d6eca1493b8cf607c0d4493c3b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="ddc7fb79de1a6b6e9efe6d0196f31322"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="0e671b4301dd9a9d158ef5b519840bd5"
    $a9="15c2864b8c73079f372eb1f0e77067ed"
    $a10="db51013b2730e1f16df6db7c3a73ad60"
    $a11="209c6174da490caeb422f3fa5a7ae634"
    $a12="876f827c2d6b791883681cbd6f59c122"
    $a13="876f827c2d6b791883681cbd6f59c122"
    $a14="d7b01f802408113c32c069edba40c406"
    $a15="209c6174da490caeb422f3fa5a7ae634"
    $a16="f544adb3063108430ee40fe5a4703a0b"
    $a17="209c6174da490caeb422f3fa5a7ae634"
    $a18="209c6174da490caeb422f3fa5a7ae634"
    $a19="a761f58da397eee687624761af01e826"
    $a20="209c6174da490caeb422f3fa5a7ae634"
    $a21="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule mysql323_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="446a12100c856ce9"
    $a3="43e9a4ab75570f5b"
    $a4="5d2e19393cc5ef67"
    $a5="43e9a4ab75570f5b"
    $a6="64dfbcae5fb57c02"
    $a7="43e9a4ab75570f5b"
    $a8="4f49bf7a10041388"
    $a9="4c34074138e6e08a"
    $a10="2c20d5bd6ff371fc"
    $a11="43e9a4ab75570f5b"
    $a12="242324dd5dd2ad4f"
    $a13="242324dd5dd2ad4f"
    $a14="34e965ee7b6443e2"
    $a15="43e9a4ab75570f5b"
    $a16="1e669f5d1c42217a"
    $a17="43e9a4ab75570f5b"
    $a18="43e9a4ab75570f5b"
    $a19="0ece4be96bff92ad"
    $a20="43e9a4ab75570f5b"
    $a21="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule mysql41_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*319E8F0F48AAB662B0BE2289936708BA26C43C5D"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*A00D7DA8C1D6C53FD57D65777DF853197E31F389"
    $a9="*6ACC4A1BDB37561519281769BAC914546D87CA6A"
    $a10="*A80082C9E4BB16D9C8E41B0D7EED46126DF4A46E"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a12="*CDE2DB342443AD47FF27F09E8EAAE03350AC4B60"
    $a13="*CDE2DB342443AD47FF27F09E8EAAE03350AC4B60"
    $a14="*986AA6FE5BF3EE2295E90CF057630029713195D2"
    $a15="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a16="*6C5F02E4A315ADEE1A72A64B1A516B06CE43B9D1"
    $a17="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a18="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a19="*B13730149C2E617525B02086BF072D27190F11DA"
    $a20="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a21="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule ldap_md5_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}s9l3hM0IpgMd6CR4axhmZw=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}KieGd0pXIP/gg8NNyFpIAw=="
    $a9="{MD5}/ZancD9nCrs/QkmAz9C1Og=="
    $a10="{MD5}TJGE83z/AbzcMtxIbsNpYQ=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a12="{MD5}YDQ3NidDblyd8K4SKRctSw=="
    $a13="{MD5}YDQ3NidDblyd8K4SKRctSw=="
    $a14="{MD5}DqvOwcCOmIozJ73DmVr2rQ=="
    $a15="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a16="{MD5}oB6adgnk9xfhMcrqaYl24A=="
    $a17="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a18="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a19="{MD5}qV5bkHOCOQo1on//kl8VpA=="
    $a20="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a21="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule ldap_sha1_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}53kW/nBtdaWILmKTtM9L4cfb9IU="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}uqpnqgEgB9Gy0UceWLcZyKbO8to="
    $a9="{SHA}Fs64g2/uu6s4mUl/MYlcw3+vyaU="
    $a10="{SHA}YcmysX23eieEG77qv/kjRIsPY4g="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a12="{SHA}4aR6mC97fJPjZfMBilXlNuhl7lg="
    $a13="{SHA}4aR6mC97fJPjZfMBilXlNuhl7lg="
    $a14="{SHA}l7qUrCymKtlOOeD09kUSQdHSuws="
    $a15="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a16="{SHA}lURids36/zoDoivmrWCF5vcSwAQ="
    $a17="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a18="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a19="{SHA}1yv6gX/aDfhsXFu5GM7FerswFy4="
    $a20="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a21="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule md5_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="81dc9bdb52d04dc20036dbd8313ed055"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="b3d97784cd08a6031de824786b186667"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="2a2786774a5720ffe083c34dc85a4803"
    $a9="fd96a7703f670abb3f424980cfd0b53a"
    $a10="4c9184f37cff01bcdc32dc486ec36961"
    $a11="21232f297a57a5a743894a0e4a801fc3"
    $a12="6034373627436e5c9df0ae1229172d4b"
    $a13="6034373627436e5c9df0ae1229172d4b"
    $a14="0eabcec1c08e988a3327bdc3995af6ad"
    $a15="21232f297a57a5a743894a0e4a801fc3"
    $a16="a01e9a7609e4f717e131caea698976e0"
    $a17="21232f297a57a5a743894a0e4a801fc3"
    $a18="21232f297a57a5a743894a0e4a801fc3"
    $a19="a95e5b907382390a35a27fff925f15a4"
    $a20="21232f297a57a5a743894a0e4a801fc3"
    $a21="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha1_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="e77916fe706d75a5882e6293b4cf4be1c7dbf485"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="baaa67aa012007d1b2d1471e58b719c8a6cef2da"
    $a9="16ceb8836feebbab3899497f31895cc37fafc9a5"
    $a10="61c9b2b17db77a27841bbeeabff923448b0f6388"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a12="e1a47a982f7b7c93e365f3018a55e536e865ee58"
    $a13="e1a47a982f7b7c93e365f3018a55e536e865ee58"
    $a14="97ba94ac2ca62ad94e39e0f4f6451241d1d2bb0b"
    $a15="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a16="95446276cdfaff3a03a22be6ad6085e6f712c004"
    $a17="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a18="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a19="d72bfa817fda0df86c5c5bb918cec57abb30172e"
    $a20="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a21="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha384_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="abb0248c11191ed2775e057f8981546aa4fa49b9aac029a58802f27668dd0e0fedacce3569d784b4b45a7d310050c87b"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="72dae0bbda3735a414154e858d5f4f9c2c444f1bbf18d4867b88ff8b5541983c98f250a4f4882726c12ec181137f67c2"
    $a9="d9c4f74a0846f5b7dad2e76fac1ea5d529f2db68aeabd40cf002e09fef1ea3afecc3aa00b77d5126b2dc4aef982bbc1a"
    $a10="b7ed5de11073842b80b594b8e56a4cee3a860a63fc1732746eb195d3838e24cd33b7c456f823d831620b97315680f4aa"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a12="4ea7948c37d7e110bad68b61fc96cc38e9fd6f01c168af3c572c649e6297d068f4c91f8985ce573d09aa5b2b9d48c37c"
    $a13="4ea7948c37d7e110bad68b61fc96cc38e9fd6f01c168af3c572c649e6297d068f4c91f8985ce573d09aa5b2b9d48c37c"
    $a14="af864cdc66534ae66c70c79e0119b02a35c9eb370e23f9390958bca16d44a04cb759a7d4c439bf24e899b7e680cdf834"
    $a15="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a16="d1f4eb410548c181ae10011ec664830dfdca3e4ddbbc83da012a7f4e6197884c595b3806222df97bd72244e778c32762"
    $a17="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a18="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a19="f8fc9449e28505df5e6d3253c830892897e8e8d4fddb28162f1c587c8f33e51d2eb4f914f20acec8c679cfe65d37bad3"
    $a20="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a21="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha224_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="be0b39b08181103d1fa47aee92a84873de78757def95bff0e9d74dfb"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="6b1d3d49f3829502026e0000a672f19bf9d284558906d13417012a7b"
    $a9="35807539335d3c054790313c4895fb2c205f5bdb638833c27b2b534c"
    $a10="888fad770c3a27c39b480fff6350198462b46ff1d4bd01a6ee7dc24e"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a12="5c54250368d793966f71d96967d539d35eec60cf9046b70614d8f19a"
    $a13="5c54250368d793966f71d96967d539d35eec60cf9046b70614d8f19a"
    $a14="70f7383f38ede73626f931c05e2d7ec451c032e4c453921b05c1a537"
    $a15="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a16="a33b3cce9f96643053691faec28d7aabb5c97ac29ddd95a12ba639b5"
    $a17="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a18="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a19="91dbb637483891700ae70881d07c35cbd5f59177b0118fd4bfa647bd"
    $a20="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a21="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha512_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="02571d5cb5cf0e03b6fdb89a6b931f28b8e8124446eb96f229de29686af6f60be87ddb499b004265457f9e55a03ec3208d47de831f25cc9fd5e6eaa536254ada"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="49e1832f1c4468ce3401a04c546efa6796b458ab002a9abe53d41e377855b50a59c4b54a2f4c700cb8917815891d90fc69b197b22fefc394ac8bd7dc93d4487d"
    $a9="0a85ac4a88cddf29eef756f958ab8df78e3f889c017c0dafb88fbd72c946624def34286d5260848fee3a01bb212eb10053f5a0231e52ee06bfe7c91c4b321a59"
    $a10="d32997e9747b65a3ecf65b82533a4c843c4e16dd30cf371e8c81ab60a341de00051da422d41ff29c55695f233a1e06fac8b79aeb0a4d91ae5d3d18c8e09b8c73"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a12="f9212f89e936739e4aee42290d06f044674c182346096c3a3e24ef7f72c1afebf834032fa25ab371a5a459be2619f59ba7076a816ecddff9e5311c7625bd1b71"
    $a13="f9212f89e936739e4aee42290d06f044674c182346096c3a3e24ef7f72c1afebf834032fa25ab371a5a459be2619f59ba7076a816ecddff9e5311c7625bd1b71"
    $a14="b2e99c2ff77e43840e67f2dc946a7144bbc546a93d44492957151bcf1f847772da03d695a13c1aac98aad13cafc5631f7fcf3a0d5caf6793fca9f433d727c255"
    $a15="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a16="661706349473c2b4488d172296d4118f22f2862e592def16405a85420bcb4b43266a3ec96cb244762ae836d3ab976b88d9f4d12c048fa34e57b9de706914ac4a"
    $a17="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a18="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a19="ce2cb7667099fa6f891288146adaa74bb8b46cd714b1a685bdb19b815c312547bbcc129b2760d0f8ee2a8c3cb16828af8d1e3ea176fbfbbb097b7c5b06fab10d"
    $a20="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a21="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha256_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="e82fa6befc9aa14d0e2a00c3a203ae9dfeb3dab2a11129f48be1e08264c4ae77"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="1e40a275a84b46f5603c7af871598c5a56bd51197a81a569ca0cc03022b8c303"
    $a9="35cb3600ddd4ffa04f69f0d63033957934464a78f532bafe60dd9b8e83437949"
    $a10="efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a12="4fa360a1ddf2a68eab861d8e866e3c5cf5f9b4189c91bba1b7a12f09e5dc2a56"
    $a13="4fa360a1ddf2a68eab861d8e866e3c5cf5f9b4189c91bba1b7a12f09e5dc2a56"
    $a14="6b3889171631e664046782e8edc458d9d47712fcf19f5b070b374c27926bec09"
    $a15="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a16="1c139a022e0fa9e9a67d4a548a6217b49fc55c2e706f67a357fa9678fa4a77b8"
    $a17="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a18="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a19="16e4f26d3662eff5d75341bc31a5457d54d9a720186ae17bd3f7dbdee91e2943"
    $a20="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a21="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule blake2b_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="0ba13c8438ea68f2d953d9cd3c8c30a0e769152ffb8c2edc824adec03f9567c59f7f19c1ebf7524c04d5457bb8634fb74380587e4ade72de1bf13f8058ee14d9"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a8="750a1f8b290721b551d85405a4bc24d8ccea2ef1ccde4fe95920686cb7a86fd1ecebbd278cd5647478c21de93f0aaa2d639e67648484f5ef29e1072d8181ed5a"
    $a9="00643f2b0c9b53819717294efe1b12fffcf144f3dc8b0755362f5223e577299dc221dd0b17b5a082fa2a63ceaec33de378264a4de934f20e781405d6db60e3b1"
    $a10="9b86d229f9202d4965f9250624d5a5a3b50ddad4c477b250ae1c6660ac998237ac04331eb5fe7d19b2071dc4fd33f7190d8d5c109e9961c1d5061644282c53b5"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a12="d635e57ff54ebe668443c4a746afa5838be065b0be22f5fe737d63cec9ee06351089eaf73081f554fe4c2ded924286f3b5046897c2b49a8b70dbb7baf6c84293"
    $a13="d635e57ff54ebe668443c4a746afa5838be065b0be22f5fe737d63cec9ee06351089eaf73081f554fe4c2ded924286f3b5046897c2b49a8b70dbb7baf6c84293"
    $a14="8a8ac42f0684a9a1849bb70c11e95c0325aededc4c271dafefd6fa5b6579556f6b977bef1ad2d9ddead63449fc8827b6c61d0845baa7633d07860a55ee315fbe"
    $a15="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a16="d7b84ce397db12f727360c2262217dd338953665502e87eba914b1f19870f868fe33545465864ae7679260b266a7708853d023e3123709a3886a03fb6c28b57a"
    $a17="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a18="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a19="e52739fd72dba52bc9ea14a37a065e895c70435087dec69972e4fa2ac6c9a4cf721b2bbd41cf49bc127218b0e4a6344a2db7104ff510497dd6d80956d54053ea"
    $a20="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a21="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule blake2s_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="4ed0f92da3ec1ff94b5ed67bfcb542e5045da6d0c80d4aa7008faba09f58dc7d"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="bb5724830d602461c479a652e85fc8bea49407f8d34442877195a37785fa86ab"
    $a9="911da23c815c526db1d0ca4b792f4962cba09ac0bd90662de650fd5cc29ddb1d"
    $a10="7c34faf3351e3df0d7958ecf36b094a5f3e1b677907cae2469c1ac1c22abefbe"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a12="a2102636135f50a3122fcb77ceb7876e77410a59d0bf1f38216e2be89e204c02"
    $a13="a2102636135f50a3122fcb77ceb7876e77410a59d0bf1f38216e2be89e204c02"
    $a14="57727f4c480364a98620378043300a7eb3aaefa12707912a6d486d4c0220d712"
    $a15="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a16="cdc2f0d214e9a7587651498267c8e1c65347b1061af15cb27b253dc4f2ceb482"
    $a17="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a18="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a19="f1aed680f8feaa588d1d5680fa45a227de69a6613f082fca5508dbcbd1d7a0c7"
    $a20="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a21="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha3_224_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="2e3cbc64ac7ed7c82b5ddb5ba5b4211b1b3517f80d0ccd1018b3f46a"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="45892c5692ace56b005ca7e1db951ba6a8c98ac2ff1af2f13eef5913"
    $a9="5ff358742a8d0bdc1c5ef08f8093046e39f5dc137d53ad1add310d34"
    $a10="fce6b65ff1f6bdf9a6f0aacd5e7a9dc7644d73363d611da652b343ef"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a12="a2e1b6c323964b309ab92c1cbe0bb01b83f5fbb9920546bcd09d2fac"
    $a13="a2e1b6c323964b309ab92c1cbe0bb01b83f5fbb9920546bcd09d2fac"
    $a14="2f58f74ee10c605ee49ffb90102ed51bfc141dd508b9e301815cce04"
    $a15="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a16="0ad7e7f649086006c9f036e85b191d1d4fead179a27848e0deede101"
    $a17="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a18="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a19="b3c364c455fdc02ee1d0a45cf07e428e2473fd969fdfc4d659d3a285"
    $a20="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a21="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha3_256_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="0258bef97afffb99c2403b0584562c4a7ff85cabe5ce4b929260a27fce7bf9f7"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="0c6ac23fb537ec6ad977c5cb7c1f6473ee47c62e1e526de7c1a2f3ce8f0101a9"
    $a9="0a6e90db3a6613fd747b538902881c9abb74be9cf4fe123032d75bb8029ab60b"
    $a10="8630b82c230363dac5b5e7973c7022eb4f2f6f755c288a0a51da9ee0f74d5f5c"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a12="6fe5638d1985847e15e47f474da06bea0ddb48325c73e603c264a0b394ced51c"
    $a13="6fe5638d1985847e15e47f474da06bea0ddb48325c73e603c264a0b394ced51c"
    $a14="735fc8b9602ccb8c094d21b19a821ba99ce10b0aa1d0d950a84854ff0267dd37"
    $a15="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a16="62db7e6e03cf3b0ab19d2e26879af0638065921b47e382680655fbf5252ec53b"
    $a17="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a18="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a19="210c343c1b7a9382b20a9c52d8e279556331c567b65acee55ff17994d59484ac"
    $a20="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a21="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha3_384_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="dbc878f47a4179bc70d92abb8048359b2023ccc79ad1988ad86d7e3e9be98fd87b60361e4c9e3f9f6615dddd7bf84118"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="69ab6636c4ed1174ae277bf1306d2ff2580c7d850349ea966a9eabbf661241c799d7f6d0556ad6cc7546600f7f618650"
    $a9="833d991c35bda030d56491306e30d4ad0d0c216bb75f11fd990833fe1ce5948d72eceb11d292b1fe6f3ea1a77d878ccf"
    $a10="28ae62cdf89ad615a595376f6cf6b515da95d2e3e62292ffd86bf404301afa41f6c3922ba481553d1491a6c5ad8b2a7f"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a12="2b18d3d7fb12eef4d0852505e06c7c0e6907bc53f95690ad1c4c3a4ffa94c8aa7318bbf3ad682656f9051d5a34515302"
    $a13="2b18d3d7fb12eef4d0852505e06c7c0e6907bc53f95690ad1c4c3a4ffa94c8aa7318bbf3ad682656f9051d5a34515302"
    $a14="62d927b0b7a7d09215f47e41f1f19d980a993acc5556050fa17b58d2f9d80a3e7ac0a46ea25fcef938f83eac78a026c1"
    $a15="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a16="69941cf5185b676bf3b1ba97eace90577b780051bf114874c9166a42a6f010d4250011f9c19788039ad1649d49c85c76"
    $a17="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a18="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a19="2f88170320f990ae4e94db441740418835d204cab58361b874dda6cb52104d9446034c8781527733c0a0e0d0df99d663"
    $a20="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a21="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha3_512_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="3563dc2d6b64c2f5da08e9b3884b1e4a56670b55f7e269d039a956e581b23c8233ea525547bd499ef708ce509bc6fa7ce752bfc7e59b8d32af620251c5a955e4"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="922fef93df6adce63e5debf49504b4a81ef5a4a6425c898fc1af352d6d0b2ef56e44b9ac8bc7cd7843168d080a374126450b5258b530c6841a11815dfeca1a06"
    $a9="89cfc1376cba122c6165d66d04a5c22c51fa9172a5e111269622cd4d406b11497456a6ee97c4083a0d8a0fcae54bc5286241cf828c880fb01c1954db50491ef0"
    $a10="f67522486300911fd85bbc40abf440ec940657368f80407a893bb34d1bf44f3b5faab5fee1cf14bcd54d8af0fb8b299127df856a4d6bd5cdba3cb8cce470342e"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a12="466d655ff7b75b83884a7298ff86efd6a6bf91bb6e42b16ff13f02179d3306920e72602e200baff0203b1bc4cada5dd815e454ffffec44c321520ea4c14606ac"
    $a13="466d655ff7b75b83884a7298ff86efd6a6bf91bb6e42b16ff13f02179d3306920e72602e200baff0203b1bc4cada5dd815e454ffffec44c321520ea4c14606ac"
    $a14="28ab56f8fc14b6cd5b75b806d4eb823ac34307fd2a0375a12acb9fb0f31387f625c8a77d436ee396a4ae2071265149a0bae4c1a0cf8a3eae56e45f09a4a4bab6"
    $a15="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a16="8e8aec4a9221034f087648cc318d1d82aac40e222f81c52ab3a2a9e47825c1144bfa2139ba493ee2e9121083cf2ffa3d4649d9b20a6bf840082f3e8e285e1522"
    $a17="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a18="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a19="b94ab49eedc3dd6e0ee061afee22c21f293bdf06c27fa40379af778add1c7019437afa2fbc5b5dfa6a821e541eea81363e4032af02150f46276e8045b7218817"
    $a20="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a21="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule base64_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="MTIzNA=="
    $a4="YWRtaW4="
    $a5="cGFzc3dvcmQ="
    $a6="YWRtaW4="
    $a7="ZGFyZWFkc2w="
    $a8="QWxwaGFuZXR3b3Jrcw=="
    $a9="d3JnZzE1X2RpNTI0"
    $a10="YWRtaW4="
    $a11="cHVibGlj"
    $a12="RC1MaW5r"
    $a13="RC1MaW5r"
    $a14="YWRtaW4="
    $a15="Z3Z0MTIzNDU="
    $a16="YWRtaW4="
    $a17="eWVhcjIwMDA="
    $a18="ZG9udCBuZWVkIG9uZQ=="
    $a19="YWRtaW4="
    $a20="cm9vdA=="
    $a21="YWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

