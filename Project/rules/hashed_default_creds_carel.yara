/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_carel
{
    meta:
        id = "1ndgzxkqW1AcPKGagqD5Nu"
        fingerprint = "27d4e82052d8d4e44a85027c819cdfd58b6c26cc8a58fc2203b25dc2eb951459"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e222d2accc784a8a5b785ca939977238"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="bd62a39f78f9d8e5e7f18c45c08ef9b2"
    $a3="e1652f41fb194c8d4ec0cbe4a29d5aba"
    $a4="82211d6de11c4edb25c036c1f969cfe1"
    $a5="823893adfad2cda6e1a414f3ebdf58f7"
    $a6="cd6696218888fc07ff3bdfd044045b06"
    $a7="13c2c51c12aeee72a9f4bbf7354e094b"
    $a8="4366e392dbf0dd27fe6bd977792990af"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="209c6174da490caeb422f3fa5a7ae634"
    $a11="209c6174da490caeb422f3fa5a7ae634"
    $a12="1dd14c820bcd1de7fbf36f2f8bae21b7"
    $a13="fb499578a8a2f14b7801868946ff2d12"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule mysql323_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6716cbc473d31e6c"
    $a1="67457e226a1a15bd"
    $a2="58477f9f244b097d"
    $a3="219dff356b14eeb2"
    $a4="2164f5686c7d538a"
    $a5="57510426775c5b0f"
    $a6="5bfcef617378a992"
    $a7="2c77d2ab1a6c61ff"
    $a8="020b226132b5cb46"
    $a9="43e9a4ab75570f5b"
    $a10="43e9a4ab75570f5b"
    $a11="43e9a4ab75570f5b"
    $a12="0472b3b734bdd432"
    $a13="3eb99490241191cf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule mysql41_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5999B676A27C3F09595EA7E474A630190D9DFA0A"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*7F197929184D2FF4703EE39C9ACB538CF773690B"
    $a3="*3C0914F73A6E8734370D90FED73F5A0448C19D3C"
    $a4="*067FE572F26E17D78F0D63F57DFFC49841898798"
    $a5="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a6="*4971FA2AEBC3A3DF92BB304C2784CEE83CB2C315"
    $a7="*FD8BD21E333105A80A16759310D133CE1DD8A840"
    $a8="*471CD179BF428F243B07B8FECDBCE0A996987E8E"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a10="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a12="*98019C71C7E00D5A16FEA2C358E8D8D35111F31D"
    $a13="*7F571BDAAAEED0D2E6E1DE51639F4F317653AE67"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule ldap_md5_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}b/8mVWId6Vexi22Cu/UBrA=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}UICkX2eb3sVLlam+UodM5w=="
    $a3="{MD5}+1l5Qrm8Dk2mOJbQ/ZepPA=="
    $a4="{MD5}OEjyvE/AX+s19SkaM2+kvg=="
    $a5="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a6="{MD5}Jltq6eErgV3VJJmD+jDQSw=="
    $a7="{MD5}Cs3jiH+JNRo4VCgv6JkTnA=="
    $a8="{MD5}U3TpVsiDvCYEti+Uv7WeZg=="
    $a9="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a10="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a12="{MD5}h5ylOIVH3z2QckqE71DblA=="
    $a13="{MD5}suCvV7lJT0l9FHIkEXAF+Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule ldap_sha1_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}f149Ll0oynDQmreXFP0skCki5WM="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}eNtjY2DLQ2AZUXTbC1zrtHyGbhM="
    $a3="{SHA}YStDYnw4AOiTMQa2hUjCm/C/88M="
    $a4="{SHA}FwKAyaqbY280wCxiNjkNhf2pO9M="
    $a5="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a6="{SHA}C3sF3lB0Gs6ULKYOHQfEWoavuNs="
    $a7="{SHA}hZwS68tLq/E6axblDrTs9ybuOAM="
    $a8="{SHA}G1+KKl2Ks3t/uqY/UyAKotfGEsY="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a12="{SHA}hsTsnA8iS9gMbXzKhTflRk+ZZr8="
    $a13="{SHA}qyv/UV35yjX8fKh0MKbFZCZT5Lk="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule md5_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fff2655621de957b18b6d82bbf501ac"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="5080a45f679bdec54b95a9be52874ce7"
    $a3="fb597942b9bc0e4da63896d0fd97a93c"
    $a4="3848f2bc4fc05feb35f5291a336fa4be"
    $a5="084e0343a0486ff05530df6c705c8bb4"
    $a6="265b6ae9e12b815dd5249983fa30d04b"
    $a7="0acde3887f89351a3854282fe899139c"
    $a8="5374e956c883bc2604b62f94bfb59e66"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="21232f297a57a5a743894a0e4a801fc3"
    $a11="21232f297a57a5a743894a0e4a801fc3"
    $a12="879ca5388547df3d90724a84ef50db94"
    $a13="b2e0af57b9494f497d147224117005f9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha1_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f5e3d2e5d28ca70d09ab79714fd2c902922e563"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="78db636360cb4360195174db0b5cebb47c866e13"
    $a3="612b43627c3800e8933106b68548c29bf0bff3c3"
    $a4="170280c9aa9b636f34c02c6236390d85fda93bd3"
    $a5="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a6="0b7b05de50741ace942ca60e1d07c45a86afb8db"
    $a7="859c12ebcb4babf13a6b16e50eb4ecf726ee3803"
    $a8="1b5f8a2a5d8ab37b7fbaa63f53200aa2d7c612c6"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a12="86c4ec9c0f224bd80c6d7cca8537e5464f9966bf"
    $a13="ab2bff515df9ca35fc7ca87430a6c5642653e4b9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha384_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b4ef61652a805fb93c589ab76b6b69e5edc5f8253555fd287334e2c70bfc1ae843a77ed357f957e361a0dbd10975671e"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="8254f988ad2d54011453d89d1b599a1df82ea03fc64d0f7d28727815e4f12df5e81737b9492192ede1e16f5ef4bc41d3"
    $a3="b2394f271560fd38c43a015c1bd2ebf6ef5c16220d4ec912495f3bd606e352cb2c001148a7af463c261e2f24168d5eac"
    $a4="9955e839189f954aa7ef059a8cda487c82e35fb96284b95f6ccd4f049a4ffa264914633a44a3b96da78c5adfc3a39534"
    $a5="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a6="aa5ddc5015acd038dd0741e0bc3768d5842000425f47810c9d0c9c495d8ed939677f7a7ebcda2628758be13718211f90"
    $a7="8bf406a777126d0f53e43c230b9d55746ac1ff5e5b8cd5090a9ce1aa9bbaa508cb9046bb5afb23ca4742d476b8b98dac"
    $a8="0de7c99fc9145cb5c8385f3df2483785778a210d2f466af9ce811c46f9699823095b7f9f0d19d9383a6d054ad60be1ab"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a10="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a12="8cbfd7785b1b9ec76a26eb24aaaa09110b59edc72449319e3636e0f705dd6238fddf06fefcef3052b07b62ea67f86662"
    $a13="abf96f2ed771d9f7d6de913e112d31c7cfc58c8b30643149bb88efef03b94e3a5ced8c13bd4840f4c02795669e1e0fab"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha224_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd0e23c742bc3298128817659a431d68421e77d4da85d702563c1608"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="6cc18f4090de553413e94f6152a40d2a2990ad6bf8c09a31fb11f352"
    $a3="2d36617f9530f3ec59f9bf9b0b41d524e5d773aa3efb6f7def1115c0"
    $a4="71df19a0b41572e1da049f58bda18c831e1ddbf2e73954a976456cb0"
    $a5="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a6="27982fca7ed3224baf4d20c8b958a934d4d4def1a97c1bfe7e571563"
    $a7="24f0be6b3f6173d2c7ff7953c52837be32fb6a6b2493ae6400dafb0a"
    $a8="9443b63a009b867ff1ac985550fd67db0573be868e58e5abc184d10c"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a12="c46ae1c520133e364d5b45bd235e3f1e324b1ce2c8748d217b23edba"
    $a13="9ff2e07b7649a2c0317a6a8d57057b4ff621385b13a045a71a014241"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha512_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c463d2e37a30b59654286df095a3dae4dedd3fd70517da07753825a3ad3e4333a62ce2ad5049e6c81d601607d18c901e73dc6e5e3474bc27e6ea0402673b92f1"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="ffe3f4e6ac31e3d5582426003b4fea206d34fefc88252ac2053d17d13440870db2d28b8c0892eb3def5e31cb7d6c545165d86b20ce5a8b38283c68cb04256635"
    $a3="e0562be9d9e7101b8d2402c3855f57b38d96caf6889167e58189d5af876d480c13def121e8f5cc71c5c8029c31b4197e6170610cdc5b10d9361795e2ad584266"
    $a4="e6df825e83e8545a7c9bdc397ca4c87a7272cba9559910c4807d2e45622918fe5267b2154d3719d7585e0464aae07d1d23586f640ed37d41e28897b8f9336e83"
    $a5="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a6="eb1a7891ac4555572e95fc02b111ab89b6f9448b553a446734894545f63bbd70ca9ad4eb872d3d27c30a01e7eed182e014f41c90515b4da71a022a1d1efeba02"
    $a7="edcbca4a3a8b6016adec2851e7a555f0bf7b733016a40f0fc2c9dfba7f608bf19d4785e713388730d7d4a1d78f2ef13be1e55232f5eb30482588fd8b25791c03"
    $a8="21d35c8614e88240fe72493c988e9226b5c6dca03a16a7ba4563cb6a5f79056357864077f9afcb42cf064aae0e6680764280fdd4130316005401f854dbcd6b3e"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a10="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a12="b8939f8099599c0dbc2a976a6461f2e7ef345da9bcce7b1f71486212cee8c24327f377e7bd5be8b70c55388185e2d5cad29bae2e7c0cb38eb6f744ad7fdda87d"
    $a13="7e18c2c27623ecd2349ed8250ad949781ece7ec955580d56d5903cf087f8590bf86cf2d1d6a543de6517e1647f9ffa0178157bc0a9e0214d89cdd03a95cf73ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha256_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2de8a89303d3ff0ac243ddbc8ec7926c19d3494a986e110b82e91e0671f4d803"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="48144a5881f37fa0108194419df0de6d46f5bf1e1b60c2706d3377a02db4a000"
    $a3="ad961909dbf6279c4d8a45b8dabd9a5307b02478e01381bd4e7db0412b25e9e8"
    $a4="b681d7a7ae7d77e42f2775527507bf8767d8b028c75e8b87cc8084d73d43c115"
    $a5="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a6="744e3df6af2898cb4888fb7567f4e81396c55ca0859670c293b0676c9ce9fd4a"
    $a7="93f1800279c7acd3e7b55b984f5a9c4ca16a35c54e1d96649602f7d9aafe157b"
    $a8="1fc7a460ffbc5d34af0b6b7fd57f3d55ed8551313c6f1be4f77c7db3eff1e89f"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a12="98cdf893ea9d6e34066b434353c4243e63e952ca11df6ed2d15d0f5ca78d93dd"
    $a13="fed4c5499a7d18e4054ab175eb87b19f39cb102b1d72adcd471052b7b9e5fe45"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2b_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c26a374b47b8f8604054cd867aec29a5e95e024847fadf63eded2cfdc5c33f363ea8bc8d0ce2a14421ec384c5a112f2f20fb95a0fe568897f17477799c331ba3"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="3708456d9830844ec2928ccf88df90915b1ef08a68fdefe8e5e30b1395b416d2e320faf6949b71f8368b3410f01eab136f3d747afdc319bd7ed6314d8945431f"
    $a3="e73759ae7abe9a78f2f94bbe31e6f8d037fd33378919cdb8af11d2c38ba83449ad6abc3736b5f2f82186176acacca41be5710b7abb816d36aab4fb80d64cefd9"
    $a4="f94f97f1b9da8ff630d7eddcf58638776158e0b60a90fef9eb66a905e303b8ac05022eb1ccc4f86c4e6215a019455a059f21a0b47ab6bf7308896fed02bb79e3"
    $a5="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a6="f36fa1fa0b28dc239916f1640e8c0ffd4d5ddff67e3409f1b060d1afd933b1e52785f9d7f2fe862f90f94c9816a91a0d1213d446f39b02b52d775e731646deb8"
    $a7="6d0bc0da78aa75d4e3c65fa72ea422bfd1845131531059ea09862c9eb6b43412dacc856c0a19ca0248bd223477992f1b247ed6b7eacc22cdda1556fd3b3b65da"
    $a8="702d8f6f7c661b1aaa88cdb52e8acc25c7ce3ff245cb8773675dba075a645093876de67b99597b601c451a810654e781534cae068e5cda735603a24017db3cc9"
    $a9="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a10="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a12="3610d3ecfed1562093c4c41a7c39ccdf5652cfcb74f28639925e4ea327c26d7ba5581fd0501563a19de6465220cda144e51ade72641262a9099571376d83f1ed"
    $a13="c7f8b8a85c2184ed3ce5249dd6a8c872d19197f4ad0356bc5881d89583f3e2648a52102908523dcf59605a0d8d0e08f4f85ee7ae27a9ddcef2ca69523895da69"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2s_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a740d7e996aa82241f2484b1337afdfb6cc6b7ef4045ea83b9e47ba0104e949"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="334b0ca2d64b32b82cfe1857e6d9ffe07896f630dca6602e2c32b7901293a758"
    $a3="d1e09d6ed41d3d01aef6d3db8a4c7fcba16ef21b5768e365062f57c168c4a8ae"
    $a4="a623fe8afc873a57c6a4c5a884031d72aad39e8cb2c1409792254325836d6621"
    $a5="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a6="420cec69e54b2fc0bb3e50d1c1e2e38ab991afee1bcc457fed70915a13fc0c20"
    $a7="0fa2f331d3c86ff7af4b1ea1b6f2c7db4bdeffc24fb646cd1ffb8a8fe91f776f"
    $a8="f65651439abadd7c269c010fa95c0cda02c17f1daec30025405216dee1818690"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a10="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a12="815aaf0b2d8d3e193a9fa163a65fb90cc565a386e43e670c4905f47a11a5ec9b"
    $a13="930b1ff490516eb57486c34411040611a9254820cfa0e08a22bc80aa8647c309"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_224_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad645f91952b93bb6c48129a850609559c46e2f25f70ab1efc683da7"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="d38f285df1681a89f9619514a37271a60b04a96c3d96213c1b701a95"
    $a3="2cf101bf0ce335f6cdeb360fcae0e3bc9ebf70286ae2c0a0032d9064"
    $a4="d5b04af892ec5cac5ec02f32e4705d8132b80de1d042ce5b0386b857"
    $a5="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a6="89ed8db6b9f37af1854e9da36f83cc0d70ed069f6d3bc31a1712709b"
    $a7="339a8c57706b2633624e1d190fc548f399276d7dd6a2c5c6e802f162"
    $a8="712b9d695575b896ca57a37f2e0c4b7838fbf50cf1252494aca1cf37"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a12="ebb8d1bcfb73115fa144afe02f7f639f8b373842669ed84f1b64ea1d"
    $a13="d26bab4e9b50cdc179d2db65e32568eff47c15f45e3770719d5f48b3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_256_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ce879e5ecffd8bdd8708ad528b127fdc5af62bad9391abeea3cebd5e5c15c6a"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="6f4e7231414dd68f72281c05e2febce9570c7afd82849bf72ec655d2bf06b968"
    $a3="7b0259861f4636043c6ba8ac0462e5a6d28b62b18f466e06c181a118bd33660b"
    $a4="da056aa026df9262cc36c7dd75546dba5eb3d1772eb38688deb4032bdc1990ff"
    $a5="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a6="d40bc53ccb3df613131e72e46c8bbb2bc05030a02cf4ac81223dfc224ee03f8f"
    $a7="ec4a58942b4dac0953dc886ad03288e9b98234285e670ce2da803a782a38c952"
    $a8="85e118c98aaaa18fa295ad12e12929effe564a02d625d5a20e21503a60a894bb"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a10="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a12="f7649aa351d3e686a0a534623b441bc90cd9e527aceb9d03efc43bb42b3138ac"
    $a13="8f775eebf93f2f6fa2d5b0e6488550621b7d027f6d212799bbe60b991f70640d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_384_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90cd7c569836b5b98b3f9cbd011bfcfeda26475b186a648f05a5db70301e2ccd7020caeda91fef10e935dcb0d8c467d4"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="1872bfb64a427774b1403b959fe4a5727d2f55a728f9926e0ec62c98c465b80caca2bbd7240553d47ab8e40b548c9030"
    $a3="dcaddc1fa1c13b35fb67fc6ec2ac25ece3d28f0462a61f0b503bd5f5b8b9c3df0827166ef1ded08c9bb918d4e180d3bd"
    $a4="134a8b4be353f06e91e075d2dc7ec0f6b5c0c51a0dde9726c4484e2bd09412982d6b140ef79486f7b24d751740163ef6"
    $a5="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a6="c9a75c32ba7a7e6e85316a0810fb78b6d093ebe77db18f32c96e64fff6b256b6910f151a8e01da15eb3da92d8855ce41"
    $a7="b30a5277ac3f0bd4bbd555d40c7a80e5b187624a9424179fa8fba824130e5cb197f85da532885f0630fc37f8b73f11a1"
    $a8="251fb475c089348f26e88eadb8e7175f66ae87326c859916a101ce72891465852ed717ab647ca3fd65da298b1e6814ce"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a10="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a12="f10900ad904232aa227088a65945155469675597b8ba04d7e364caa2edf1213ae3b87bc3ecf9b9cc02773540a42dc56b"
    $a13="764c8195d10386bd9efc2b79d1ae9518492a1efe7a714f1980223249618a85e3bb0af21c1c3052f5e2d996b0895957d6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_512_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="966b4fe3e73f333c646c27fbb7ce1775e5d6ab7ef3049b8b744633947fb1bfc5f7b97b977bbe53e2a1c03b6e75e5e52a954b73e0f97fbf1af3400e2da40ad5f5"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="09558640f7654d5c32ec7d54251104041d8f10aba9b8335909da23f1b8a989d4d161f8314814896a9804b73e8eadac6a71effa023aa3d85b1603f2213c4c512e"
    $a3="3c177ed17b801e3a825e264e0877b1556e0ad8c603245172937ed840dfdcc5a96c7b80e2f6c72e5371b9c5a54e45dc7160bfb76c485a93908d1da691a2f38f79"
    $a4="12dacac848b55fa0faad79d5a0e559dcb3682b0d96052bd1f1bfcd31da7a01717e0872c50aab7d2533fe38179b6d646aec4367891404beb30935140f39670ef0"
    $a5="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a6="d959d6edbc5408727afe0149deca7e072af72d17cb681d900a863b5bb89fc7b8e86a3ee800c28d39581867474a317998daec33cb8f2f18f2ee2afe2b2dbe1e3b"
    $a7="485a32f0e4d8ff6eb8f08c48cd1cd5715322de7f932e8b0be84a0e14673e6aaaf5f9f84ecd53c3fd60f63d2d6215d5cd12f4699c39b3523761b445cb1c37a1a4"
    $a8="751294b54e6941a95f3fc141df06dcf97f6d923c8e0b9ea365b0e1a268c0d6595640a087782fd37b49d73fc8a376229a0f3f2c0f07291051ab3420b9b4d909d9"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a12="730173b90025a45193d85ab72578489fef51e7d8e7861145b2a4c22441e3d516174d8d7df80ec6391659679ce1fe55475ed6ce8829dd17c88a301c3811bd7a18"
    $a13="c18eef2d8c54f39b6e61cc2e7ec2c083a2049418560b2c569b5c8024cca829c07e3b6b26d091c5e4c71c37adf48fbb437f2fb04b373aa20a73a8ad1359519f5e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule base64_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9vdA=="
    $a1="ZnJvb3Q="
    $a2="Y2FyZWw="
    $a3="ZmNhcmVs"
    $a4="Z3Vlc3Q="
    $a5="Zmd1ZXN0"
    $a6="aHR0cGFkbWlu"
    $a7="Zmh0dHBhZG1pbg=="
    $a8="YWRtaW4="
    $a9="ZmFkbWlu"
    $a10="YWRtaW4="
    $a11="YWRtaW4="
    $a12="UFZSZW1vdGU="
    $a13="UEQzNTAxMA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

