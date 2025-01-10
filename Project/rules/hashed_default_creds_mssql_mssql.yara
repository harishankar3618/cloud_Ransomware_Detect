/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_mssql_mssql
{
    meta:
        id = "3uzitNi1XTft2ZIugdH54Q"
        fingerprint = "40c8f58db2297a59c512ff9366f35d93710c9ebedd723a77e752ec1593321f07"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8339998d3fd42ab9d3b83cd2d9694c20"
    $a1="8b7f283183bf5eaded3080eac0afea69"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="9cb285c0622b8e5e8181a2b3d1654c17"
    $a4="58a478135a93ac3bf058a5ea0e8fdb71"
    $a5="9cb285c0622b8e5e8181a2b3d1654c17"
    $a6="9cb285c0622b8e5e8181a2b3d1654c17"
    $a7="9cb285c0622b8e5e8181a2b3d1654c17"
    $a8="f799d8e152f7385b34319efe44b0e766"
    $a9="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql323_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="739ce4c8509ce556"
    $a1="410b87716417800e"
    $a2="5d2e19393cc5ef67"
    $a3="077ff75a4925858c"
    $a4="605d63e76a0fcaa8"
    $a5="077ff75a4925858c"
    $a6="077ff75a4925858c"
    $a7="077ff75a4925858c"
    $a8="0de0d2393651b07f"
    $a9="077ff75a4925858c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql41_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*EF23B7D8B076353461321AE54C8DB2DA734D1E44"
    $a1="*AD7D041242E9B18AC223D6BDA09E2E0690115320"
    $a2="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a3="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a4="*B867055C61BEA33BAB533EF0900D1B193FBE6844"
    $a5="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a6="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a7="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a8="*97834F5F96357F6E82AEB7FE1FE91759EF69396F"
    $a9="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_md5_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}CifraEgCv9iWO0Ug81wIKw=="
    $a1="{MD5}ozmrt50wB+rIYTekYPMsng=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a4="{MD5}QvdJref54ZW/R183pEyvyw=="
    $a5="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a6="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a7="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a8="{MD5}DAE0wMvr9IvoyVkg9ep0/A=="
    $a9="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_sha1_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}x45HZ1Hua9AFbZ1cbGuVliR4TvQ="
    $a1="{SHA}rjgRUVM/lhejsJtso/ov1rEzTkE="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a4="{SHA}sumK1vbrhQjdahTPpwS61/Bfb7E="
    $a5="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a6="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a7="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a8="{SHA}jQyoJV1zBeE6kYXKhmaoLXphkI4="
    $a9="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule md5_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a27eb684802bfd8963b4520f35c082b"
    $a1="a339abb79d3007eac86137a460f32c9e"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a4="42f749ade7f9e195bf475f37a44cafcb"
    $a5="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a6="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a7="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a8="0c0134c0cbebf48be8c95920f5ea74fc"
    $a9="c12e01f2a13ff5587e1e9e4aedb8242d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c78e476751ee6bd0056d9d5c6c6b959624784ef4"
    $a1="ae381151533f9617a3b09b6ca3fa2fd6b1334e41"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a4="b2e98ad6f6eb8508dd6a14cfa704bad7f05f6fb1"
    $a5="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a6="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a7="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a8="8d0ca8255d7305e13a9185ca8666a82d7a61908e"
    $a9="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="708a30d296765478ea9d0dc885a9dd2a91910a657b9b08056b633b4fd29ef02dc9f1de6f9f857ce34068578e604793fa"
    $a1="d96ee928bb18029b2640bb7cedfd1ac524494a1ac1dbeac9065468050506c7614446179c42328194ae62332e6f7250bf"
    $a2="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a3="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a4="69bae5ab169e00ed30d1dd983a8cb5cedf9b55af477953062c331c12020de26e17291a03df3a24c3c53034ba988557ae"
    $a5="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a6="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a7="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a8="0320db65a65807733d28ff40f180e4fa3cfd5be6d4b6b5220cacb8269ddd2cf15fd379c5994bfa06bff613479b6d0806"
    $a9="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b16fb3b924e301032472a00a31b2f40c96b19018bac9dc2713a870e8"
    $a1="ccc90fb04d0614ccb20bb44d30bee7f985bea6dafd22e2c8d81cb170"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a4="c9a2f5d2d923b4ce105ee3e1943ff5bff91ecd4c15960054752eb2f0"
    $a5="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a6="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a7="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a8="f63497db4871ace8b860d9ca4757a4a77a2494727b1fdb583dd54d51"
    $a9="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b66386d20fce16f959d01b3ea27b3ebbe8f652c92206ef73e5cea224ba32f9a4d8765f06e1767741efd44033e4c466faa1905bf8dd8d5c49c00b52eebe4deec3"
    $a1="23d35367a5430f5d8f0e3f7bc72cdb7a24052ec6ba20fd14400e19d69fc4f8d9c6fe13dbf058b4e91d4ab1454e45edc9aed2a1805a5465c6d911e21097410130"
    $a2="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a3="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a4="804f50ddbaab7f28c933a95c162d019acbf96afde56dba10e4c7dfcfe453dec4bacf5e78b1ddbdc1695a793bcb5d7d409425db4cc3370e71c4965e4ef992e8c4"
    $a5="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a6="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a7="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a8="b3f3ffa101ace22b95ff85ae8c57bea405b6d133de58a584073550fc7944a4482ed40d3c21bd3901ff9f4f4267af300d6f9917afb3ca64834b58024e4785fa90"
    $a9="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a612393342c59ffbfa75d39d4d835b8a9c4c7304f905c8e7c4f0daa3370b9a39"
    $a1="fad5208e113adb5d9bb5b5a1cee8c66af5d079f78526a912daf1b5456f01a710"
    $a2="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a3="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a4="008c70392e3abfbd0fa47bbc2ed96aa99bd49e159727fcba0f2e6abeb3a9d601"
    $a5="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a6="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a7="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a8="4270ceb3db39fc36daf9216bd48a5763c9823a17344f41cf00a44fe5fab4586d"
    $a9="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a39919492dcef371cffae3e7e603767e3ec4b489eaad74e4f520f8d143d7d6d8abf222a05abfa8908ece125f9bee7d0a4778cfe28599262ab845a1f1c718896"
    $a1="00b53f434fa7caf0a2cf41c073917ab68e16a1283fbe4856d69e0ff531d72fdc099adb1fc0126f9af2f585801cff756829450877acae5686a463d1616535f80e"
    $a2="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a3="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a4="41efa2ee765dac718e8122c20caa1d5a8157bbdbcd1445d7273e5d0be9e79e16f6e8c127ab384d83c8fc70233138b0ccc59469c1e2ef3704f46740ee688a7396"
    $a5="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a6="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a7="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a8="f7f173a05c4ab68f3fead025ac792df5d22a3bcecff6d0d3f0ff43e204e1e035effc46e675800ab2452870b654cccad286dcfa0e799cfe18208291d12455ed96"
    $a9="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d59a7cc6209c3f94370d665a9dda648e474e83a83ba9a35d3b1bc55aaf69747"
    $a1="ab97aaf4444dff189620a33572991c8cd0ab8294466d624b4ed610beb13f2aac"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a4="e80220afa6bd68f7176903c33deb49f3d32ff3cd91668af087910fcb73180c0c"
    $a5="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a6="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a7="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a8="8a7a4fdc3c3e51dda63342b46acf87f375869c268a61715ffc5331e11f46dfa0"
    $a9="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="08212cf33081e27a009858c2af540145b6a4539ce4b2336fd8e8dc25"
    $a1="57299d8b3113c196fa5a93d407903351d730270cb2cbe9aa34958c0b"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a4="96dc79212c6415df2536c4a4ed4905c3b0a25e803cb609375eb0a6ae"
    $a5="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a6="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a7="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a8="55974149b1a5ac08d4b2e027e3e19b9281c808a1d286f22227a4611d"
    $a9="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="589e39f67c3fb3ad3292b34e1928ff402264934ef93f9845f17179276148a1eb"
    $a1="09ac018b1cd74b73490289e6b6decf79159d75b94264cae5ecbc535b2778427e"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a4="5464c64a7c1c8f0a05a8cd2382415898d3a2c5e7b2fc1c22cf30ac230b7801ab"
    $a5="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a6="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a7="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a8="dd59e2bfc902edf91244278122a23ef76b3d7cf9b5e1be716b441c9f39962812"
    $a9="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e9eb23a06d38bd2cdf54509a7a62270886c22f3aed98d4173ce790dbb760cf39449a57725192b88e7dc0918a431c8f0"
    $a1="0354e661dcae4f7a222c7ca552a29feea03f5b4723e52cd19dbe44d528e18afcca8f0c33b9cf2139b74fac902771fb6d"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a4="c75121bf587b6ce29d05dbff92c5a85eb4eb9264fb4edd69b07c9a19e589ba24088dff4a5ce2be8c7b34361c54d58db0"
    $a5="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a6="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a7="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a8="dee302bd1a49f7ae8f4f1a9f7cd9e4b8668d95841a68c9608960d00ac13bc8221938457e38408f354225fe7b7e110b41"
    $a9="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81b9a4c4774e36ea76916431f85dd466081d6d6049e84047076923ae8e42e3688516f8bca0ba8931e0e8a9a720cd41849e033158c34d272863d9e76cd0b1fdc2"
    $a1="50e617641431d65dc867f4b8501566a518e3a55115e0aa2772aa34f39445a75114eec29e00f8870dd2d65bcc9ad9c3fd735257a4cde89906c30d30666e5e48a3"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a4="bcc03f9763a44e3f3123441603395c2267c019f44d1a82e2915416804c9f8889ed2b543404ae4c6d22b7b8bf829ab8c60b02c593058191d274e5425234e7d5cc"
    $a5="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a6="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a7="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a8="6dae4955f1d61bc13e9a7c91f05c295586996748f09f01971ba011af4e5c3d26d5e7bcf9645dc4773b09faf679b8b90afc5fc85b6b7436d6f5dc82ffc01da7c9"
    $a9="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QURPTkk="
    $a1="QlBNUw=="
    $a2="c2E="
    $a3="cGFzc3dvcmQ="
    $a4="c2E="
    $a5="UGFzc3dvcmQxMjM="
    $a6="c2E="
    $a7="c2E="
    $a8="c2E="
    $a9="c3Fsc2VydmVy"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

