/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_celerity
{
    meta:
        id = "QVBJtt14chqUx5i8pmjcL"
        fingerprint = "d3875a240d4dd79dedf7b4d4d0c2535ba0063819b73fd7cc08923cbf9b8b7ed4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a5a4e3f7926ead1808de5437067d9f78"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="76b73ff4c9f1974401351eac9887e6d2"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="9e3927efcb1155a64ae6cd92af47ee84"
    $a5="9e3927efcb1155a64ae6cd92af47ee84"
    $a6="09f151785872f8ba88c62604d1e355f0"
    $a7="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="136b867b04030873"
    $a1="67457e226a1a15bd"
    $a2="340dc7172b16ce61"
    $a3="67457e226a1a15bd"
    $a4="3c2646a7737196bb"
    $a5="3c2646a7737196bb"
    $a6="5c34b2fb2e9f5417"
    $a7="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*1658C6044561AC66AA9989C72A20C67D41469F5F"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*A5374BDE7E3C9CC39AD1890AE2B8F51186C06674"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*6E05B74C308FB91D100528DAB5A5C9DD13EB2029"
    $a5="*6E05B74C308FB91D100528DAB5A5C9DD13EB2029"
    $a6="*B362860132F47ABE176507842B991CD0650C98BB"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}KOKhdc8bIuSJqIonexg1Kg=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}gY31l1irJuByAnC1PXKBdw=="
    $a3="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a4="{MD5}zGn2ZsQFjGVqzIgXM0vlXw=="
    $a5="{MD5}zGn2ZsQFjGVqzIgXM0vlXw=="
    $a6="{MD5}nlfiWEjKYXw5ezW2UH4nEA=="
    $a7="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}E93Q8yK2ko/c4qiZEaV/3l3LhKk="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}RmUEiaPziFMpKWLkhwh3jBNQSbg="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}CejuWDcxyAZGAPotX9wlHtOIj5A="
    $a5="{SHA}CejuWDcxyAZGAPotX9wlHtOIj5A="
    $a6="{SHA}FdxFA2VTn6YZ0bT7WrJhYIbFB4o="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28e2a175cf1b22e489a88a277b18352a"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="818df59758ab26e0720270b53d728177"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="cc69f666c4058c656acc8817334be55f"
    $a5="cc69f666c4058c656acc8817334be55f"
    $a6="9e57e25848ca617c397b35b6507e2710"
    $a7="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13ddd0f322b6928fdce2a89911a57fde5dcb84a9"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="46650489a3f38853292962e48708778c135049b8"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="09e8ee583731c8064600fa2d5fdc251ed3888f90"
    $a5="09e8ee583731c8064600fa2d5fdc251ed3888f90"
    $a6="15dc450365539fa619d1b4fb5ab2616086c5078a"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="772e92d491db143f1a7c9ef776e0684f7d1c7077450dac1a99215241bee5427d8f6d386f039cb5b47661fc92f2ca56aa"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="403c86809bf4deebb534120b3441278d16b3e44b2fd264a7caf1c66c19bc81c741c12eec349d49b1054afd0cd4a505bd"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="2845d2352e91ec6c23950ffae8d2068256bfa3328b8be6b0f05e64165a88badbe3d1bd046a131b6584d32e8196a2e73c"
    $a5="2845d2352e91ec6c23950ffae8d2068256bfa3328b8be6b0f05e64165a88badbe3d1bd046a131b6584d32e8196a2e73c"
    $a6="5d61c1cc3d79cd7f3667e544fdb52d28f0f612f21a371f7829b2eccede68abd33a4d3bd9d7830392c534626af31b88c4"
    $a7="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee8ada0d3f4ec7b03c06ea18d778520c7ba9604e0b116fb4badebbeb"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="2b083a6f86773daca4b5272441195a178a8e6e25e7e73a3b9e4b2eba"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="db91cc04dd0f28d4449ff9c475ef0a8d0b129f414f0653ddef42c04e"
    $a5="db91cc04dd0f28d4449ff9c475ef0a8d0b129f414f0653ddef42c04e"
    $a6="a66fe10d2ccf30b0e04081ce304db4670cc631d7ddf3ca5c41848b43"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22bbcb9e5de1c4a19aaa965c115d80760ad6fb61d68a13c2755bdb82915fd67eb6a85ec467345b1420ebeac20cb6b31b7146de7bd566032edf24cb3cfbaed174"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="9fb41e98ac839e0d5b5f18a038a269e34786dc87c7cbfbc9f860ffe9974471f6fa72c63d7e2b1931193541f1f780490eb6c191c32c9d628623d8bf87490260f4"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="116dc22a3af6a6f6e3d4e64c22b3d6d384d7819257043c3c7d82c74c17addf146aa38a5c11f7eced518faf90b94ccd87a5e183cd228889e2d09e11dc0edd6655"
    $a5="116dc22a3af6a6f6e3d4e64c22b3d6d384d7819257043c3c7d82c74c17addf146aa38a5c11f7eced518faf90b94ccd87a5e183cd228889e2d09e11dc0edd6655"
    $a6="ead37dfccbcb3c075bd1380bd5ca94a590207b2779819eafbb4de534be08cd518c9a92f2d9006a2f8e1b1c6378cf799aab6cbb19ccb47b3a1a5116e1aa97b485"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b8180e90c61e2ed545d4fa82ff943f9842a874fd6fc0c6a28fc7f505cfb18815"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="6594a8fc77a70d4a0e7111c66509c0541fe511fc0e401684fa166fe6a75b008a"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="213e88ec8794cce8b7803294ec0992ffacf88abef89f6aa4faaa3db80e792383"
    $a5="213e88ec8794cce8b7803294ec0992ffacf88abef89f6aa4faaa3db80e792383"
    $a6="a3c4ff03c78ff2ede7e8942527a9cb80e95956cbe0d92fe5772890fbc28d492b"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a5ddc62aa7be4d13ebf92fbb613db776b76bf4fb822a855792662dc983cb07e5dabbd0c471976fe1424ec3c2a81a400589e76795e6226e06c7cfec5d86363b42"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="7c9f6370dc07f5ed1ed3365459726c975ffac72cc69bf35397049b93d228a7e52810306b4cd8ae6b580f8254f3807fcb9d0339ac366b7877cb32c72eb774c0b5"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="4d5e70857236af965ee93b8e260157c93e30d29252ded4e689507991566b49056115715af73ec6e8094e78d6bfce5d0f76879c47d969ae20196107c0ffec0bf2"
    $a5="4d5e70857236af965ee93b8e260157c93e30d29252ded4e689507991566b49056115715af73ec6e8094e78d6bfce5d0f76879c47d969ae20196107c0ffec0bf2"
    $a6="94c543f416cd2b4b9c06c31a745b5b578f0b71317cc20d6b18abbad48ff5e664bde6e71e89bf68d22bcc84578b9867abb549d1b3e51b1633ab3b922e3e5800d4"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="865d0ef3f685de5eccbe7f644228fb3a612c5657bae6da2464cfdfe06b0e6ca9"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="8314c99555738c674dc7c1b1363a6e19c08466a4e7807c279d3a7fbb2212be60"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="3b6f88188f890d6d57a648821f8a11f4b796b891a0626d1244a97a3253ee594a"
    $a5="3b6f88188f890d6d57a648821f8a11f4b796b891a0626d1244a97a3253ee594a"
    $a6="5db25a2ebabbf148ae0af5027e9f3eed87e325b935fce924719af02565800644"
    $a7="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d7aa7e09d0857f35411eaa9edbb6e409c55c7561395baf47df4c1ec"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="335b9b5fb1b2e8a6ac3f8aa5544661184010b3c00d5d93da2ec9c268"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="2268df243f3ba7aec970f4326b184d5db233b57082c465d9ffcbc185"
    $a5="2268df243f3ba7aec970f4326b184d5db233b57082c465d9ffcbc185"
    $a6="5789eaaa22f199b60eb6fbf90898db050c4c9b34059f7f5a0efecf23"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f562cbc3f4489b1d3b5d84b97b45ed82e263bfec13b4eedbede6944704df2711"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="a7570e993de49d7e3fb80e62f965991071cdb3b3660032500a5da071166db9ff"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="ad02dd5acc3bf0c2af65d421c9fb4623bd65a9d03d5e6aadca4d64df57fe721e"
    $a5="ad02dd5acc3bf0c2af65d421c9fb4623bd65a9d03d5e6aadca4d64df57fe721e"
    $a6="73e65939b85d51c320db19b9d127680484d860ce45f3e8bfbfb318c4c29c0640"
    $a7="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5b1b0af242b690c3b681ad8e1c0c8d202504fcdd7f041b86d0b1cd54eb04e03c069f8cc5e1817e43c4b2a387691904e7"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="2fec206acf134425d44d35ad36d00a24cab7fca41de03ba021415dc11da227477cc71c8e5179ca067a7db0889fb84766"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="d1ead38489a10222f7aecbf07399721e4d243c8e56fcb0a780b966f905a1d4165402284b852bdcd046a193ff6fb0e519"
    $a5="d1ead38489a10222f7aecbf07399721e4d243c8e56fcb0a780b966f905a1d4165402284b852bdcd046a193ff6fb0e519"
    $a6="1f9c692c2766f2abbee9a8e26e5e3fc0b9fdbb721ccd67bb333078eabbcb8e680eb4f8a8c2cbd5fe8d17390a7eb358e1"
    $a7="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f7f20fd3bc86aa5b99df0efce3caecde11562f88db46cf59daca2d6b75085ff56667c32d35a820b82c55bb6ae52dc04c2e0ec4f9af72d132c4158ea56ba65d9"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="9ef64b874b753eb351b5788f0e16d2cddd3c35f77e67465d830ec1e8e47d16afcd86de0e2132d0fd58d93dd249a874c63dc518fdf6efc63f94d1e1beb7f8d8c1"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="b0e44564bad963a5b8fd84494303289fd068cb6bbdf14f5e70c2d2d20778c7be94a50cf79671add9f3c30354bda46461f9eba1e9934a9038cbc25c9d29b5822a"
    $a5="b0e44564bad963a5b8fd84494303289fd068cb6bbdf14f5e70c2d2d20778c7be94a50cf79671add9f3c30354bda46461f9eba1e9934a9038cbc25c9d29b5822a"
    $a6="01bf3a32baa45fd9dddcdb8b37c4983a4ac7ade9e753cf4373c64cbad34393c2718aa6685adff535922f983128aaa73ca19df4330f46392f2cb89d203bcbafbb"
    $a7="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9vdA=="
    $a1="TWF1J2RpYg=="
    $a2="cm9vdA=="
    $a3="TWF14oCZZGli"
    $a4="bWVkaWF0b3I="
    $a5="bWVkaWF0b3I="
    $a6="cm9vdA=="
    $a7="TXVhJ2RpYg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

