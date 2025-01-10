/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_next
{
    meta:
        id = "7U88nvYCoDWzCn6jDM8Xfg"
        fingerprint = "f06051ecd009a18fb43734de83741fa81b882f75a07aa1216e4744d07dae914e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="942eb66be76475de7a06013939eed27d"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="e37adf58eeed64deba316c9a84e5ebcc"
    $a3="e37adf58eeed64deba316c9a84e5ebcc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2043bf2b760173bf"
    $a1="67457e226a1a15bd"
    $a2="33de3de876f78788"
    $a3="33de3de876f78788"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A964B1F920D2FAD80C19741A8113BBA6E682BF56"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*B19B1DC81116103E1A5C618E10A92BB1E1DA6D62"
    $a3="*B19B1DC81116103E1A5C618E10A92BB1E1DA6D62"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}o21uzxM4jh5UGVkcHQiH6Q=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}2ZK7jetyHloDLOQSMfsCzA=="
    $a3="{MD5}2ZK7jetyHloDLOQSMfsCzA=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}kVNYe8XF4gHz40mlgfAf4BQ7VMI="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}d0zumXD4EpKOl9vsi0a9GE1pDf0="
    $a3="{SHA}d0zumXD4EpKOl9vsi0a9GE1pDf0="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a36d6ecf13388e1e5419591c1d0887e9"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="d992bb8deb721e5a032ce41231fb02cc"
    $a3="d992bb8deb721e5a032ce41231fb02cc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9153587bc5c5e201f3e349a581f01fe0143b54c2"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="774cee9970f812928e97dbec8b46bd184d690dfd"
    $a3="774cee9970f812928e97dbec8b46bd184d690dfd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a11faa04445c9a632c733ff8787823b563dede908ef16e033e50e35a52861988729944c0560a01e90a0c89d688d77e0"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="d3ea14b8ad2c447849fbcf27105f7b943093ca6be70cfa3726f62c9aa68ca6312a6f73c8284ec2904816028787f763e1"
    $a3="d3ea14b8ad2c447849fbcf27105f7b943093ca6be70cfa3726f62c9aa68ca6312a6f73c8284ec2904816028787f763e1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b9bf26ea864b73a48c7c8eedd41822605a9339a064426cdd6485c182"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="49b929d8c8d228f6a8d06123c4c5c9abc7dd0b0a98af8c0e3e92ec76"
    $a3="49b929d8c8d228f6a8d06123c4c5c9abc7dd0b0a98af8c0e3e92ec76"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e03a8c7e7b54608c1aaa1ac78e4e9bbd7e70466e4ea7e629daa6b0571290dec441a60444f6467bdb51291873708ddb9c1d1ac57a37ef4f920fe17794440d96d"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="bb8e34bc9455c62c8ab10cfa7cbe0d80e9e156f5341a8c9c549e558a17942bf7b900262e29afb24232d4baad598f326caeca95a02ebefba8c5bfd5cf71373c17"
    $a3="bb8e34bc9455c62c8ab10cfa7cbe0d80e9e156f5341a8c9c549e558a17942bf7b900262e29afb24232d4baad598f326caeca95a02ebefba8c5bfd5cf71373c17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d648266682e89af95d2fd0f4e69e12818b89740e2c780eec89e44ae5892e5932"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="fff54f2073829bb9f53e03f1a660ac1b97005b09bcd539d00fdf77b8ab3960ea"
    $a3="fff54f2073829bb9f53e03f1a660ac1b97005b09bcd539d00fdf77b8ab3960ea"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e38c657b4febf840cd67451c2a18c40360581064289f2fc07be57b523ecf84fda49ed03d9a9f0d58c6b8b99634fab7ce9a95748a36747351099c2a47066a3f3e"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="8ab30378335f158b64a6d5a2865df48c4357c47d192f9dbd908cd79264cfde2b185ce3634d471e3b2e05f524afb6929e91f3d00c10aba2acc17e0e0e767ec8a7"
    $a3="8ab30378335f158b64a6d5a2865df48c4357c47d192f9dbd908cd79264cfde2b185ce3634d471e3b2e05f524afb6929e91f3d00c10aba2acc17e0e0e767ec8a7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b04fab18cc1da79a461571efa1db7ebdf0e6d7687e4af47296763a4285e7eefd"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="6780561953cbdf18b7ad55ace3bf98a2ea496d5c92472faf15e29c5c0736cfd6"
    $a3="6780561953cbdf18b7ad55ace3bf98a2ea496d5c92472faf15e29c5c0736cfd6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db8be03ad95b60db24a1b3ab1492a48bc3bbf9f6fcacbe79fc70efcb"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="ea97e30a08153a029bbcbc81f26dc49de73ee31dfa70c494acf66233"
    $a3="ea97e30a08153a029bbcbc81f26dc49de73ee31dfa70c494acf66233"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bcbc31574e376353de7b4fa2a9b895635e8129e6e49d61878076cba39b50dd0f"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="a2200db0b1a533ccd99538f6ff63a42f47b192c1392ae8847d46a56a0bc2973b"
    $a3="a2200db0b1a533ccd99538f6ff63a42f47b192c1392ae8847d46a56a0bc2973b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="253901e35798fc58539cd8a8d6558135b00ed1bc708b4e2a53394097a4cb4dc9a28ec019bf5f13dac2811678dd963c34"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="725b258768583ec6a2a6a66d6cc95f5d38e9da23a48d2db7d1b18ccbce3572fcbd6e61b5e7f8cb72b009c49dc502227f"
    $a3="725b258768583ec6a2a6a66d6cc95f5d38e9da23a48d2db7d1b18ccbce3572fcbd6e61b5e7f8cb72b009c49dc502227f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9700a92084a378567fcbfc158aa1e53a53d06fc4cf2f2b3f0a08cc0c41412c0a495df571928a75aea875027705a4aa793b0f4f7a0f9e32287e9a5cc2175fc3e7"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="031fc2625ed64bc0273108e7f60005881846a2625569ea6f3e303d8d5748f5017db27bf3971c1f6fb763bbfc53d29ff743902771c08c5f61ad62af7cb77ff3c3"
    $a3="031fc2625ed64bc0273108e7f60005881846a2625569ea6f3e303d8d5748f5017db27bf3971c1f6fb763bbfc53d29ff743902771c08c5f61ad62af7cb77ff3c3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9vdA=="
    $a1="TmVYVA=="
    $a2="c2lnbmE="
    $a3="c2lnbmE="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

