/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_sun
{
    meta:
        id = "Ea2k2nmnV6K82cSBTPsIY"
        fingerprint = "e58956458fd5e80c99f31b3a45cc9824b43c76efdb45c5eafbb31b0ca7519f8f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="6597d9fe8469e21d840e2cbff8d43c8b"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="c91ad2f7a9888288c71b8dff713a3075"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="6c65c1d0126bc589c803ffaf07025c6a"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="b5e3b0e4b2e4416607e23164ac0bc2a2"
    $a9="b5e3b0e4b2e4416607e23164ac0bc2a2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql323_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="16d7f906289d77b3"
    $a3="67457e226a1a15bd"
    $a4="2d1d3cfa622bda8a"
    $a5="67457e226a1a15bd"
    $a6="0bb219c6194e880e"
    $a7="67457e226a1a15bd"
    $a8="789f0730263347e2"
    $a9="789f0730263347e2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql41_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*7ACE763ED393514FE0C162B93996ECD195FFC4F5"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*BA2FF9A447F91BE52A96D8FAA17B3901B97BAC30"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a6="*D3DA5E0774CA4DF8B264CCE3DA692E5559554368"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a8="*64E58932732623A73E5C2A3CE1947266089DB72F"
    $a9="*64E58932732623A73E5C2A3CE1947266089DB72F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_md5_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}TLnIqASP0CKUR3/LGkEZGg=="
    $a3="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a4="{MD5}YDXXoXD/l0WAaMeeZDEKOA=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a6="{MD5}Oxxbu7/4UV9ufa7t1cm1cw=="
    $a7="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a8="{MD5}l8nGlNmfcp4aSJQNCzhqmw=="
    $a9="{MD5}l8nGlNmfcp4aSJQNCzhqmw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_sha1_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}+pvrmeQCmtWmYVOZ57uuITVghrM="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}96hOEzgUa79LJaJ9FLE4hIyZH/8="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}y8vHf1ajHNz5jXtzFeZH3SHOuOk="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a8="{SHA}eT0FIDRNTjWuSbwY/VHJExsAvSo="
    $a9="{SHA}eT0FIDRNTjWuSbwY/VHJExsAvSo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule md5_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="4cb9c8a8048fd02294477fcb1a41191a"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="6035d7a170ff97458068c79e64310a38"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="3b1c5bbbbff8515f6e7daeedd5c9b573"
    $a7="63a9f0ea7bb98050796b649e85481845"
    $a8="97c9c694d99f729e1a48940d0b386a9b"
    $a9="97c9c694d99f729e1a48940d0b386a9b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="f7a84e1338146bbf4b25a27d14b138848c991fff"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="cbcbc77f56a31cdcf98d7b7315e647dd21ceb8e9"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="793d0520344d4e35ae49bc18fd51c9131b00bd2a"
    $a9="793d0520344d4e35ae49bc18fd51c9131b00bd2a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="7d49d02c105312b2b69de69141b27de1f4f4c202b4afb19d7ff7ab9849e9ce2da165a87eeec971bca66c8eb8a9243f5e"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="fcedfb9c8a81fc4e3fed3b538192ec2c4833400459db0987ddd68a097caaf43aaadd25f76bd4bc7e83d958f628d0bfc7"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a6="863a40e8172ab8cc10f35ec8292b49f7a9cc065bd40d99820836f90e83f187b149227a26cb0de22cbd15491c59a518b2"
    $a7="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a8="0ad723fce2fa1a269d14fda8a3ca2e4c1a9881fa9a1a3f087243c39d3d1f8d8023d234ef1cae8202c5d9fa8c59c775f2"
    $a9="0ad723fce2fa1a269d14fda8a3ca2e4c1a9881fa9a1a3f087243c39d3d1f8d8023d234ef1cae8202c5d9fa8c59c775f2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="d44d697d0b8ad27b1d3b323b1b438db88058ec1f0f21cef6a6629875"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="432c12b9bd30adc1cdf98985953a9af1c17e25fa6df183056583ad31"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="cffe0ece075a3924ccd9adbc21ce32260b0088307e587e3938a377af"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a8="f5e5cf522be63f36322027ac57951409e28a73c7a65e015d152251fd"
    $a9="f5e5cf522be63f36322027ac57951409e28a73c7a65e015d152251fd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="f1891cea80fc05e433c943254c6bdabc159577a02a7395dfebbfbc4f7661d4af56f2d372131a45936de40160007368a56ef216a30cb202c66d3145fd24380906"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="e4abe26a2eb7ca8d3367154a89262f44e4c20b6e67b62dc43a54cdb311c5843cebee8b72e8c04dc5b2c0158e2fcfcc75da41b157a3457c83dafd720550171531"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a6="39538def457c5d9ca7f23b1d4fdd0b05256571fdd612888000987f3fcf23a029a0b48f9abe28cccd97279e74530ef75a5e838eb05261a5807f7df1eb9f9e6efa"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a8="96c9a03ea4a916aa903f271b24bfc8fae161c996ab11a4d6a91fde2691ee4e9e735e166e335fc85e7f11beac7ec3c689150eaf71199900b2424e799b3cd94bb7"
    $a9="96c9a03ea4a916aa903f271b24bfc8fae161c996ab11a4d6a91fde2691ee4e9e735e166e335fc85e7f11beac7ec3c689150eaf71199900b2424e799b3cd94bb7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="30108c4c21bbf2a0e7445efb1724c2abdb8aafa65ec8333cfef61fb5b7140804"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a6="030b17b2169a535bdaa0a4eb355aa17604851ff96e4b94629f9c458ac524a0bd"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a8="007d831ea2e8e1d080b31e33c50b89ea07f9b694bccad998c8cf5cb1a087f889"
    $a9="007d831ea2e8e1d080b31e33c50b89ea07f9b694bccad998c8cf5cb1a087f889"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="bc8653499aba9b909eecec568e20a1855cfc87f30ef8e109ef4e6d4cb9fff8aa9461d5c3092fb1e5f3950ca5fdf986cc52927a2b1d7bb30af201f2ff95f34d42"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="e454bd0fe83d5f20b070ea83fba63e221781bf538009ba7617a7cd2feb4480108e5f5d6bef574a4693e429888c4435a46a315d274b601fd6c36a0b006887f949"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a6="56227212607c670601e3494b649ac570a4ad1914641537d58e12a047d92e00932dae905504a57420e1d7dfabee59de9dacad3faef9e16a834086168bd02a172e"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a8="e6de0b487a78bbeada86a22cec60cc4fade47168a34051824f87e99b0dbc4aa9e0fa51d111c43d91cf895558e196e95ea945d8fdeace67240e3185e54537c691"
    $a9="e6de0b487a78bbeada86a22cec60cc4fade47168a34051824f87e99b0dbc4aa9e0fa51d111c43d91cf895558e196e95ea945d8fdeace67240e3185e54537c691"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="3f7eae1ee1e4295ab992391eea5d33a45e869e50fabf367779086eec821b2698"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="1a907fa4e672895f840ba727f7e8462aa7ee9d697a879fe0c6b68576b8745ec1"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a6="1b2b990aaf29f39ae5b6ca8682aae265c157e9fdcf945a91e38f03da827f762d"
    $a7="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a8="c290609813c61da32a782afb032648c5e0666a7c93ff47e950577ab96c440bfb"
    $a9="c290609813c61da32a782afb032648c5e0666a7c93ff47e950577ab96c440bfb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="3580d8fca5a3d7def6d1bbb076d8192b806ba4155c7569c89713d606"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="0688cbd2ee273d4a359b5bc0a8c45c00cda485ef5f36c2914a7b3bd5"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="d723259e7c7a2518098db34b7edb9051af9f2307c55657b32af461ad"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a8="3db1415f3179b66da0e34acacfc4a542eb2e5ae067b4d13446387907"
    $a9="3db1415f3179b66da0e34acacfc4a542eb2e5ae067b4d13446387907"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="f4d6ed1b56b50792c161e7b440f2931279901d1fc97791c69af7d3d2381980f2"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="76d9c8341c138b2b9b35b1f114508618fc24875214dd4a26a104d2e85b66ff77"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a6="0e29c3a44f1a80037916bd6fd0e787aa06c9297a7dd17b3908b80f9578611cb1"
    $a7="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a8="f7b6747cf2fd176ef521a1633de2e751f516bd7de30a1962130a2b0b694929b0"
    $a9="f7b6747cf2fd176ef521a1633de2e751f516bd7de30a1962130a2b0b694929b0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="4d58bfd306307b517f58bda7326e3570b9e38ca9cff807e9023d8c3af94c89c0cb1c5216038bc235e8ff6fcfb86fcf6c"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="5394abf6a1e1c7b032e9c65d091a00e63ae5e4ffb93d5f2903d7082c147121c9f04064295e68978f0a1c427b9f3a163a"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a6="2fc9d5abb5853fc431c303d438a5601e7d300daa650d37599ac69e44d8a2a1a81ebf6aca5d38063181e53ec312fbc69b"
    $a7="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a8="e2832687c2b360db06ada9649c10ec15be4b70a105abbd0a116141ef906bd326ce81fe6691e89bd2b94bbbad5ef5c9fe"
    $a9="e2832687c2b360db06ada9649c10ec15be4b70a105abbd0a116141ef906bd326ce81fe6691e89bd2b94bbbad5ef5c9fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="83ed150dbcc9700521ccc2f7d67243c3d4000c8228281488dccd6c6753f48515dcb24714d5a294df27eeda834e9242e1ce4014fc38df3e0439b999fe3efa0765"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="fb324354599ef86a212637dac66f9f47bffa0865b6c8af259e9d46477425459c7ed61fe889b5ac9ae2e11d8971acba1b0b50963c7a40d2fc88ba13cdcb9fce8f"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a6="465a56680a7d5850f07b4f786d3331bf28d6ca64764bcc8e481edc861b345f65e02f8605280c22667498385bf5db22d7dadd425b3a2f544e2e1c0af3a4501fd1"
    $a7="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a8="1840b381398b9340c7f3040183a5d1ca79d0b38de07b903f9d9167c77c64c25affcf08664807d094e1a6d97b355b92081ff0f6921fca8b8948cc2caa07f9a5dd"
    $a9="1840b381398b9340c7f3040183a5d1ca79d0b38de07b903f9d9167c77c64c25affcf08664807d094e1a6d97b355b92081ff0f6921fca8b8948cc2caa07f9a5dd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="cm9vdA=="
    $a3="Y2hhbmdlbWU="
    $a4="cm9vdA=="
    $a5="c3VuMTIz"
    $a6="cm9vdA=="
    $a7="dDAwbGsxdA=="
    $a8="c3Nw"
    $a9="c3Nw"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

