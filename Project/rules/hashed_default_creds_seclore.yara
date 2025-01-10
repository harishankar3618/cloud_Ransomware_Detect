/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_seclore
{
    meta:
        id = "4ptUt3vag0A69DB5ub1ILm"
        fingerprint = "6a348e7182d0638cdf25a5299355c2dc6dd00b4798d9b36bc6fbbb8a3b242fc9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e765b5ce499d7088f0356ace07c7ca8"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="4e765b5ce499d7088f0356ace07c7ca8"
    $a3="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="75834cc22d215bc1"
    $a1="67457e226a1a15bd"
    $a2="75834cc22d215bc1"
    $a3="077ff75a4925858c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C707666A2F2E3FA068F18C1C0A6608D607DDED8B"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*C707666A2F2E3FA068F18C1C0A6608D607DDED8B"
    $a3="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}/WvOOF4W+ehLlpqgdevryQ=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}/WvOOF4W+ehLlpqgdevryQ=="
    $a3="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ZyqaTh82PKbT9qxEE52rbmiouZ4="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}ZyqaTh82PKbT9qxEE52rbmiouZ4="
    $a3="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd6bce385e16f9e84b969aa075ebebc9"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="fd6bce385e16f9e84b969aa075ebebc9"
    $a3="c12e01f2a13ff5587e1e9e4aedb8242d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="672a9a4e1f363ca6d3f6ac44139dab6e68a8b99e"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="672a9a4e1f363ca6d3f6ac44139dab6e68a8b99e"
    $a3="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c102dc29d6f3f1671072a6f48767189e2d6c27647f2dd8f17fa9ffb6e1f5a74ee5e12e127c672894902061a451345bc5"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="c102dc29d6f3f1671072a6f48767189e2d6c27647f2dd8f17fa9ffb6e1f5a74ee5e12e127c672894902061a451345bc5"
    $a3="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bd97452ad7e3b6c6567f147459dda78a8e94f75caf8708bd985fe2ce"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="bd97452ad7e3b6c6567f147459dda78a8e94f75caf8708bd985fe2ce"
    $a3="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10271e1a053cc3ab6dfe845733eeccbdc7fee811327a34972e0c498486c6a9ad102372df03f56ec4e96e41b12bd691015d50064be1bb246e92cd3906f8427650"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="10271e1a053cc3ab6dfe845733eeccbdc7fee811327a34972e0c498486c6a9ad102372df03f56ec4e96e41b12bd691015d50064be1bb246e92cd3906f8427650"
    $a3="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c418c489d1ede5b0a5971649d7a3e883e9ba01124cbb871cfc8f955dba9c07a0"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="c418c489d1ede5b0a5971649d7a3e883e9ba01124cbb871cfc8f955dba9c07a0"
    $a3="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="49ec4c1565a6140663daa4eef0019aee86488d5f988036c41cea631740ecf1d0be4ea5c178523811a9a3aad3ca08d692146f3599b23219d1eca190932cc1f5c3"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="49ec4c1565a6140663daa4eef0019aee86488d5f988036c41cea631740ecf1d0be4ea5c178523811a9a3aad3ca08d692146f3599b23219d1eca190932cc1f5c3"
    $a3="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a39a761c8758267cb518c1719df33d398e6d9d609cebbde018711aa545d617a2"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="a39a761c8758267cb518c1719df33d398e6d9d609cebbde018711aa545d617a2"
    $a3="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eaf148693ea8ebfba7891d729e14854e63240548eadcd69ec7a8777b"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="eaf148693ea8ebfba7891d729e14854e63240548eadcd69ec7a8777b"
    $a3="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d999686ae2009addb9df0724e4c48ec9aa89dd6eb2fc14d4e011e152636fb60"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="7d999686ae2009addb9df0724e4c48ec9aa89dd6eb2fc14d4e011e152636fb60"
    $a3="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0abe854ffc0d429c5d5dfbf6acaef489bd61f538e518bd2540c1ed4cef8e3e46c8a80c91c3f1ad9418a826e7859655a1"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="0abe854ffc0d429c5d5dfbf6acaef489bd61f538e518bd2540c1ed4cef8e3e46c8a80c91c3f1ad9418a826e7859655a1"
    $a3="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e0b72801d3e0e66b58e5e8f8ce63bb962af011c464dc5b545a493f050840f9ab1511a0b9ce19ddb127cd8b5331eecc3bdc972b2f35ba8929b7f8ac17df5c1593"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="e0b72801d3e0e66b58e5e8f8ce63bb962af011c464dc5b545a493f050840f9ab1511a0b9ce19ddb127cd8b5331eecc3bdc972b2f35ba8929b7f8ac17df5c1593"
    $a3="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9vdA=="
    $a1="Y2hhbmdlb25maXJzdGxvZ2lu"
    $a2="c2E="
    $a3="Y2hhbmdlb25maXJzdGxvZ2lu"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

