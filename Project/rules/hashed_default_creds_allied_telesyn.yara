/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_allied_telesyn
{
    meta:
        id = "2JjXy4XnnoOnTYMqGhiMMI"
        fingerprint = "9966729d6b5c6c2cda914bd6bae21bcf538a15435c5e078437311ac786fa3029"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f938b53b982f22cd6b1c14ae10665480"
    $a1="f938b53b982f22cd6b1c14ae10665480"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="f938b53b982f22cd6b1c14ae10665480"
    $a4="99d479d0a424c9ecbcb67568c4889239"
    $a5="2e810dd7bf85d71280f588266c1e2ee7"
    $a6="99d479d0a424c9ecbcb67568c4889239"
    $a7="f938b53b982f22cd6b1c14ae10665480"
    $a8="25370f2e5cf8d152408a610c4939e67e"
    $a9="25370f2e5cf8d152408a610c4939e67e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql323_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5336eb751494bdb1"
    $a1="5336eb751494bdb1"
    $a2="43e9a4ab75570f5b"
    $a3="5336eb751494bdb1"
    $a4="7923eae65177ac3c"
    $a5="2ac90b9577c33931"
    $a6="7923eae65177ac3c"
    $a7="5336eb751494bdb1"
    $a8="411305f40cbc0383"
    $a9="411305f40cbc0383"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql41_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a1="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a4="*67CCB3E4C7D082F59E21B16E36C6655A938EBABE"
    $a5="*6695524259F1EEA28BDD985FC5235873DBF015E4"
    $a6="*67CCB3E4C7D082F59E21B16E36C6655A938EBABE"
    $a7="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a8="*D28AA394BB8D942030AAA56A45C3EC7CD3012295"
    $a9="*D28AA394BB8D942030AAA56A45C3EC7CD3012295"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_md5_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}HQJYwkQKjRnnFikrIx4xkA=="
    $a1="{MD5}HQJYwkQKjRnnFikrIx4xkA=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}HQJYwkQKjRnnFikrIx4xkA=="
    $a4="{MD5}OvAMbK0R96tdtEZ7Zs5QPg=="
    $a5="{MD5}rpS+PNUyzkoCWISBnrCMmA=="
    $a6="{MD5}OvAMbK0R96tdtEZ7Zs5QPg=="
    $a7="{MD5}HQJYwkQKjRnnFikrIx4xkA=="
    $a8="{MD5}yWK4bz2oVqmmciGn3yA47g=="
    $a9="{MD5}yWK4bz2oVqmmciGn3yA47g=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_sha1_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a1="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a4="{SHA}5phnyn1aewq2Ciph57eRwQb3v2Q="
    $a5="{SHA}ur4wUOLoHf2HqM5nJk1RjLNK73I="
    $a6="{SHA}5phnyn1aewq2Ciph57eRwQb3v2Q="
    $a7="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a8="{SHA}r44+AE/Suhq//Sg9RED9Xp9zigc="
    $a9="{SHA}r44+AE/Suhq//Sg9RED9Xp9zigc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule md5_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d0258c2440a8d19e716292b231e3190"
    $a1="1d0258c2440a8d19e716292b231e3190"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="1d0258c2440a8d19e716292b231e3190"
    $a4="3af00c6cad11f7ab5db4467b66ce503e"
    $a5="ae94be3cd532ce4a025884819eb08c98"
    $a6="3af00c6cad11f7ab5db4467b66ce503e"
    $a7="1d0258c2440a8d19e716292b231e3190"
    $a8="c962b86f3da856a9a67221a7df2038ee"
    $a9="c962b86f3da856a9a67221a7df2038ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a1="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a4="e69867ca7d5a7b0ab60a2a61e7b791c106f7bf64"
    $a5="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a6="e69867ca7d5a7b0ab60a2a61e7b791c106f7bf64"
    $a7="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a8="af8e3e004fd2ba1abffd283d4440fd5e9f738a07"
    $a9="af8e3e004fd2ba1abffd283d4440fd5e9f738a07"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a1="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a4="dc9e656e15fe10c4cd4d42d93b9c221a43ecc62a5302f4d378e9dcd512013653abc3f92c3d2ca6f3d3b138a2463ba60f"
    $a5="9f926adb99d65307adc43260aaab27c71af4f8b1c112b8f3b45139eab7ccb9a4afc0569c47fef0c4ba69af737533271b"
    $a6="dc9e656e15fe10c4cd4d42d93b9c221a43ecc62a5302f4d378e9dcd512013653abc3f92c3d2ca6f3d3b138a2463ba60f"
    $a7="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a8="773d7807eef8dffaf0cffb3a735502f150de9c5e36be5afd6a052942dc9299ee2d71652f3d44aec229ae0799d9158e80"
    $a9="773d7807eef8dffaf0cffb3a735502f150de9c5e36be5afd6a052942dc9299ee2d71652f3d44aec229ae0799d9158e80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a1="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a4="3ccfe0ad92ed1626819859280b3a54413af3d332c84cbe3d2d93725b"
    $a5="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a6="3ccfe0ad92ed1626819859280b3a54413af3d332c84cbe3d2d93725b"
    $a7="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a8="08e74fd1a5217257bc135439002d9feeba343848249276662407ffef"
    $a9="08e74fd1a5217257bc135439002d9feeba343848249276662407ffef"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a1="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a4="83004bb19c3daaf3babbeb0aa831acaf52eca126abe8d74628e22b6ec6a5741dc61680e3fc7497073911a49bf1db94196900dfe49b766aed91781f829a7f2c00"
    $a5="290cdcaab07595d41dda81be97b19b9dd2f0ccd7594268d075a9eac22121c2fb033469f384c988ed20749aa4ce0f46f5c592a9468c8609c8de1b6a5bad56b596"
    $a6="83004bb19c3daaf3babbeb0aa831acaf52eca126abe8d74628e22b6ec6a5741dc61680e3fc7497073911a49bf1db94196900dfe49b766aed91781f829a7f2c00"
    $a7="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a8="ac4ff0eb7e78b66018ad6cbdd4cb8896038fec6d696b6a423b26832e75fe89f1b7e5d77d840031909e13bc8dae80f4e48116af4cd4ae965fdde672ecfdad0c6b"
    $a9="ac4ff0eb7e78b66018ad6cbdd4cb8896038fec6d696b6a423b26832e75fe89f1b7e5d77d840031909e13bc8dae80f4e48116af4cd4ae965fdde672ecfdad0c6b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
    $a1="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
    $a4="cde48537ca2c28084ff560826d0e6388b7c57a51497a6cb56f397289e52ff41b"
    $a5="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a6="cde48537ca2c28084ff560826d0e6388b7c57a51497a6cb56f397289e52ff41b"
    $a7="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
    $a8="68a9bb8989efd73ddfd694dff79181fd2db171a23ad1edfdce6d17a2afe82301"
    $a9="68a9bb8989efd73ddfd694dff79181fd2db171a23ad1edfdce6d17a2afe82301"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f05cc1dce30522404088964d1d989a90a5e73960f95e2bb823058768cab802b81413bfcc8baa755c2319bccccf5255686c9afaf59c769ecd4d2cf66b13d133f1"
    $a1="f05cc1dce30522404088964d1d989a90a5e73960f95e2bb823058768cab802b81413bfcc8baa755c2319bccccf5255686c9afaf59c769ecd4d2cf66b13d133f1"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="f05cc1dce30522404088964d1d989a90a5e73960f95e2bb823058768cab802b81413bfcc8baa755c2319bccccf5255686c9afaf59c769ecd4d2cf66b13d133f1"
    $a4="1d45231115688f6712ef6ba4b634421bb0026fd06105c28785888dfb2f6145b1481f9c43c0c3dc9464f5dbdad787cbfd983f8e9076fc9292ba2afb56a67f631d"
    $a5="d4ee695d84d47ff4cbb16c47fa7364edd5b8c0acaf21ba78a32cfa403dbb6dfe597547cefc004638dd1f8a8e6cbfbe90f7f10afd6412e912077d370bb4a4c39d"
    $a6="1d45231115688f6712ef6ba4b634421bb0026fd06105c28785888dfb2f6145b1481f9c43c0c3dc9464f5dbdad787cbfd983f8e9076fc9292ba2afb56a67f631d"
    $a7="f05cc1dce30522404088964d1d989a90a5e73960f95e2bb823058768cab802b81413bfcc8baa755c2319bccccf5255686c9afaf59c769ecd4d2cf66b13d133f1"
    $a8="816a55c89d2372acb1f4c7071b3202eee9807f4befee4f1528400ccb8510adf4d7fb6c15e5b627bb51af1e6721eb5f3bec99d1d23a38f68eb1d14358733893a4"
    $a9="816a55c89d2372acb1f4c7071b3202eee9807f4befee4f1528400ccb8510adf4d7fb6c15e5b627bb51af1e6721eb5f3bec99d1d23a38f68eb1d14358733893a4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a1="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a4="360dfd847ab06765bb81fc7889ad843a09b2ff1e92a4f3fffedbd011cd2531ea"
    $a5="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a6="360dfd847ab06765bb81fc7889ad843a09b2ff1e92a4f3fffedbd011cd2531ea"
    $a7="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a8="fc1cf3a33d9f06da7b413bcc4487c188dc0665202cf566c51c6721a7b2d8b8f5"
    $a9="fc1cf3a33d9f06da7b413bcc4487c188dc0665202cf566c51c6721a7b2d8b8f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a1="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a4="71853ed3baa9c0d0e12e25267edb98e0e043af6ab5e6becfa29fe927"
    $a5="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a6="71853ed3baa9c0d0e12e25267edb98e0e043af6ab5e6becfa29fe927"
    $a7="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a8="a0a701f57b0a5d174a9720dfcfc998a62520fb94f26e2f6f99d0ddba"
    $a9="a0a701f57b0a5d174a9720dfcfc998a62520fb94f26e2f6f99d0ddba"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a1="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a4="d582e49e6418298578ef5d896b08ac121fff042ea7f8ed13fdafa7453f5c389d"
    $a5="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a6="d582e49e6418298578ef5d896b08ac121fff042ea7f8ed13fdafa7453f5c389d"
    $a7="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a8="905d922e19eb59c39a963226f7efd9f36666accc1cc08fc2940da0216ecbf4d2"
    $a9="905d922e19eb59c39a963226f7efd9f36666accc1cc08fc2940da0216ecbf4d2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a1="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a4="49d515950d401a15a7199d58b29240ae5e3c9c2f4881ddde9d7e29f78dbcfde73a8b47e41076492a2aac3086bca52063"
    $a5="9fde29cb657614f4dd02c1329dea73d4e409ce50a8275fd34c9fa00ab6a590211814bf8b5254581e99383bad238d4174"
    $a6="49d515950d401a15a7199d58b29240ae5e3c9c2f4881ddde9d7e29f78dbcfde73a8b47e41076492a2aac3086bca52063"
    $a7="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a8="023fb079bdf2d642a5d370f80fba12d4f4ba865ce4c287aab0536af45a0e2ceb5c4bca8a07353aa43e1f5d043e9b14d4"
    $a9="023fb079bdf2d642a5d370f80fba12d4f4ba865ce4c287aab0536af45a0e2ceb5c4bca8a07353aa43e1f5d043e9b14d4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a1="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a4="08576a5ea33e50285f7839faceb8920c99b6623c2da5b134d8ad1df32d18f36f872f7ebdd56b01ee3e53c093dd07a88c487127e798ebd79c15fd4147a8c0d4ca"
    $a5="23da8a9053fc47ed8afb004dd1559061050ddc8ddf1d38f0b02566b9a2f6962345e22bd807f576775b07cd8a63aafc583fe7747bd73f0633e7eb83791d3967e9"
    $a6="08576a5ea33e50285f7839faceb8920c99b6623c2da5b134d8ad1df32d18f36f872f7ebdd56b01ee3e53c093dd07a88c487127e798ebd79c15fd4147a8c0d4ca"
    $a7="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a8="693ad475bc726c9ce3f017b5d84f25135bcac7e3338ca0efc471162644d5c8648c29e00c959aa6a54dccb4fa220524de5ed9b28ee2ad36fbf864ab150b343280"
    $a9="693ad475bc726c9ce3f017b5d84f25135bcac7e3338ca0efc471162644d5c8648c29e00c959aa6a54dccb4fa220524de5ed9b28ee2ad36fbf864ab150b343280"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bWFuYWdlcg=="
    $a1="bWFuYWdlcg=="
    $a2="bWFuYWdlcg=="
    $a3="YWRtaW4="
    $a4="TWFuYWdlcg=="
    $a5="ZnJpZW5k"
    $a6="bWFuYWdlcg=="
    $a7="ZnJpZW5k"
    $a8="c2Vjb2Zm"
    $a9="c2Vjb2Zm"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

