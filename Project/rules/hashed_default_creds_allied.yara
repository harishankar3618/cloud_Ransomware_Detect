/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_allied
{
    meta:
        id = "4JHvTnZFj6Tki25Un1OAed"
        fingerprint = "2e53c80e723b6a24a9821eb1035791110b949a7913052df4ebbf2ba53cf09414"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99d479d0a424c9ecbcb67568c4889239"
    $a1="f938b53b982f22cd6b1c14ae10665480"
    $a2="25370f2e5cf8d152408a610c4939e67e"
    $a3="25370f2e5cf8d152408a610c4939e67e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7923eae65177ac3c"
    $a1="5336eb751494bdb1"
    $a2="411305f40cbc0383"
    $a3="411305f40cbc0383"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*67CCB3E4C7D082F59E21B16E36C6655A938EBABE"
    $a1="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a2="*D28AA394BB8D942030AAA56A45C3EC7CD3012295"
    $a3="*D28AA394BB8D942030AAA56A45C3EC7CD3012295"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}OvAMbK0R96tdtEZ7Zs5QPg=="
    $a1="{MD5}HQJYwkQKjRnnFikrIx4xkA=="
    $a2="{MD5}yWK4bz2oVqmmciGn3yA47g=="
    $a3="{MD5}yWK4bz2oVqmmciGn3yA47g=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}5phnyn1aewq2Ciph57eRwQb3v2Q="
    $a1="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a2="{SHA}r44+AE/Suhq//Sg9RED9Xp9zigc="
    $a3="{SHA}r44+AE/Suhq//Sg9RED9Xp9zigc="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3af00c6cad11f7ab5db4467b66ce503e"
    $a1="1d0258c2440a8d19e716292b231e3190"
    $a2="c962b86f3da856a9a67221a7df2038ee"
    $a3="c962b86f3da856a9a67221a7df2038ee"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e69867ca7d5a7b0ab60a2a61e7b791c106f7bf64"
    $a1="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a2="af8e3e004fd2ba1abffd283d4440fd5e9f738a07"
    $a3="af8e3e004fd2ba1abffd283d4440fd5e9f738a07"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc9e656e15fe10c4cd4d42d93b9c221a43ecc62a5302f4d378e9dcd512013653abc3f92c3d2ca6f3d3b138a2463ba60f"
    $a1="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a2="773d7807eef8dffaf0cffb3a735502f150de9c5e36be5afd6a052942dc9299ee2d71652f3d44aec229ae0799d9158e80"
    $a3="773d7807eef8dffaf0cffb3a735502f150de9c5e36be5afd6a052942dc9299ee2d71652f3d44aec229ae0799d9158e80"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ccfe0ad92ed1626819859280b3a54413af3d332c84cbe3d2d93725b"
    $a1="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a2="08e74fd1a5217257bc135439002d9feeba343848249276662407ffef"
    $a3="08e74fd1a5217257bc135439002d9feeba343848249276662407ffef"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="83004bb19c3daaf3babbeb0aa831acaf52eca126abe8d74628e22b6ec6a5741dc61680e3fc7497073911a49bf1db94196900dfe49b766aed91781f829a7f2c00"
    $a1="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a2="ac4ff0eb7e78b66018ad6cbdd4cb8896038fec6d696b6a423b26832e75fe89f1b7e5d77d840031909e13bc8dae80f4e48116af4cd4ae965fdde672ecfdad0c6b"
    $a3="ac4ff0eb7e78b66018ad6cbdd4cb8896038fec6d696b6a423b26832e75fe89f1b7e5d77d840031909e13bc8dae80f4e48116af4cd4ae965fdde672ecfdad0c6b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cde48537ca2c28084ff560826d0e6388b7c57a51497a6cb56f397289e52ff41b"
    $a1="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
    $a2="68a9bb8989efd73ddfd694dff79181fd2db171a23ad1edfdce6d17a2afe82301"
    $a3="68a9bb8989efd73ddfd694dff79181fd2db171a23ad1edfdce6d17a2afe82301"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d45231115688f6712ef6ba4b634421bb0026fd06105c28785888dfb2f6145b1481f9c43c0c3dc9464f5dbdad787cbfd983f8e9076fc9292ba2afb56a67f631d"
    $a1="f05cc1dce30522404088964d1d989a90a5e73960f95e2bb823058768cab802b81413bfcc8baa755c2319bccccf5255686c9afaf59c769ecd4d2cf66b13d133f1"
    $a2="816a55c89d2372acb1f4c7071b3202eee9807f4befee4f1528400ccb8510adf4d7fb6c15e5b627bb51af1e6721eb5f3bec99d1d23a38f68eb1d14358733893a4"
    $a3="816a55c89d2372acb1f4c7071b3202eee9807f4befee4f1528400ccb8510adf4d7fb6c15e5b627bb51af1e6721eb5f3bec99d1d23a38f68eb1d14358733893a4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="360dfd847ab06765bb81fc7889ad843a09b2ff1e92a4f3fffedbd011cd2531ea"
    $a1="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a2="fc1cf3a33d9f06da7b413bcc4487c188dc0665202cf566c51c6721a7b2d8b8f5"
    $a3="fc1cf3a33d9f06da7b413bcc4487c188dc0665202cf566c51c6721a7b2d8b8f5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="71853ed3baa9c0d0e12e25267edb98e0e043af6ab5e6becfa29fe927"
    $a1="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a2="a0a701f57b0a5d174a9720dfcfc998a62520fb94f26e2f6f99d0ddba"
    $a3="a0a701f57b0a5d174a9720dfcfc998a62520fb94f26e2f6f99d0ddba"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d582e49e6418298578ef5d896b08ac121fff042ea7f8ed13fdafa7453f5c389d"
    $a1="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a2="905d922e19eb59c39a963226f7efd9f36666accc1cc08fc2940da0216ecbf4d2"
    $a3="905d922e19eb59c39a963226f7efd9f36666accc1cc08fc2940da0216ecbf4d2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="49d515950d401a15a7199d58b29240ae5e3c9c2f4881ddde9d7e29f78dbcfde73a8b47e41076492a2aac3086bca52063"
    $a1="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a2="023fb079bdf2d642a5d370f80fba12d4f4ba865ce4c287aab0536af45a0e2ceb5c4bca8a07353aa43e1f5d043e9b14d4"
    $a3="023fb079bdf2d642a5d370f80fba12d4f4ba865ce4c287aab0536af45a0e2ceb5c4bca8a07353aa43e1f5d043e9b14d4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="08576a5ea33e50285f7839faceb8920c99b6623c2da5b134d8ad1df32d18f36f872f7ebdd56b01ee3e53c093dd07a88c487127e798ebd79c15fd4147a8c0d4ca"
    $a1="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a2="693ad475bc726c9ce3f017b5d84f25135bcac7e3338ca0efc471162644d5c8648c29e00c959aa6a54dccb4fa220524de5ed9b28ee2ad36fbf864ab150b343280"
    $a3="693ad475bc726c9ce3f017b5d84f25135bcac7e3338ca0efc471162644d5c8648c29e00c959aa6a54dccb4fa220524de5ed9b28ee2ad36fbf864ab150b343280"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bWFuYWdlcg=="
    $a1="ZnJpZW5k"
    $a2="c2Vjb2Zm"
    $a3="c2Vjb2Zm"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

