/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_jio
{
    meta:
        id = "KwtqNYYu3D5ZcazAdO7wv"
        fingerprint = "5702ff7ae94f2b3c3e003c68535169a4114334277552c63d859f98c31c04713b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="622e3f0665ba6c932a29d844ee89a3e5"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="a4141712f19e9dd5adf16919bb38a95c"
    $a3="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e39a48e0d88e2cb"
    $a1="43e9a4ab75570f5b"
    $a2="7a7eeba37575fe5e"
    $a3="7a7eeba37575fe5e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*3C84F49217E2D08023FB84C4A19E619868D6217A"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a3="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}td22rGmwfTRzym6Zx/+OlQ=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a3="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nXzE9Go4nRwJpCns/C3VxUaH2XM="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a3="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5ddb6ac69b07d3473ca6e99c7ff8e95"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a3="200ceb26807d6bf99fd6f4f0d1ca54d4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d7cc4f46a389d1c09a429ecfc2dd5c54687d973"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a3="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="77396e12062f690715af94cf9835d744a641006b1efcecac18fcdee95b6cc6cc74988004892c32044dab0eddd3d73810"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a3="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e7df61d7b8219986dde0dd3ae7d2ef2a7f0c3d529c3312231ddd2e3"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a3="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b2e28a1bc2a9570be4bf9ae7852210196fb564a6ca0044b621af655e248a462dc3f50bbf73bd6ca1d74e32e39167d66e68b10ee8fd268d55bbd27d3c739c731"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a3="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="432e9eb5f5b24ab931be050256c0f3dc8296e1b41b08fd91201cae9dc7a554b5"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a3="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c62e8de600b56d70bb4e0583086f8108bd7330d91a4873306b2ecfa6c75c8e262216dc2ff81082afa82671a7fa5eab528c212ba5677f2aefdd7b85cfa56ddac"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a3="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6dc369efc4892e37601cb0f7a1f8d26c91e255c4ade65c992774f6f424e28d5"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a3="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b5372cfc5f9c87abfc713be1dcc0cd1e76c07631fbee51aa56aa031"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a3="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fc08d44dcbdf52eef0187330b67cc5fe1b2e9ea8b2bf7a96eb648ba706d626a"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a3="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da8a388764657c015316437e77da9cc10761c48bab3e98a2b28308462e35cd176be700ca108716becf071979f9489a91"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a3="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03ce86044dc6a8966e887e6396bdb9ae9ad16f3af72c83c90dc6d11c51b73ac7db948e782fb3718e2d7c9cda1edbedcac39491fa310671bca3ea894bf7129e73"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a3="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="SmlvY2VudHJ1bQ=="
    $a2="YWRtaW5pc3RyYXRvcg=="
    $a3="YWRtaW5pc3RyYXRvcg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

