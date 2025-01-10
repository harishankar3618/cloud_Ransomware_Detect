/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_netscreen
{
    meta:
        id = "4VD4emxBhrhsuNMBLwh9Oe"
        fingerprint = "8b1150dab488545e4d4821797320359fe816002be397f23e6db5d0c3169c919c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e41364f3191d288dceef6373c3b40634"
    $a1="e41364f3191d288dceef6373c3b40634"
    $a2="e41364f3191d288dceef6373c3b40634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="707ad979245de1d6"
    $a1="707ad979245de1d6"
    $a2="707ad979245de1d6"
    $a3="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*DA7B25B1BA72C91D124FAD86067FE077C0D8F5B8"
    $a1="*DA7B25B1BA72C91D124FAD86067FE077C0D8F5B8"
    $a2="*DA7B25B1BA72C91D124FAD86067FE077C0D8F5B8"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}8iK57IRp0nIw70IB+V49Rg=="
    $a1="{MD5}8iK57IRp0nIw70IB+V49Rg=="
    $a2="{MD5}8iK57IRp0nIw70IB+V49Rg=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}glee/aW9bOYEewkD/6Ri8sHh2mU="
    $a1="{SHA}glee/aW9bOYEewkD/6Ri8sHh2mU="
    $a2="{SHA}glee/aW9bOYEewkD/6Ri8sHh2mU="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f222b9ec8469d27230ef4201f95e3d46"
    $a1="f222b9ec8469d27230ef4201f95e3d46"
    $a2="f222b9ec8469d27230ef4201f95e3d46"
    $a3="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a1="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a2="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a1="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a2="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a1="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a2="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a1="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a2="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a1="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a2="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a1="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a2="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a1="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a2="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a1="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a2="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a1="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a2="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a1="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a2="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a1="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a2="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_netscreen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bmV0c2NyZWVu"
    $a1="bmV0c2NyZWVu"
    $a2="YWRtaW4="
    $a3="bmV0c2NyZWVu"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

