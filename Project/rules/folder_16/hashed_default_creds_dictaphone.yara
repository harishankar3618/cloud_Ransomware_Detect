/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_dictaphone
{
    meta:
        id = "2cRLrVfPjQKYXU1Dega7Ei"
        fingerprint = "35c176fa60a91c3e6aa8807ea2aa0ecc9b0df5a8cb48504cf99c53ddeddbf4ce"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f86769771ef26b6fb2fa00aa7f1ffc5"
    $a1="4f86769771ef26b6fb2fa00aa7f1ffc5"
    $a2="03b2f73d716f9174fbb4ba4f646e4c32"
    $a3="03b2f73d716f9174fbb4ba4f646e4c32"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d55d87c0e1724a8"
    $a1="0d55d87c0e1724a8"
    $a2="717c38fd0e889450"
    $a3="717c38fd0e889450"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*02DCBB5647848698AF833D5CDD8E82358CF5119C"
    $a1="*02DCBB5647848698AF833D5CDD8E82358CF5119C"
    $a2="*689702948E6BFE035925935CDFFB1A19EF64265F"
    $a3="*689702948E6BFE035925935CDFFB1A19EF64265F"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}JYNRiKI1XpUw06EPy+TGWw=="
    $a1="{MD5}JYNRiKI1XpUw06EPy+TGWw=="
    $a2="{MD5}cXQOw0yrvQPwP7J76K7DUg=="
    $a3="{MD5}cXQOw0yrvQPwP7J76K7DUg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}aEXG2QWFwk1j3iZsmm2gQJDtLcI="
    $a1="{SHA}aEXG2QWFwk1j3iZsmm2gQJDtLcI="
    $a2="{SHA}amBhnCWTmkU3STfQjOZ0OJ49d2U="
    $a3="{SHA}amBhnCWTmkU3STfQjOZ0OJ49d2U="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="25835188a2355e9530d3a10fcbe4c65b"
    $a1="25835188a2355e9530d3a10fcbe4c65b"
    $a2="71740ec34cabbd03f03fb27be8aec352"
    $a3="71740ec34cabbd03f03fb27be8aec352"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6845c6d90585c24d63de266c9a6da04090ed2dc2"
    $a1="6845c6d90585c24d63de266c9a6da04090ed2dc2"
    $a2="6a60619c25939a45374937d08ce674389e3d7765"
    $a3="6a60619c25939a45374937d08ce674389e3d7765"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1dc4fce6e46b62d31fe29f5a5ca51c2b4f3db5ef8d58cec9d7bba4a4a99978959f4637730df6287852eac2243495aa39"
    $a1="1dc4fce6e46b62d31fe29f5a5ca51c2b4f3db5ef8d58cec9d7bba4a4a99978959f4637730df6287852eac2243495aa39"
    $a2="bc682477e61c4a8a71a1777b0151a1842c02e474220975fdec86c2fd8cf932e9caacf552eb2a999117b26172b8edd4e5"
    $a3="bc682477e61c4a8a71a1777b0151a1842c02e474220975fdec86c2fd8cf932e9caacf552eb2a999117b26172b8edd4e5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab88a05dabbdd79168edc1d36d7e1f026c7144cb85792701611576f7"
    $a1="ab88a05dabbdd79168edc1d36d7e1f026c7144cb85792701611576f7"
    $a2="5e982cc7a14b30196bc347ee60b91fd0b4a1647814dfd8894cc5f9e8"
    $a3="5e982cc7a14b30196bc347ee60b91fd0b4a1647814dfd8894cc5f9e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d57c797c20fa47182c80d1e4ff32f2dd292ccb686d294072ab050ea4cfd6f4b26d089c642fd6cf1b1710891f343f0a686a52100ed67ebf2fbdfc0e27c08a4cbe"
    $a1="d57c797c20fa47182c80d1e4ff32f2dd292ccb686d294072ab050ea4cfd6f4b26d089c642fd6cf1b1710891f343f0a686a52100ed67ebf2fbdfc0e27c08a4cbe"
    $a2="4280f3eebeb1ca3f6b401d448d1963372b5ccc66b69b645347cbed493b982e0ba238a780be72bd3d9fd79be3bdc899e5fd5e8ee11e2a2a1e64158cafbb18213a"
    $a3="4280f3eebeb1ca3f6b401d448d1963372b5ccc66b69b645347cbed493b982e0ba238a780be72bd3d9fd79be3bdc899e5fd5e8ee11e2a2a1e64158cafbb18213a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5a9716fcd63f4a279e2f6df8f6de89dce75ff38fad8c7e04ebb2d8e2227e2eb"
    $a1="b5a9716fcd63f4a279e2f6df8f6de89dce75ff38fad8c7e04ebb2d8e2227e2eb"
    $a2="737f62617487a729b41b1f8b53f432f1551d3f2bd5124b016c7c0ecc69c46a80"
    $a3="737f62617487a729b41b1f8b53f432f1551d3f2bd5124b016c7c0ecc69c46a80"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d230428f78de6b4d82df4a3cf4ffa430b5f7ee3485107cb37cda32c5807e6a4ccd72f533b739b907fb9d410e1318f6b3e2cb0c4b39a571fce2478020cd364fa3"
    $a1="d230428f78de6b4d82df4a3cf4ffa430b5f7ee3485107cb37cda32c5807e6a4ccd72f533b739b907fb9d410e1318f6b3e2cb0c4b39a571fce2478020cd364fa3"
    $a2="f036b90815db103238fe933fe748a7ae48aa271516d127ab0962d97b403d53aecf30d3374ca2537629e767753fb6d3b421b3921838c3bd2da6ccd0043a254d3a"
    $a3="f036b90815db103238fe933fe748a7ae48aa271516d127ab0962d97b403d53aecf30d3374ca2537629e767753fb6d3b421b3921838c3bd2da6ccd0043a254d3a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bcd4b1c877da47b20b5fe711e0e5a47532bd57aca7fbe4e4782a2216df6a0f30"
    $a1="bcd4b1c877da47b20b5fe711e0e5a47532bd57aca7fbe4e4782a2216df6a0f30"
    $a2="6e901b6b30bea1f0c3e2afd93f5c720f15c7145b1e6ec0f89ddedb3b8d4767c0"
    $a3="6e901b6b30bea1f0c3e2afd93f5c720f15c7145b1e6ec0f89ddedb3b8d4767c0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f4f9645c6ecf231432820a3334b276c11b746bd96b9b0e2932ef9a39"
    $a1="f4f9645c6ecf231432820a3334b276c11b746bd96b9b0e2932ef9a39"
    $a2="0e4729a46e76021dc02a90f365b845c17440a14f8d39e3a380eae46c"
    $a3="0e4729a46e76021dc02a90f365b845c17440a14f8d39e3a380eae46c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a6a93d8fbdb169f05a0270ae9040e5a68a420f7d8902828031676487665ffac"
    $a1="2a6a93d8fbdb169f05a0270ae9040e5a68a420f7d8902828031676487665ffac"
    $a2="b41c4dacb6eea63d2ddcdae18a2bca25429a837c1bafa5037baad8283c1ae514"
    $a3="b41c4dacb6eea63d2ddcdae18a2bca25429a837c1bafa5037baad8283c1ae514"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c805854f8913a1dfd3ab24126f5babd95262447ff267fc9c97e21313165e6da535d9a37527757b6f80f522bc956d1d02"
    $a1="c805854f8913a1dfd3ab24126f5babd95262447ff267fc9c97e21313165e6da535d9a37527757b6f80f522bc956d1d02"
    $a2="1c33fb8b518f6d550863616cb2937ddc13c2b4a87f87db404b1507dea258cc5a1867f65c5ab27ec5b35cc29c016637e0"
    $a3="1c33fb8b518f6d550863616cb2937ddc13c2b4a87f87db404b1507dea258cc5a1867f65c5ab27ec5b35cc29c016637e0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e31c51bdd66677ebe710ebb5c0f216d4a8a8210c501ac97fe54beb1b93bac89c9d40ae2da98ccf94c81881721c0d09999ee2d4c0afcb5c5bbbc6e77506f48d10"
    $a1="e31c51bdd66677ebe710ebb5c0f216d4a8a8210c501ac97fe54beb1b93bac89c9d40ae2da98ccf94c81881721c0d09999ee2d4c0afcb5c5bbbc6e77506f48d10"
    $a2="dfbd646332d1b53596068288f6b284fcced07fef20395cc50dcc1461c1e47c76dad59955048267edadc353656298508a4b8f48cac28ca2049368141f38c4a7f4"
    $a3="dfbd646332d1b53596068288f6b284fcced07fef20395cc50dcc1461c1e47c76dad59955048267edadc353656298508a4b8f48cac28ca2049368141f38c4a7f4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="TkVUV09SSw=="
    $a1="TkVUV09SSw=="
    $a2="UEJY"
    $a3="UEJY"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

