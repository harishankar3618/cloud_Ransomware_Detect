/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_asante
{
    meta:
        id = "22McNDOBzCs5JEWVszWq17"
        fingerprint = "04725245e91ace16b94a61e5cc21edf87fb0ef461b63f86d29f56db4515c6865"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e7a3d0e7af2a44c77d3343a9edef710"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="4e7a3d0e7af2a44c77d3343a9edef710"
    $a3="8f62e69c0919247c923b60a23c0e46b4"
    $a4="9e59da9d84fdd2de6aa708a606ca8839"
    $a5="f689cb3717c2c7f273c7254765fbc538"
    $a6="9e59da9d84fdd2de6aa708a606ca8839"
    $a7="29ae0f559cdcda1c08e55c20ccf64961"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b5a31ea36bebc2b"
    $a1="43e9a4ab75570f5b"
    $a2="3b5a31ea36bebc2b"
    $a3="1e0c530062ec7e17"
    $a4="7de2fe8a3d64624b"
    $a5="1731959a18d86d30"
    $a6="7de2fe8a3d64624b"
    $a7="115d27f60f8521e4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FCEAA1CB0EDDE29E10614EA822DB0CB0A943FAA4"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*FCEAA1CB0EDDE29E10614EA822DB0CB0A943FAA4"
    $a3="*F5AB3475E4D0309381498567B7C7A270ADED2652"
    $a4="*9E351BAC81422C58648B8D1AE37F369E57A7DAFB"
    $a5="*BA029B8A98C6835A5523F4995B2EA34D1EB9954A"
    $a6="*9E351BAC81422C58648B8D1AE37F369E57A7DAFB"
    $a7="*9265F6647EDA8FA891BEBE9F103B9CB6B43DA03B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}QgclI4yfr2nW3WDpUfZ/YA=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}QgclI4yfr2nW3WDpUfZ/YA=="
    $a3="{MD5}C66i8K4gFQ23j1jN2sRCqQ=="
    $a4="{MD5}6LhLnSFZzMto/xj7SZWnPA=="
    $a5="{MD5}wnOhhnmuZusuw877tSnZ0w=="
    $a6="{MD5}6LhLnSFZzMto/xj7SZWnPA=="
    $a7="{MD5}EdoqKmEmtLD9INIU/q8R8Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}WLTUWC3ZhR3J80r+Zli1UF0F+Uo="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}WLTUWC3ZhR3J80r+Zli1UF0F+Uo="
    $a3="{SHA}jme7JrNY4u0g/lUu1vuDLzl6UH0="
    $a4="{SHA}+0ELGKqCz/gIlx4fldK+Fd7uorw="
    $a5="{SHA}Dj1hpE62LgsuzoDQV+gm4BsZpIQ="
    $a6="{SHA}+0ELGKqCz/gIlx4fldK+Fd7uorw="
    $a7="{SHA}CKM6n4wBU9Um96E0iGOBadlua2M="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="420725238c9faf69d6dd60e951f67f60"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="420725238c9faf69d6dd60e951f67f60"
    $a3="0baea2f0ae20150db78f58cddac442a9"
    $a4="e8b84b9d2159cccb68ff18fb4995a73c"
    $a5="c273a18679ae66eb2ec3cefbb529d9d3"
    $a6="e8b84b9d2159cccb68ff18fb4995a73c"
    $a7="11da2a2a6126b4b0fd20d214feaf11f1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58b4d4582dd9851dc9f34afe6658b5505d05f94a"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="58b4d4582dd9851dc9f34afe6658b5505d05f94a"
    $a3="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
    $a4="fb410b18aa82cff808971e1f95d2be15deeea2bc"
    $a5="0e3d61a44eb62e0b2ece80d057e826e01b19a484"
    $a6="fb410b18aa82cff808971e1f95d2be15deeea2bc"
    $a7="08a33a9f8c0153d526f7a13488638169d96e6b63"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8013528d2f1cf3caf4afbe16d8e618f26efe259942bba110ed6a9f6ada7c3841e12dc5189334e8f8b9458cade429a34f"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="8013528d2f1cf3caf4afbe16d8e618f26efe259942bba110ed6a9f6ada7c3841e12dc5189334e8f8b9458cade429a34f"
    $a3="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
    $a4="79e841b2b010297eab94ef2c9e5a3eefd931fe6e2e589740fd2c24bbbb80d5e9e4dbb95acfe00e08d68c1dc57f36d215"
    $a5="9e9c45ab235a9f7f5fd51a3242cad3f4e9a6d72d7690e565aacc96d2508e1a4254fb10af6ccdce776cedee947cbaa129"
    $a6="79e841b2b010297eab94ef2c9e5a3eefd931fe6e2e589740fd2c24bbbb80d5e9e4dbb95acfe00e08d68c1dc57f36d215"
    $a7="ab9bd1abb1b47360f4eeda08a78839845ce1a35fef23632d59615b1f0bb5cb68d2e4db51c7e45d4c29c658c53754bf28"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="619add9516d6a1f35edcf883c286f6c0964c34526ef6e03fd36e8118"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="619add9516d6a1f35edcf883c286f6c0964c34526ef6e03fd36e8118"
    $a3="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
    $a4="f572a21950751b641924847868714c3edefcf610d0f7f39a100db9c9"
    $a5="37b34e490bdb921eb50902ed04613e6bc307035960f145e78a91f914"
    $a6="f572a21950751b641924847868714c3edefcf610d0f7f39a100db9c9"
    $a7="7fd56d3848ec5197aaff4167bdc5b5910e290efb51f5167f9f114411"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a131635fe38c1e8f066bcfe9afb910af375f67ed60f866208c0857a0de829780c276a474f64d6ec49beb1a77fb190b2b807073d3a3e2edfbf71d082c003f7d9d"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="a131635fe38c1e8f066bcfe9afb910af375f67ed60f866208c0857a0de829780c276a474f64d6ec49beb1a77fb190b2b807073d3a3e2edfbf71d082c003f7d9d"
    $a3="2cff38a527697f0c8df41a644671718d7d139c9b6d836e126b62677d8b57b1598874b6b0595c10358f59ca4e943d8fd2aa57327db011a421a80ec65945ea210b"
    $a4="f724623e7c0fcf5b2b27bee13bca3a4c9f1bf9f969ea9671c8a9964b740b5adc716e5f025d62af042682c8032d9b150da9a6fc57a8e99c9f4d69aa3e788fbf21"
    $a5="b4ceae0fd10ba7beb0e03368279a1f93487b4b915e8761655bad09e8399f7c56e60bf7d0ebe648b0f5eb0c60f1c817acfa505196a3543b4f5d31c9e02530781c"
    $a6="f724623e7c0fcf5b2b27bee13bca3a4c9f1bf9f969ea9671c8a9964b740b5adc716e5f025d62af042682c8032d9b150da9a6fc57a8e99c9f4d69aa3e788fbf21"
    $a7="9ac7bd4b9286e4e03dcf7c98b7200a550663158eea9a7693d09f78de94d5c360ce47a5cc7336cfe4e51883b27be25d7e1ccf9a99d02ba6632324dcb1ae3e2d90"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d676e1c20b54d612d398e611b11327d605af6af96464b1bba8a1dfd1de5b55da"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="d676e1c20b54d612d398e611b11327d605af6af96464b1bba8a1dfd1de5b55da"
    $a3="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
    $a4="33f1a3dac043deb24e70e7b7c5489e7c6240ac64d26e43a1b5785c0efe28440e"
    $a5="bcfe8bf6b05dd55667fb640a0187cc83ac77f436d41467b1bfa7ee782664f56f"
    $a6="33f1a3dac043deb24e70e7b7c5489e7c6240ac64d26e43a1b5785c0efe28440e"
    $a7="a4146dcc6cb08401ffad98d26d3a81d72b93d9a8c6d842e7a9224d157ee7a850"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4c817340369b1c68cb9f4e9650ac0f85c10f5bcb1a1ef79411a4be0cd2e6d025a44c09d7df130cd673d276cca8dac9a7114c7132c79a70fcf4255a029e988eb"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="a4c817340369b1c68cb9f4e9650ac0f85c10f5bcb1a1ef79411a4be0cd2e6d025a44c09d7df130cd673d276cca8dac9a7114c7132c79a70fcf4255a029e988eb"
    $a3="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
    $a4="a0b27c918d9f592294404e94211de06da421cee7b40ab4fb19cdfb7709ba4fc1f1dd5b141ebbf3c3289e39ef4c64ef0e16e670e32ea58fc9b5e42ce43867f886"
    $a5="5aab9d8b71180f3a0418c2b3b244fc89b6e0da50f22ec18f96e31ab97a55bf76daca60d374f7de9caf7954d8d054c092bd6a718cd0db1b915c48aa93e97a42c9"
    $a6="a0b27c918d9f592294404e94211de06da421cee7b40ab4fb19cdfb7709ba4fc1f1dd5b141ebbf3c3289e39ef4c64ef0e16e670e32ea58fc9b5e42ce43867f886"
    $a7="54f187577cc51bf3fc27e69d10d8b2b919014945cb21a69ec4efca5b40b6b0daf5f2c94a409b5500aa1508159a3b35e2584ef0172fd568de43952c7030e2ba87"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66e622a2084bf867e60d9ae77e0b98e69489074f5cedcc11cb68f066904f2ee2"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="66e622a2084bf867e60d9ae77e0b98e69489074f5cedcc11cb68f066904f2ee2"
    $a3="2538fd118f310b61a135cfbefc4524bfc4860d075ad19c7a9f1ba86dca1913ae"
    $a4="d78c0e6d974d867f9a497f92f842f8c634a6fc7cd92533c5f8ffa5fc1d24bec3"
    $a5="970afdc6ee2aecfa5da9427390b905b3401b71dcbb58170f5d1215ff3c5921d2"
    $a6="d78c0e6d974d867f9a497f92f842f8c634a6fc7cd92533c5f8ffa5fc1d24bec3"
    $a7="ce018efb2ee034f62d98168e7eb5c22e193421f872f561229f1e80202e1ca1ae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b2c897a235aaeac2fc0ccc1fe8bbae4196a2048cc30dde6208c25cf9"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="b2c897a235aaeac2fc0ccc1fe8bbae4196a2048cc30dde6208c25cf9"
    $a3="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
    $a4="978ef02bb6885624beb66a3c76cbf1aef4195e07dfbfa7aa1013e853"
    $a5="c125ce68f583ea1fabec8152c54d60d14131a6f037cb0ce85605e7fa"
    $a6="978ef02bb6885624beb66a3c76cbf1aef4195e07dfbfa7aa1013e853"
    $a7="448c754a66d168b6d4b8f739c975a6c92d0fe8b6a9fbc8b303e0f18c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abfeafd656b5a18206092fa00e2df04c821b8cf7d168c0769492bd9764435474"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="abfeafd656b5a18206092fa00e2df04c821b8cf7d168c0769492bd9764435474"
    $a3="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
    $a4="835013eb39d3e3f3f53c6803f10cd82aa9f153e96d725ee858691a1944f9749b"
    $a5="0d6efbb9065510471bb1783ef3db93c06f476b894af603b46fcdfb692e1d36b7"
    $a6="835013eb39d3e3f3f53c6803f10cd82aa9f153e96d725ee858691a1944f9749b"
    $a7="cf4a073d1685377e9a96df1d897f90bc429ade355bf50d2b959679d562ae620e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="87290571eba3eba6aec4faa6736368a75ecb90fc784d476cd8f5c3ea877a5cd9f0868dbe5cce3dbbd65b06a47cf7c302"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="87290571eba3eba6aec4faa6736368a75ecb90fc784d476cd8f5c3ea877a5cd9f0868dbe5cce3dbbd65b06a47cf7c302"
    $a3="05de7187b529f77320118b614d697fd59004745c2993e9e827e78b02049458c9afb928d19c5e7f2917c9d57c9b841ad1"
    $a4="5eef2e4f10c050e9758d64fcee1c10e5b83de22882ad412e671e914825a8c81c80e8af16c02e797a8d2c31cfaea51d86"
    $a5="2d2883c76a749712765314a029706a65cc6cc6ebed4a391a8f9b094a7c005c2f6df6984f8470cb99e6e1c3374fefe6a3"
    $a6="5eef2e4f10c050e9758d64fcee1c10e5b83de22882ad412e671e914825a8c81c80e8af16c02e797a8d2c31cfaea51d86"
    $a7="b434a0786144a999f291f53fb0734331b6f2fc4bda164afc4e33b2d1dcd02078f92510a0d54436c1c1da86940878ccac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0dcc3b9c586e11be5146f5bb0100734f0b45cec891e26a7d2a166bff64258c1d44002cd143521f7deb3a685b284fe7d4d7dfe43c00858cbeac283948d80eeac4"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="0dcc3b9c586e11be5146f5bb0100734f0b45cec891e26a7d2a166bff64258c1d44002cd143521f7deb3a685b284fe7d4d7dfe43c00858cbeac283948d80eeac4"
    $a3="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
    $a4="23bcd02f19831595b52c406554bb267e95df45ee00f6319ea5d36297f0988dc70a0bc04b3534794b47888f63469934508531c157cb52138b4f1c44f212d82a6e"
    $a5="a76eaefd97aaf8c84ecc4952505db296edb3a92730f3c1fe5f7f2f8dd8bea02c0180d31178db0fbcb03d5a01328b7e5f4d44a2d3cbaa033a30397b6de944fc36"
    $a6="23bcd02f19831595b52c406554bb267e95df45ee00f6319ea5d36297f0988dc70a0bc04b3534794b47888f63469934508531c157cb52138b4f1c44f212d82a6e"
    $a7="115e96ee49d3cf341f25c038acad769180b421e61c4b834d99b9f4dddd7e6e03141a2d84ac5af8878ac7cbb758fad78c66f1b1d7e3eed6087cfb9522702efa39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YXNhbnRl"
    $a2="c3VwZXJ1c2Vy"
    $a3="YXNhbnRl"
    $a4="SW50cmFTdGFjaw=="
    $a5="QXNhbnRl"
    $a6="SW50cmFTd2l0Y2g="
    $a7="QXNhbnRl"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

