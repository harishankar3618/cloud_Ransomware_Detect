/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_enterasys
{
    meta:
        id = "4qvb91eZ4kHSqPpnfQhM8E"
        fingerprint = "56e260ca1de520a09ff1d8763c1236e4ed793a525f29522374649c1f7ae899ff"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e2003ea1b0309acb195f977cd6b66135"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="70772c5247dd98cbfc3700ff9acfa3ee"
    $a3="0b9957e8bed733e0350c703ac1cda822"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7266fb56310a3161"
    $a1="43e9a4ab75570f5b"
    $a2="4554d59f2bde7946"
    $a3="3b920bf545feea6d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5A663994E26D658F8E7972F1AE5EFEAEE733AF7F"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*28CEBF99A3C7C01D020A9ED46E52E8A6632177E6"
    $a3="*F2F68D0BB27A773C1D944270E5FAFED515A3FA40"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}B97WT4Eq+42hgQFKnQh3KA=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}yAzAU35sE+CaKW3RlZSuoA=="
    $a3="{MD5}Q7kJIECWGPGIv8aSPxa5+g=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}2SiZyMumjIG/SWGXxPD9yw3UTSY="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}VBzHKcuFQj7KEPVgDY1xOu4IrZY="
    $a3="{SHA}RuPXcqGIjq3/JsetpH/XUC15bgc="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="07ded64f812afb8da181014a9d087728"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="c80cc0537e6c13e09a296dd19594aea0"
    $a3="43b90920409618f188bfc6923f16b9fa"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d92899c8cba68c81bf496197c4f0fdcb0dd44d26"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="541cc729cb85423eca10f5600d8d713aee08ad96"
    $a3="46e3d772a1888eadff26c7ada47fd7502d796e07"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="70e37c7ea05439431632b6f111c55cbb14a08a072cdbea5d024eb41262a211c5247112b4664f706ab874d47b215e1dc0"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="42558a2167a555f161a6e98ec87fcacb02fa5fb6451874f254f32b3739fa0c7a2c43c4b1b9a117233d96360c1fca06e7"
    $a3="5ff16255d4666e60dc7653c6cf982274e73d0c0c401f7feb28f9dd9e9e649e87805a8153c75c6950d48a8dea2c5c5a62"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b79ccc933306b4be7d2f499aa20fcc2e63820217e1a5f0d4d7476977"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="afb7120ab71a720f35ab638bec3968c12dd012a2cb52f4809ca607e0"
    $a3="4ce554b51c95da14f962dd11ead04c4c649ceaf50f059b58f8879a44"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc47b055fbdeb77058fd58922e1393393b47ae884401e7203b235d8751bc6ebd25f2418501356e5a9f8d9033d185ce1f1b891eaf73626ad3a707b364266d658e"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="988de5b4640eab1c331a8c123ef133fc427652df04fb1981c4fdf48095951e15b6682776f62ba56e32e82ea4ad0171ad0cc6a34bae7bfbd45e47b60435932af4"
    $a3="91f325261bca90f05e2175299e9fee045003017047114b3662b79201d05342edc72d4f5ba805ac9961f2f43c66234b5070e9d4c67dd324198afb00eee4c916ea"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcf803280302c60456047893d5d1014bdedb3eab7bc5c920770ac00c9883a168"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="3dbfc980dc71faf9ce9bb51a91bacd5f7b19a7c2669c9ba9411f6772cf8d9515"
    $a3="f15c16b99f82d8201767d3a841ff40849c8a1b812ffbfd2e393d2b6aa6682a6e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97ac4c2a060e714d81767a70edf1b86ed9c8df9c086df538883c26f0598d850e8ffb3ce15d966b5e6f9898c9729c8108c092c9c7577407e5e1a3af940828d15f"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="3c9feacd7a6ef26891503791be4544c98be22ec9271a4134544dd978233495c85604b1efd71352e9187d50aea3c6ad52c701b98be64692519b4dc8921f2b6ab5"
    $a3="1d7e0515bbebf48e479c9e3b70ea9f5c18ad768e6dd6e3d00af372555eadb697219556159edc45a330f585fe5d4220c1330f241666b8500142e8be54f528bf2c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f292b71f87f3b514e1d443926f047d06569387a14ab0934f660a3c38b1a758d0"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="03cc6210c5b87903186f0be376407a1933d9caa59043e249a1921870ad9d3dc9"
    $a3="f7262995c54e4c2dad3fb559926ae798ef3f5df56b4ecd769bd577491ad89a59"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="191a452050220815ecf53b385b21927c7ce4987503c003f50370d499"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="f9cd59184b9e4f57fad4ac82db27cd444dbdbc09df070aa86441f0fe"
    $a3="e9ced4a9908bd9dd07a8020d01997973785b6e455a90e1249a7abda7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d57cd3911fea06ea5216199ebe00f719dfc32a7bf19923adeea5e1853d191c58"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="e4cd7fdf87ca2d2221f8a89496151e2a15199ba43960a944d6485b6eb46e7750"
    $a3="1bb00f682e1b26ab9e36ee7f9f874947bc00b5926c69451a22dc99fe8cfd21c6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f133e2a2a99c2f4f761f061678bd7ef64245d4d6f1452db9eb62e15bbc7f5e348fd972e8359ffb9e4229d2aad1a8787"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9ebc8b83e466b0345cd577dba27a2e667c2c170a471f4867699b8f35d9a5fb2acf365e2dfe002972553339c8f440ace0"
    $a3="4385f1dc4c75de3575b22ab0d91156473f89fa8191f41092bf6d55053ab2236d1c6609191e138608d8ab584c33b21baf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48d21c54186d08dd99513469a2eb87a2afcc3af0f25250ee7aa67802beb27dcd76c743e2c68d38d2fee41118629fdb943fbc13ae43ddcda32524caf9dd790755"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="fb34a7db3856065b1b3cf22df94cd087e62cd3200ef7588f0bfd59e9145fb49d70648f0e0e57acedd1a1adf77ebfc564060c082069b35025adc6fa87dceca8d0"
    $a3="a0e03c7f9cec389616c03d3b59f3a51f33b140ebca5055e5ebc7170351aa97984fd4aeb8a7bb25016159b43b13c8438f51306902dffb5aafd592bce5ef92349f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="bmV0YWRtaW4="
    $a2="dGlnZXI="
    $a3="dGlnZXIxMjM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

