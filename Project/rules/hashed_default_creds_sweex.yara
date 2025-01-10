/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_sweex
{
    meta:
        id = "6w1QAUfxIzKMCDgRlgpLxG"
        fingerprint = "2e96eb9662f8111c37cc363b14ce146c1835bb3963cca8996adc07397d407998"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28fd0495591d27493ceb953b0cc90dc3"
    $a1="66bff22ef634404b65bf0ec421a8bb1a"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="c130686c5e7390f6dfb455744d6ca639"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="93834cb9d11de401604c62928f8fdc16"
    $a7="93834cb9d11de401604c62928f8fdc16"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ec9cd103a461db2"
    $a1="47b1035a0032dad7"
    $a2="446a12100c856ce9"
    $a3="43e9a4ab75570f5b"
    $a4="7525d0f416af828b"
    $a5="43e9a4ab75570f5b"
    $a6="36954c9d59afb8e5"
    $a7="36954c9d59afb8e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*F7A763809A6F09611399B55D3778B91079DE488D"
    $a1="*956D20503E7318E7F7F68CA7AC24B3CDFFE3D0A2"
    $a2="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*C91474C93A7A272091D89920625F9C1749E6567F"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*050F46D65B660795AB12D8E1FF4B4143B6E080C4"
    $a7="*050F46D65B660795AB12D8E1FF4B4143B6E080C4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}FUo3RaKpGcEApzp/IwPvGA=="
    $a1="{MD5}wbIfRkh3HEastqxlt2Kz9A=="
    $a2="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}aX76lK0eZlxNDt1MgQ22+w=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}l4dtB+w9YJpu3Fhx8Do8ow=="
    $a7="{MD5}l4dtB+w9YJpu3Fhx8Do8ow=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}xmwJo9jjEDb9CIofEq7DR7J+B4s="
    $a1="{SHA}LcY+tRpeqslbo6+LA3Wk14PCJIs="
    $a2="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}GxD+jB8vXCn3j6r6Umr9IQ3tn7I="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}B8jNSmp9aKLrg+4HaBEfnnt5Maw="
    $a7="{SHA}B8jNSmp9aKLrg+4HaBEfnnt5Maw="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="154a3745a2a919c100a73a7f2303ef18"
    $a1="c1b21f4648771c46acb6ac65b762b3f4"
    $a2="81dc9bdb52d04dc20036dbd8313ed055"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="697efa94ad1e665c4d0edd4c810db6fb"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="97876d07ec3d609a6edc5871f03a3ca3"
    $a7="97876d07ec3d609a6edc5871f03a3ca3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c66c09a3d8e31036fd088a1f12aec347b27e078b"
    $a1="2dc63eb51a5eaac95ba3af8b0375a4d783c2248b"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="1b10fe8c1f2f5c29f78faafa526afd210ded9fb2"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="07c8cd4a6a7d68a2eb83ee0768111f9e7b7931ac"
    $a7="07c8cd4a6a7d68a2eb83ee0768111f9e7b7931ac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0831bfb59eb75eca8d74ed393b18044884d7b1acd54369255496570027d7fa4f8818fc888d191f2f3fd198ddfa5d45e5"
    $a1="392b0f28a6b7827967a93a52306347a74c51f2db12c582546008c7a3dfcc3b9d11c49b0bd7ceae864be4e55020b336b1"
    $a2="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="e063d31a6d256a31b2d1882a9cfc0ec4de630d4af37b6e8942a5cb1bd18b2af08fc937e773564b559161b670301d9114"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="5fc841865fc4fd1d00c065392d3fd0b2a13b2914c7d00fb6c81c81e0f5a3ef9d2f2af82f56a330b2e24d00dc3a2383d2"
    $a7="5fc841865fc4fd1d00c065392d3fd0b2a13b2914c7d00fb6c81c81e0f5a3ef9d2f2af82f56a330b2e24d00dc3a2383d2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b12d3ac8ee3f493c393ac2283b41b878476773bf7ac110a7f851455e"
    $a1="89507e57477323f5d3a38b4ad4f5cb43e0713f827f9fafbb7aa59fe7"
    $a2="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="3febb630e97a4b8be0b40acbeb4edbd88a1483c57187f0493d7465ec"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="ddcf4af692370322c72858c21d6c91b53f1b95b3fa34767ddeb5baa8"
    $a7="ddcf4af692370322c72858c21d6c91b53f1b95b3fa34767ddeb5baa8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc35aea6b82b5bb7152fe5c78ad7c87e38ae06f9b5749cd7e22dfd5498aa5f84b5b1bfa1b387eea6c4f41de2b14bcfca795a07fe420268945fb3366dbe81c662"
    $a1="b1a522ae5d2b9b0738a182a7e16d8553ea5013b92a350cdc7fe7a870fe5946fee0bf267631a061fd386b896b54d5d3f76b09ecdcf0323ffc2fcd0a9a5b7bb36f"
    $a2="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="acf4fd04a648ae5754053813e74c37ed875e024caabe9905ccff0441cd18efb969a58089ab4a60a51545f03ebfb94220105a47185a6aeaf108851cfc513cb7f6"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="768232fcb74ab2fddea8bec15e6c845f11b6f79094303ba75481787291237982ca28e8e14a84045da8f3b2e5e9659ea285b7a1c7987172fdd6ead28cf40998d6"
    $a7="768232fcb74ab2fddea8bec15e6c845f11b6f79094303ba75481787291237982ca28e8e14a84045da8f3b2e5e9659ea285b7a1c7987172fdd6ead28cf40998d6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68748822a91ecad774e5b003cb902fce075190efb9d48b30e5c1f2c03b321ddf"
    $a1="f6b05a8dfc21ac45103a87a9c845a7b8f92e5c572d8f3607fff101d6daf17f65"
    $a2="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="4dd98590f9dcdcdddaf268f443300ec1f63ddc8fb5a72e7b4bea2c0e4cc57014"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="87d342881cec7ed0cdbc447da129dd07547a89f540adb642398ba59e22af52fd"
    $a7="87d342881cec7ed0cdbc447da129dd07547a89f540adb642398ba59e22af52fd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="950b577e986853020dd0ed223ad7b34d1faf2eff2350ddb3c406ea1bbd73dd71c573e46f439d8a8ffb52928e69783477ab3badb9a33c7d0bd3a4dd59af4621d6"
    $a1="67394b512dbcda224a2ef0749cdfbc0aeb6e4cfb22a14e348e3838559b9dd0c960a7eef0335512bbf2752a5100ebb04ec13b434e6ee729a3cea726526eb69285"
    $a2="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="cddfcc68ad850c35154c6aca1a70c03adef9d253ebeda58b91c3028b3fe44acfac46ebf6d90a80810389b249845137a758dc0ab0e64d0b5a423080b068325b9f"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="ff86a58729d06321cc03154320194bd9c8de16777be446899c1575cb92e77a3c339152d163c9d29582bd542b7dfca28ab91dbfe7e1a57d489f18e7354e187ebc"
    $a7="ff86a58729d06321cc03154320194bd9c8de16777be446899c1575cb92e77a3c339152d163c9d29582bd542b7dfca28ab91dbfe7e1a57d489f18e7354e187ebc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73fd46d492aec5e03b0af7458e7f852c65786fb2650f28a1d8728a4b5c1f5a6e"
    $a1="ab2ad7b24145b8a9b326fff780008611d381bca0d751e914511c3ac974257eba"
    $a2="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="6fa71e9650b7541e9e5e75e67a434bc1521551a29ad163adb27b7466e315be95"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="8a35ca10a587c9e8ff45f08c13fe45fc5d0d4233341b58f8dfbe1ea361387f19"
    $a7="8a35ca10a587c9e8ff45f08c13fe45fc5d0d4233341b58f8dfbe1ea361387f19"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21c3945f6418df7177b27fbc54bd27f12cb7e8633f2b28044008de2c"
    $a1="632320d4c1e678748f6314f75686d47ab31ec31457fbf307f995ca97"
    $a2="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="74e9e35306cb170b41b514726cc07b9017456d0800f2fbd5287a20d8"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="23d8138b9b97353676e81615f06e359497faca5a0224548a34e7ab6d"
    $a7="23d8138b9b97353676e81615f06e359497faca5a0224548a34e7ab6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7655d678c888d13cd130845df4b7e77dfee0c691cabdaf7ee84c268fb43cdacb"
    $a1="b7170130508f2002460d3e603420011ef75523057e56db8470317e942e388d4d"
    $a2="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="d99cff6dd5fd907def4381b046a27dca74dc887b3c1581e74c16b46543443c46"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="1159364c952bf676504b627e6b8d4420c1ce7eb2916f0ac8ae50eed7e8ced6f8"
    $a7="1159364c952bf676504b627e6b8d4420c1ce7eb2916f0ac8ae50eed7e8ced6f8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab33c5631e10e1b6039c54c9db2d43be1eaab964066f89ff42201d6528df5cab213d2ab4421c8427e2b5338971af4cd9"
    $a1="f456f8a04d373f0a4e18faa5b06f6b46ce00d05ac5c1f84e6f69c65da649647ad659bae5b65c7933e106acd5ae669954"
    $a2="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="742f12e0aca6501a72089aace68a8eec168b18fda318ba2e87ae0ed5046cb1afa206229a2e871d459359649efb5eec5e"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="a94a325f944ccdc2cad72d7da27ddd3798f4446da97d85b1dfa7cd465f877d0ce291197c22500a7d278cae7a0fc3f10b"
    $a7="a94a325f944ccdc2cad72d7da27ddd3798f4446da97d85b1dfa7cd465f877d0ce291197c22500a7d278cae7a0fc3f10b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0e1d999fe06b3fb7277ea27201394bbd012aa62e940931a5ec71153f9c9f523b7c5a022a7d9898a7cd10d3d4f5b40efd20e22b24869c568a82d3dbceeb24dea4"
    $a1="6b69dbfff44c9016c82bc4115674954d12f4077cdc7f7a25231a13e0f46f6cae17e0e4424b09d629935b065667b62c9c7e3b73d98be6ca70863fb7916f5d2f47"
    $a2="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="d2082958b8a3adb6763e540bc84cf911872791ca5a08c0fbbfd0b5888516e5ea4bd7298172cea3c269d06fbce8134607a61140cbdb1ee9fa3611a8e5e607393e"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="60662fbca9a6677f8a47dc94350fc551e5ce56b055fa3f6d5b23ed19d47e04234c3b61aa5ee7980fba5264345c07e40de95a3552ce610899b96de590d6046d4b"
    $a7="60662fbca9a6677f8a47dc94350fc551e5ce56b055fa3f6d5b23ed19d47e04234c3b61aa5ee7980fba5264345c07e40de95a3552ce610899b96de590d6046d4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3dlZXg="
    $a1="bXlzd2VleA=="
    $a2="YWRtaW4="
    $a3="MTIzNA=="
    $a4="YWRtaW4="
    $a5="ZXBpY3JvdXRlcg=="
    $a6="cmRjMTIz"
    $a7="cmRjMTIz"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

