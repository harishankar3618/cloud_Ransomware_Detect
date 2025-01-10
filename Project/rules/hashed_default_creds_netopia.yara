/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_netopia
{
    meta:
        id = "7NTO4CtJRgYKle0gP20Dmr"
        fingerprint = "0c2c9e0c74419b5cbf41de45d7b57aaaeda118f3cb172779ff11b6d4a80a00b6"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d07decfcd8194b2be29258f0f971410"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="f2a26a379b161ce3df71157f7de6c879"
    $a3="f2a26a379b161ce3df71157f7de6c879"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6caebe9c5af1641e"
    $a1="43e9a4ab75570f5b"
    $a2="0ace9f4e557e1a6b"
    $a3="0ace9f4e557e1a6b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FFA2B3BD57A41AF0F2E003244B7B5C6554799217"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*1917EAF750491AEA862B446E80EB2B73925B630A"
    $a3="*1917EAF750491AEA862B446E80EB2B73925B630A"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}IJfXsGPW+LXMgDq/PfdYqg=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}WZNCi6vSyyU4NOBt4YAJFg=="
    $a3="{MD5}WZNCi6vSyyU4NOBt4YAJFg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}bYzYJOnIb5wcQlLLLf0z3C9X6JQ="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}cmZwc+zZLFdXJAuywDRThhWwPNA="
    $a3="{SHA}cmZwc+zZLFdXJAuywDRThhWwPNA="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2097d7b063d6f8b5cc803abf3df758aa"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="5993428babd2cb253834e06de1800916"
    $a3="5993428babd2cb253834e06de1800916"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d8cd824e9c86f9c1c4252cb2dfd33dc2f57e894"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="72667073ecd92c5757240bb2c034538615b03cd0"
    $a3="72667073ecd92c5757240bb2c034538615b03cd0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64eec76b124335a27abdf2cd9fc3fb766ee95eadd8d119cc9a78e9c00bbb159a8c2b547d9dfb5ab8cadd7fa83a5193f3"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="4b3e1edc3b1184afb902e4a1afe7280a2512740d2cb4a2a0e8bca2f94f2fc46f00bc536a99f5576082a83b19e8548f89"
    $a3="4b3e1edc3b1184afb902e4a1afe7280a2512740d2cb4a2a0e8bca2f94f2fc46f00bc536a99f5576082a83b19e8548f89"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a344a7a157fe55175b70cb5a6867b11b680aeb6e20f8f84b988b2897"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="2a36636a9c970899bcacb080e63ad12da7996344d24b54e61eb7e26e"
    $a3="2a36636a9c970899bcacb080e63ad12da7996344d24b54e61eb7e26e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4388d32f5d77a84bcea8f3502135bf79bc21deb1fa669e00775cc083a50d15fe3c47dc242f6712f24c831b73426fe7b49ffe032d59663859813f41318008c3d6"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="371da7b035a29070b0ee37c16db51d32af6470d9a201fc80070c7fca6d2264c847fdd3f323a971622c5efffe890f3bf72ba2b1816347522b5b1375ec97b64e33"
    $a3="371da7b035a29070b0ee37c16db51d32af6470d9a201fc80070c7fca6d2264c847fdd3f323a971622c5efffe890f3bf72ba2b1816347522b5b1375ec97b64e33"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1f5175cac7219d5274210b1b36acd6e2693a84fe41be92d5810cca2dd7104ff"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="8547b7d11af8a0ddb560ae8e25021ae1c04e299ed3145dddd86a1ed053a6c159"
    $a3="8547b7d11af8a0ddb560ae8e25021ae1c04e299ed3145dddd86a1ed053a6c159"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22b0dae0bc77d7551a5422bfe873dac6a40ecd29b1681b661a31ac42a2009809327c80e4c9e1cea735858a744450835dca72a02353857b9a1f008e03253c0dae"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="d12452ae660aedd5848621b81314abbc6db8b10a5ff5918e9aed1321e5dffbd8ffbd3a7e71e83ab5c3fb25f58a3b3b89517cfc165418d758f6f8cc09d42810a7"
    $a3="d12452ae660aedd5848621b81314abbc6db8b10a5ff5918e9aed1321e5dffbd8ffbd3a7e71e83ab5c3fb25f58a3b3b89517cfc165418d758f6f8cc09d42810a7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="51159e4877dd0c189bfccb3c8a4fa991fac8a766435d522d82f04d01341b7a7b"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="d1d90a972e12df922d9019c07d2ff7c767b8c1a5f0b7f4c7eafd9de4da954b9b"
    $a3="d1d90a972e12df922d9019c07d2ff7c767b8c1a5f0b7f4c7eafd9de4da954b9b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9baed77c2d840f9d027c100f1f09735d55086271731a4344add77298"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="790e62018c699bfdb1d4df6e2264a7ae469d6c9f5e563745250d6055"
    $a3="790e62018c699bfdb1d4df6e2264a7ae469d6c9f5e563745250d6055"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="382eb1cdd10deb82263887f746b3b5d52070073fe9e598aca2432874270c56ae"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="981c96a9a479cc7f3353cddf89d90e04fdf10993fb43293c17b06359242ef8cb"
    $a3="981c96a9a479cc7f3353cddf89d90e04fdf10993fb43293c17b06359242ef8cb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="734336f2919c992320b8b4a2296e3619af30a1a33c99fd223af5e32611d6e5a844bfb33e23af8f7f9ae8d4894d90322b"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="c23021929ae92423cb46e50de33070cd268fa336ce2682a81cdcb02f97c2a1997efb8168393d90dbd6f4778d3da7c524"
    $a3="c23021929ae92423cb46e50de33070cd268fa336ce2682a81cdcb02f97c2a1997efb8168393d90dbd6f4778d3da7c524"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66a646f62cf6febbf71c02724d0019e878e44f06de95233dff368d6c241322ac57268597f79542486ac5757876f77722e73698bf7ffb29fdf2f3717b8c67dd9f"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="d477031231112e4e5328469d4af80d8771c394026160f82fb47c281bd877c1b9a19757081e3cbd68b3ffd86f32edad1f5076eda087e9bd7fc91317fb0fc94063"
    $a3="d477031231112e4e5328469d4af80d8771c394026160f82fb47c281bd877c1b9a19757081e3cbd68b3ffd86f32edad1f5076eda087e9bd7fc91317fb0fc94063"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="bm93YXk="
    $a2="bmV0b3BpYQ=="
    $a3="bmV0b3BpYQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

