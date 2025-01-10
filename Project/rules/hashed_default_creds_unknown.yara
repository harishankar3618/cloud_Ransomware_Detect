/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_unknown
{
    meta:
        id = "5aCovpemOXFMpk7iqzMyza"
        fingerprint = "66dbd78b256262a4e3e5df6c388ce90de9b3256c7b93171eb8b30a4a3ec56d0a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="20fbb7d3552870a48725ccd3ef2f74b4"
    $a1="20fbb7d3552870a48725ccd3ef2f74b4"
    $a2="e337e31aa4c614b2895ad684a51156df"
    $a3="e337e31aa4c614b2895ad684a51156df"
    $a4="0cb6948805f797bf2a82807973b89537"
    $a5="0cb6948805f797bf2a82807973b89537"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76779e856ee86156"
    $a1="76779e856ee86156"
    $a2="4297dfd67bfb01dd"
    $a3="4297dfd67bfb01dd"
    $a4="378b243e220ca493"
    $a5="378b243e220ca493"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*17CE4DB46F337A305C612896DA3B78B6388084EA"
    $a1="*17CE4DB46F337A305C612896DA3B78B6388084EA"
    $a2="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a3="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a4="*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29"
    $a5="*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}efFT+Ips3PJfWsui+w98jg=="
    $a1="{MD5}efFT+Ips3PJfWsui+w98jg=="
    $a2="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a3="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a4="{MD5}CY9rzUYh03PK3k6DJie09g=="
    $a5="{MD5}CY9rzUYh03PK3k6DJie09g=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}93UWZEodOjCEGUzul+j66dHGr5Q="
    $a1="{SHA}93UWZEodOjCEGUzul+j66dHGr5Q="
    $a2="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a3="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a4="{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M="
    $a5="{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="79f153f88a6cdcf25f5acba2fb0f7c8e"
    $a1="79f153f88a6cdcf25f5acba2fb0f7c8e"
    $a2="4b583376b2767b923c3e1da60d10de59"
    $a3="4b583376b2767b923c3e1da60d10de59"
    $a4="098f6bcd4621d373cade4e832627b4f6"
    $a5="098f6bcd4621d373cade4e832627b4f6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f77516644a1d3a3084194cee97e8fae9d1c6af94"
    $a1="f77516644a1d3a3084194cee97e8fae9d1c6af94"
    $a2="fe96dd39756ac41b74283a9292652d366d73931f"
    $a3="fe96dd39756ac41b74283a9292652d366d73931f"
    $a4="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
    $a5="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12444a31ae294042d7a281f5beea379ba4ca3699319673c5f5dc8b64630de9abbc6c338b3f91218b4a09b47f11607b37"
    $a1="12444a31ae294042d7a281f5beea379ba4ca3699319673c5f5dc8b64630de9abbc6c338b3f91218b4a09b47f11607b37"
    $a2="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a3="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a4="768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"
    $a5="768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ecff67aea52a4dd9e96c5ae660a311d31229c96aa548b2ea9315627b"
    $a1="ecff67aea52a4dd9e96c5ae660a311d31229c96aa548b2ea9315627b"
    $a2="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a3="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a4="90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809"
    $a5="90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f52eb8f18b079077efb7730a8a861075caa7887c3f846640f6fa3e2a8861be95a077496f0ff05365c7006787e6a4b0dbb50629779d3a0e221fd8beb0ae3d3ac"
    $a1="5f52eb8f18b079077efb7730a8a861075caa7887c3f846640f6fa3e2a8861be95a077496f0ff05365c7006787e6a4b0dbb50629779d3a0e221fd8beb0ae3d3ac"
    $a2="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a3="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a4="ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
    $a5="ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e117fc61b613553c380b34b0ed4f7afe087008fab3d56bb7d08b825353a55d5c"
    $a1="e117fc61b613553c380b34b0ed4f7afe087008fab3d56bb7d08b825353a55d5c"
    $a2="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a3="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a4="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    $a5="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="72cf2d94f56d5425fec45bb8c8aaad18141e23a009f9944a2059f890e2e054c5df494c883b4dbf86a0ca7c03100da5277723edd727debd8ee2748cf5e3a5b402"
    $a1="72cf2d94f56d5425fec45bb8c8aaad18141e23a009f9944a2059f890e2e054c5df494c883b4dbf86a0ca7c03100da5277723edd727debd8ee2748cf5e3a5b402"
    $a2="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a3="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a4="a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572"
    $a5="a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c53f35af18c515119fbc42364b0f9b2e9ddefc8f861182b28d3c8457eac5f9bb"
    $a1="c53f35af18c515119fbc42364b0f9b2e9ddefc8f861182b28d3c8457eac5f9bb"
    $a2="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a3="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a4="f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e"
    $a5="f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="516123157c0a43ae70e5ac73b4d294b1a67e03b5a02135049c26baa6"
    $a1="516123157c0a43ae70e5ac73b4d294b1a67e03b5a02135049c26baa6"
    $a2="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a3="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a4="3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b"
    $a5="3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47ace37ace27763fd73f6ba4da94d079e936ea911b53ff796d6a0bfc8b4edebf"
    $a1="47ace37ace27763fd73f6ba4da94d079e936ea911b53ff796d6a0bfc8b4edebf"
    $a2="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a3="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a4="36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"
    $a5="36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e28945e920f2d02c945cb42d93660ff5852fe6cea6c39f8c9df78d11919b47f24699a2c5ef4ef9b915823d24836f8ad1"
    $a1="e28945e920f2d02c945cb42d93660ff5852fe6cea6c39f8c9df78d11919b47f24699a2c5ef4ef9b915823d24836f8ad1"
    $a2="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a3="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a4="e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd"
    $a5="e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e5d2f7ba6b56ccceb17653d8db367a1e40add3b49957c6e9b403b4e9635610691045069ffc330ac0b232b63970861b0ffa0abb61752672ddcfd79a4882bfbc6"
    $a1="5e5d2f7ba6b56ccceb17653d8db367a1e40add3b49957c6e9b403b4e9635610691045069ffc330ac0b232b63970861b0ffa0abb61752672ddcfd79a4882bfbc6"
    $a2="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a3="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a4="9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14"
    $a5="9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3ZlcnNlZXI="
    $a1="b3ZlcnNlZXI="
    $a2="b3BlcmF0b3I="
    $a3="b3BlcmF0b3I="
    $a4="dGVzdA=="
    $a5="dGVzdA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

