/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_erpepe
{
    meta:
        id = "5flq9Oe8r1uOJNGFjCWyGH"
        fingerprint = "cc7c7d51ca78c47889c3b570c0d8e17f318da61345c66b0a4d8c99497787493f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ac258b08e5730574f882f45299d9c2c"
    $a1="c12a764b3d8da1ca60e7a5987c3b8592"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4df7bef36def41dd"
    $a1="42650b79515db0a2"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6A04D2A5C776CCD6FBAF68B77FCD29DBB8424466"
    $a1="*94B39DB9DE8EBB3F25A1AAF560E448E261CAC88B"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Vlu6gFo46hXmG9abvvFLkg=="
    $a1="{MD5}wQ12RlWQDxLrwN72+auF1A=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}WALfXpqvrUxTc3ZgXC04T5GoH7A="
    $a1="{SHA}tZfylZ91zxUV5mKK0o0QgjELE9E="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="565bba805a38ea15e61bd69bbef14b92"
    $a1="c10d764655900f12ebc0def6f9ab85d4"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5802df5e9aafad4c537376605c2d384f91a81fb0"
    $a1="b597f2959f75cf1515e6628ad28d1082310b13d1"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f7b7c33aaf24635f11e2827b288ba4af717b0c30d94c3df01744fcb76a2722d63b032867aa7416d88cf5fa6c62995b0"
    $a1="0948c7666159edd3bbc76393c4ded1465caae34ca88fcf7e40331f0c56e818e13d788d7028af4714b65c55f4562559c4"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="489805f9a240bb910b9ca551030c4e5c93f71b241739e07a3b81f218"
    $a1="bbfb8496eaffb6488ae20d68208f6e5b212ab477d79d9b56a1005670"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="01e5ff205af9b5a1e197de2165ff8ae80f2d179b42556056e7adc8d3acebabea5a5864d5d8e7a9cd4e46f76604018cd653cc0eb21fb7998cdaa95b4387face9d"
    $a1="591409c4144947b130526b06577235a6162177196411470c3294e15d603aab6d642be1487c4a3ff91b6e068d6d9645cdc733131ad13b68b32ff9605103315a72"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fa4e70ca1f70252d3c1b8e9fe3da17674ef57b2f44c4ddc61965d693012419e"
    $a1="f7e35c08f92d67b41addd0e5b92617d3c1b8a90124364fe78df0b4362f277e41"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c46095879e7881fb1be8605f501930be2426eb03571c2aefe089118e6d5ac09a2553a2cc71642a36433a7bb835dde9a6c5aa97837deb7a119b9745dd13957150"
    $a1="b46ae04ba0582af4fdcb32c063071d75432fe07e3823bd14287f4f0984a1b8c50637de0200e72a7436e0a71c8a854ea6aee30420a167f705cae95b59968d87df"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="83f790a012aa7d7bd18bc684a42ca8fd2fcca1e83eea40277b5be9cacdc0ddf7"
    $a1="379ab02ff1bf2394e78be7d3068e7cd1d9a03c924cc765c7d8b9d6dd27e85cf2"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="41299c884b7a9e7384e346ef3cf731cc35827f91d6de33667f776cc2"
    $a1="142da49f6474a54e8e3c908a53b095a06e3c92bf03a6a10ac0ca57a1"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae0130b53e1a0a83b2181436d6fb302bb1670580273f45ebcf788462a53d658b"
    $a1="7260a950618522ae4eaf0088954ae4428c75f5b9a6daca8bcad8aea5bc8979ed"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6183f37051c61abb38b39bddbd0553ad8e40bac8c9ae18ac465ea98e34b67473f92149f257802a8a426d580d1246a08"
    $a1="edb0b5aa8f7054b4666d78e7453e2d04b1e1a2bc5225a8f47993cfe9e62177e82450ac3bdb2c43cb85dd10b608ac148b"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3df48ddd03850d978ca8176f69ad856e99251172b1e27f1b2bbe75578dd6a6ab7dc7d7ea12454f0a24209a7bfea1b3a721371cead50966ae279682931334e4c6"
    $a1="35459a74cc55a091fa26935dc48656ee60512e4e7817122db1a58330bc5f2b1733061df22d26b44a0dfca727d66c23cf67fc6b3608a4a88a7c9bff2e7e3b29c5"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y2hvY2hldGU="
    $a1="dGlhYnVlbmE="
condition:
    ($a0 and $a1)
}

