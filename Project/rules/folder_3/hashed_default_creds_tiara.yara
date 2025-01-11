/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_tiara
{
    meta:
        id = "7Ihc52iRQYTem8QOrLMCXc"
        fingerprint = "3758d6ffb449c72e3f82466523d5b819af1add4407d9f69e45fae40461b4297d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23626add1673bb15fe516d023829bc10"
    $a1="81e5e425b5cd4556e9df4926c46fb0d4"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="559b542634b2b519"
    $a1="03380e6b14402010"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C12A7DDBA9C586FD142E27B90443844C3A65A57D"
    $a1="*FEECE8CC85EB78F1E3F310A54A296D16E03D6905"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}OY7xO7FsidpQ/y0X7C6eLg=="
    $a1="{MD5}RgC7i2a2oq93H7sFZnMhlg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}b2bxo24Ipw4luxX3xtc5zoNHLas="
    $a1="{SHA}w1v24rK8c5f/nyMhw57KvZBD9nE="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="398ef13bb16c89da50ff2d17ec2e9e2e"
    $a1="4600bb8b66b6a2af771fbb0566732196"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f66f1a36e08a70e25bb15f7c6d739ce83472dab"
    $a1="c35bf6e2b2bc7397ff9f2321c39ecabd9043f671"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c9f709376bc7e12a85c675db5f0af675ddbac325021de19cc1cf7543ebfc7e4489ce3fcd075a52526f70a9c63b6d639"
    $a1="e8744e7407cae08f9170caf620309cfa1ddb1807cc9f0d497e0b03098ad3a63f6633f9509b0a2ce5203c5218fb438382"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="260bec252c0303fddecf39ad22afebd350e49a96300ddb9c280ebfb1"
    $a1="f9944cbb94a0c0a2b2bf8a6b718ed2f4d9a8346b32c739c221a1718f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98c2f891db63d6f2c0b925ec72d005b59ea25a8817da9387bd16890666180bd7dc9cf818374b949ea33ccbec2d51271fa9a6a8613d5a0b9652d139781f13b59b"
    $a1="25fbbee6fcd8bf82005c2bd26de781c81060d780cfc4629639634e5ec647c71a7ed4094d51b387b1d82135aac539042b35a047ed0955d3ce4a59e262e9c0f3b2"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8581b8e80abe1d9d8417292f0772a6515618ada70b6c8b7be3a130f9b273b3d"
    $a1="51b57fa2315ff3308a2fa19b79c6682e7449ddc241eecc900180d064c16a24f0"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="02eb805bb6f27654bd1ed7d9879e2736c8a759a71944db2081828472450bdd998187002ca1f1f8395365699204e3424158e648016a16484461fb97102c5f5e85"
    $a1="afd1f93f57cabb1de66da1abd14628d2ae2bf9b2c5c5eb496dfa19c9ebf6153b0ffeb01b96aade0dc718d91307aec78a124ca450b66070ce146232d402843b9f"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7773143d6f688b61884dd6709de4a4e3d8ec6968b15dfcefa11c3d4cef113d2a"
    $a1="01e9f1dd98151f82714350a2c4e5537b519e017cdb24b9d8ecf9c25d82b90792"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6fc0ad96d39def6ffe8297153fcbfb5631c7a1d5b2de79eb16e66c7"
    $a1="fbbab0892e4437ccc7d46d062ed777d2616802bf313480da4a2f6352"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65cb8399e1b0c707af3d3309028e39317742c1bb123c4257c1d9019f9da1ea00"
    $a1="bdb4ac0899250d3b1e82ead3c77ab3103870d1ad81d551a0c4c6a440c850abc0"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eac570c2e6e211425a60e32cb04ec6da7b626126dc7bf1b8aad33ce166d1b9f2ba83d6354a430d461ee0bbf78a6c3bc9"
    $a1="e619b85b927015fe24086cb9b22540eef895d6b4b87179bfd9d4911d90a388ea6594cb13f811bc6e3b86d8e15d1046db"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11f8ba115294bfddd613264d0842061bd124ba8442facf3fe7b0f75a59ad32ef0caa2fc50b653106afa4447baa0ce0078a55d7d6ca37ef96b2cabe79d56cc196"
    $a1="eecc8c5c5c8268bd52440a00183fabec33ac6b2763214b19da54651f8017339d05c0f51dd02783bd4d3846147e192ae34062618c00ffc1a2c10248d43c6ee182"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dGlhcmE="
    $a1="dGlhcmFuZXQ="
condition:
    ($a0 and $a1)
}

