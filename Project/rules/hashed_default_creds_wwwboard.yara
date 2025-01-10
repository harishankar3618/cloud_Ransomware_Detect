/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_wwwboard
{
    meta:
        id = "16XIaYNuZwSkMG4pIl4c8J"
        fingerprint = "118fa725ff59819bd3ff63d3561c4484b3d676ff826fcec3c5762f20cea9bb91"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cdc328508bbd9e95f1ac010a432a3b6"
    $a1="af62387d97bc187df65ba77fa0d55881"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7bd53d105be9744d"
    $a1="663a338900aece54"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6A65D94A9922AC8F60241076596FE2A17BB95B61"
    $a1="*AC2EDF6AE3017AA35C7234A7402FEB37E7AFB161"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}XMvXRfVLvSHqq1qSBHDblQ=="
    $a1="{MD5}ioNRW/u5RT7cEUiHAd6YZg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Shr8Z076jwnhYU/suvdLiCtsnA4="
    $a1="{SHA}MYOkLzFSlSJkGyKW4j6oVyOvqLo="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ccbd745f54bbd21eaab5a920470db95"
    $a1="8a83515bfbb9453edc11488701de9866"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a1afc674efa8f09e1614fecbaf74b882b6c9c0e"
    $a1="3183a42f31529522641b2296e23ea85723afa8ba"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fff4bdd8b80e7c90ffd86dfc002002eb0bd25127dc4650abf1db7c1fa1c20ac3221d96a80da8184dbd65475c8f974093"
    $a1="a62b2dab63428f6f0a7afb10c6c313b1b60efcd904128e4e57e90d142dafef00187676b61d93436975f7d3897e5b1548"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="011292aa062ccd8748a03fa57880967af3c3fa545b005931860e94d8"
    $a1="e22929f28f6ce70e23d311460c058c08b89e4a365a44ecb5d82cb384"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21c66014a21008e9addd9e93d4ae2a8e30f8553399745360717b675f3f8a8ded0ec0bc17b6572695658d6d0fee8c83a8b83ebc688696b4cb9edf0bb51dbc4491"
    $a1="401ea91dcbd27df1131a68e94457b637be81684d124798b89af3fc36bfb06651d051c970bc28f66abe58045f92c7b4301d52306c47914a646eb71c04a2a3438a"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80206c19108c3f9c2ed27f18e2d82ddd33c171d1eec5f7840aaf9bf0a39e9620"
    $a1="fa51b6b0d572174d84022a102cc04d0ffd92843b624564f583dea799199dada1"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="00ffdd5905eb7c82c8d461b003b7e441a2d36047ba152b71e4c7e4fd505b77c6399478e66a6e9571c040403a5913678e67ccd826d9552ceb5e743b60be6971ba"
    $a1="4ad550e8678f077e4b1e428b78898797f8170e8c08d5bbc7b56c96418ffbc127b3dadff9a96eaaaa3bdad17979a007f32880c9132118570edc2832853cd3f1a3"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="544a10365bafcf8c2a1ec2b8e628258d91a93630f33ca897320d720ae43f0c4d"
    $a1="fc7efdc12ef525ef72e85353bd9724a32c2cd23c170e6dbf78d1c2ea61f05cbf"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="994851f0513e3b3a581f04cf123c879b2dda234ca6f5679963fbfda1"
    $a1="46f7e0b16158bd520e253f7bd4025d79c1b3b8108fcc5d4293995d95"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90737781f2c8af2dec3909af0e73389e3e6bb43390641aa18d9766f1488261ef"
    $a1="765c936570c3b52588a1bb55b66384f51a938825183c15b21a3323581f301771"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0238d91da7ecdc52168d739c610378d8aa9c562e900621351e4e3382f5ca77503f23e6ffd6acba1777cac5897c6fe5e3"
    $a1="ffdac43a0d42b96c9c21cdc7d3305f26ff0d397e29ee6c88cb4f4531ed7c6809cf5ddfdb01b0a334dd0360db73242564"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="333abe9a0c5a6e5c2f708742138aa520160f9ca27bcfde7d78ae254ff2473034485e3283a485e56c1c9f3c2df2fdb3521ff5696f8c6d208fb5c662a2d149f503"
    $a1="9a6da13771937cc2a8c3d3cec5b5829c6b063404c12735805d5ea48d2ae818ca61d665b0cac0083e928de62eb5059709b03240c5cefc49222f5483c3c7ba3f1f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="V2ViQWRtaW4="
    $a1="V2ViQm9hcmQ="
condition:
    ($a0 and $a1)
}

