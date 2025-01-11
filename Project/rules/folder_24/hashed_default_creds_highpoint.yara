/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_highpoint
{
    meta:
        id = "2SoZFbxAdRM92ELd7C4UvA"
        fingerprint = "de0b876ce268c671d688b281504bb78e55ee5c8623fe93a43a896ab0f0d26d76"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09ebbade67c22bfee34ebc87391b9fdb"
    $a1="797c35295ff162d2ea7ef1da95e3e4d7"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ae89705221ee060"
    $a1="3d5919227449b651"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*944B9F5B4A29485B8B03C070FC8C5A37111A8B2F"
    $a1="*8A6363C6827D0E6B0629513013C998F5F2D0C26D"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}oc9iMk6pgKsF/uex0xR9fA=="
    $a1="{MD5}z5FRPG/GPOvktjpmRyONbQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}lujsfM1139Vn7zf34yFx4tU2o3Q="
    $a1="{SHA}7Hj8bl85/9qb6Xl0+hz2Fj828q8="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a1cf62324ea980ab05fee7b1d3147d7c"
    $a1="cf91513c6fc63cebe4b63a6647238d6d"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="96e8ec7ccd75dfd567ef37f7e32171e2d536a374"
    $a1="ec78fc6e5f39ffda9be97974fa1cf6163f36f2af"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8c9910f7849d5b1c25ef30db30482bd156954009738a4daff206fae810cc8a7bc1ffc7feba82a6a6d9ab036ce045117"
    $a1="f1a72ae40795fac6f63816d70241563f59041d64450e1ae3df824de7a4295ec4b2a0cc9dd29369c586ccd1d35480f61b"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f889ed39bf0d4ab51a1c44c6697910916bc7910b52b9cfa3b34805e"
    $a1="d406ebf66c1247a5ee6daec2f709182073ba165aa358dd194b0aa162"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8034aa85cb386cc24e948bd92148943cc56a7988d035b7a3e5b094f2a7ddbda85da8cb80ae9952e16018c8167da6641e792c3a2cb888ec45629dbc22d9ec75fd"
    $a1="101b271ffca2c6d7d1394e5ccc45e7130b9f72541d048d66a5502bafd26c3a43c4ee38b1aca0f523b9c0760ef88c01a14f710da91d6946d8dbde520b0d291c57"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa1ca992cbacde62e2ca7990d57243928433d66e789091767de15b390e170fdd"
    $a1="fc0459fef3893d2fc2d113ed43432ca4176c13e00fe14548a0ad9d5f4b16a6db"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b7dceb516fb3ba35b7db1bcae92a23972790a8f392d1294c496031169c0892ab7ceed62ee3d8e0d2dbf4df84851d1d567544b410fb3fa988c2378e3dd0a5b21"
    $a1="2d130e17ac0a62f5b3f3235834dda84e8c81ea04ebf49025447375c767f033a288c9a56c1b04e4149fa7965200018bace11a42d66f4506cbdb13f9e8c962a2ad"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0cd1b45ddbcb86bb8a889f7faec5091741d32f1394a0b4c7113e461c6d89366d"
    $a1="652668a5992e8059aeb54f618c3ef4663dddace1e4243b92143ee261cf6ac1ef"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0b1c8818463118a5e6f37c9d0257b04a9695dd65dc1057400cd555bf"
    $a1="4a4211bc90556a7422e7202eae00bf723273d1a4f7edae532f9db609"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2406ad1483e544e076bc0d43b7e07888c6cf765382694f040d657bd4a6579fec"
    $a1="9666792e2c2a09933262ed637e0374ad3a0993d722c8526778f4c97bd33be958"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="55c3d7d0b301593640bd0c4028933ab5d4948d25f73b494185e1cc02c0122c01e9af682ca176fe4beeb7465c89698ec7"
    $a1="c84476727cb63767a3922a16f3e0123cf28778a8a541b686aee768aaaf613e0df2ac572960ca0d74a4a5627fde5110fb"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54bdd012232ff158c1a070e2b3c15748a1a3f6b647a671d88f7ed09cddbd68bf857ea39c3e29d29242b98d79cd9816434be10f4bc79d118917d1c8d5b800455d"
    $a1="f9f55f91fc6e1dfbb28c6e4712fe5e8eb6e74d039e0219da3bde556ade11fe12bac1c22b1e6d0c6dcf45d7f0d07d85af0c13bf54144e64636a112d4ffbdc8925"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="UkFJRA=="
    $a1="aHB0"
condition:
    ($a0 and $a1)
}

