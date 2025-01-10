/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_argus
{
    meta:
        id = "7RLxvtXxQn8b24vpHaL5OB"
        fingerprint = "1eb6ea6228efb9144a46525cd5dca46e6b8d66ceb2e4bb7744d7be4abb9fcf63"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cdcc7a35d120c4f1c5da1422a4201708"
    $a1="cf32420fd541befc7ac6bb7f2af8a741"
    $a2="e2136eefe3a79ac678a5e554bfbcdced"
    $a3="e2136eefe3a79ac678a5e554bfbcdced"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4825d68f2c211590"
    $a1="270325dd1bdb431a"
    $a2="660da7241a105f56"
    $a3="660da7241a105f56"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E12CD91AC8FA1DC769505B9F283FAD0EC04AEE24"
    $a1="*E2A47DFFDB3F256BDE9A1D2753DB6D110B3F29C9"
    $a2="*C356E4DA244D8C098B598F140BBDEFB8690ED779"
    $a3="*C356E4DA244D8C098B598F140BBDEFB8690ED779"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}q+bbTJ9UhPro158uhopnPA=="
    $a1="{MD5}ijxMG5AYt90mCjJebyCaMg=="
    $a2="{MD5}wYgMUGCelHJlbIB5qFrwZg=="
    $a3="{MD5}wYgMUGCelHJlbIB5qFrwZg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}q0FUp8RR9W6bf/FTd1jd0MYZ+L4="
    $a1="{SHA}rUdXQ9Qt6BMP2RPBFyE+NwNwe4g="
    $a2="{SHA}gP0Qij16WjxOLNDE2jbJQwmeAG4="
    $a3="{SHA}gP0Qij16WjxOLNDE2jbJQwmeAG4="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abe6db4c9f5484fae8d79f2e868a673c"
    $a1="8a3c4c1b9018b7dd260a325e6f209a32"
    $a2="c1880c50609e9472656c8079a85af066"
    $a3="c1880c50609e9472656c8079a85af066"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab4154a7c451f56e9b7ff1537758ddd0c619f8be"
    $a1="ad475743d42de8130fd913c117213e3703707b88"
    $a2="80fd108a3d7a5a3c4e2cd0c4da36c943099e006e"
    $a3="80fd108a3d7a5a3c4e2cd0c4da36c943099e006e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dedd9fbb2b8711a25753f2faddfd4c7478f584e8f9ee89328f3fdfab770ee19abcc7fbae828335f73500137ee4091b9"
    $a1="103e5f1cc41a1c63748322481e57b28d0abb36a5c0501a2e1f0e9f1357f99867a30d76a844904a52d319525ac0d4696a"
    $a2="0bc7b52b007a84f31288d7e99b499e8f7528fe05baf75303da65e1c361ae4132e117fd7b2b40e4eda69cc420eef0dde7"
    $a3="0bc7b52b007a84f31288d7e99b499e8f7528fe05baf75303da65e1c361ae4132e117fd7b2b40e4eda69cc420eef0dde7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a5fcaa8156df5fc8f006e239b44d01fd54862cee3056ef9ece150db"
    $a1="c63484920f98fc2d476054699e79b0b05747087251f5b2a2828952cb"
    $a2="ea6f7d82eeefde0a23050c5d1a719c6f4df06e471f5ad667da5ce48e"
    $a3="ea6f7d82eeefde0a23050c5d1a719c6f4df06e471f5ad667da5ce48e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d5f92dcae90ec87247840df8a76a195aa1cd0f7fe996b1d79eb6f9da2294338a556b46cfd64e0fe3a00b71952e17a72880b01540485924150fbb5448098e6853"
    $a1="4831e9025d3b3dd22c67747041809111a8be45a305fea7ec919cfb959ad10010d855ae2ba42b9b3156de2a24066522d977a601148002c58610a229264fde82f9"
    $a2="548949b8bfa4ea6042fb2908c25fcd07282ab47b63c055db3b019dc2aa5747ec6ae3754cb1d22d297c78e87b68fad08bfa30737779e1c98d9c8987602c3bd920"
    $a3="548949b8bfa4ea6042fb2908c25fcd07282ab47b63c055db3b019dc2aa5747ec6ae3754cb1d22d297c78e87b68fad08bfa30737779e1c98d9c8987602c3bd920"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48c5a1d217fe85082464d2ca1e90a16d15464fabe20f8610d79b63aa58797b9b"
    $a1="cc4fed175f09f5095e026bb8b492e1a4baa11500ebab0866aecdbee6c44d2ede"
    $a2="444b759c5264422ea582403ae2083d2447fd226a2e40795968dd740e9202cb97"
    $a3="444b759c5264422ea582403ae2083d2447fd226a2e40795968dd740e9202cb97"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95634d08635b26a78df2c5dc103556cc1a15ca5858c8bda7e04b16f9e68a8644eff5d2508be346a0c3ce742f064aa9abcc65e60302b589ecf88178ebcf9bd9ab"
    $a1="b8f9e0df0ffa0732974eb4d904e6ba3d3a9588fbf0bb65d5db3c057087e1408f760c4acb326da95ed56a8ee0c510fda49cd58b6f9f325b8832323d2006a2843e"
    $a2="0293a48f83a256d0cf9a961c1f4aec452b82a135c93b3761f69e1ee3004e9bfc4235c754c68396e42bca688d3fb1f288005892d049c912b3cabaa6ab33ec3e95"
    $a3="0293a48f83a256d0cf9a961c1f4aec452b82a135c93b3761f69e1ee3004e9bfc4235c754c68396e42bca688d3fb1f288005892d049c912b3cabaa6ab33ec3e95"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1afd6171483ae4dd7a2baf511850ebc9900b1adc9d8c37823a7a0650461a2c72"
    $a1="7bc949a244b64cf0831b70592c49d41bb3c5404b39576803da2840f8b4511c37"
    $a2="f018eaf04c595c3a82cc4ea20fabb1e49333d35a1430901244465165a57e85dc"
    $a3="f018eaf04c595c3a82cc4ea20fabb1e49333d35a1430901244465165a57e85dc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65a8b6efd24734f6e40cbfddad07491caab5ef3ec7f783df05aa1f7c"
    $a1="23b439bd6beba63f0212d717dad0449ad1bb54a1d100e2f7e3992387"
    $a2="f126332a9852d17e79a05018762b73e18f5a422576d38a5ec91907bd"
    $a3="f126332a9852d17e79a05018762b73e18f5a422576d38a5ec91907bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="479c8cc5b15e63edffa494719fb284525dcd351436ef9be5c6761eaead136c82"
    $a1="20615eac5ea29f807c12ce867d1e642cebf25b1f634a30e67fda9ec159f8fb08"
    $a2="083879a0735954f146f5331c90806948ed3dd6ddf7503c8106ec47769da20480"
    $a3="083879a0735954f146f5331c90806948ed3dd6ddf7503c8106ec47769da20480"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b0be128d62f2800d7c12e8c90d361257b3df6638ab81a873d6c095a6357922cb910e3fb506739c6b812a564b49810da"
    $a1="428b7583e7ccbd3ead41157bf93e56ef8ff8eb6131aced0d046f9750a131eb5477dff3e7acdc65446d2f06a53a943d8a"
    $a2="3b29171c283a0b18aae5868de7d876dbd3246f55a1855fabac4d247425f50f1f41617cadae253f6546b8eadfa8d10755"
    $a3="3b29171c283a0b18aae5868de7d876dbd3246f55a1855fabac4d247425f50f1f41617cadae253f6546b8eadfa8d10755"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bae826dd03f7c866258d7b93bde4be7ffe42d0039032436fa517abbe03da5babd149068e8a7f3f913a474a5c587ece5b7c005f7ad888b2c68e8651a7d40e518f"
    $a1="9e2ad5e823976faef863b663f7dd27f89cf92da0f6b809f0826bfaf0e797a6a6cad4e1829c29c57c4926a3aa7d41496d0a8e418f09727d104008d640edf35991"
    $a2="90a0022e1974ed15b6f901161c51e5f7452d66c428be5e6c49129c03c95969fc940f8cfc463fbb2e307f5e2c5b4aa01b1cafff01f64dd804b48c10b993a5f87c"
    $a3="90a0022e1974ed15b6f901161c51e5f7452d66c428be5e6c49129c03c95969fc940f8cfc463fbb2e307f5e2c5b4aa01b1cafff01f64dd804b48c10b993a5f87c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QXJndXNBZG1pbg=="
    $a1="bWFzdGVya2V5"
    $a2="YXJndXM="
    $a3="YXJndXM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

