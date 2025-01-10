/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_aspect
{
    meta:
        id = "6YlGyOf66lWFOQ8k3DD2xW"
        fingerprint = "d4d42b3d501cf0dc0896b4bd08d7d2d184e30a27b3bd952d3d2ba513668eb5a4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b311ea047e7c1d8d5525b11ed14e0c2"
    $a1="63c16cee3f07283c940cd078d2d145ae"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7fc7c76726ec0aa2"
    $a1="73b86221093f8cdc"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*17971A78251C520425E5133FC39DC737CCE07B00"
    $a1="*23CA0D347529368BB7F75310B04AF328973E2C5A"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}VkmxrsrkQmdoEldfWEhDuQ=="
    $a1="{MD5}GhiUn5JETOhQlluy2RBm/A=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}mnJHW7dHnBQvj68jWvPbERy0R6M="
    $a1="{SHA}B7z0sbmZQ8lft39gzhyrvLiMwAU="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5649b1aecae442676812575f584843b9"
    $a1="1a18949f92444ce850965bb2d91066fc"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a72475bb7479c142f8faf235af3db111cb447a3"
    $a1="07bcf4b1b99943c95fb77f60ce1cabbcb88cc005"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19ea73c1d4b4071f2eafba548e5d49c07bcc678f6c20735f5ab4158b32ce5bd16137b11f762b77fbf07c5468b8f29fda"
    $a1="53b85072d746d6436f988e6dd79617edfb83ce678d900efe95c64cf4f5706a17d57cdc5dd71b5979d51e5379e4f20323"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ef66d39313e803486363a6b0116754fe4814d41fd346fdc6ee1ddc19"
    $a1="5c32ed64506aa528c8e6624e654f0c9a2807f1b886adf9bad383aad2"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c71ecac0817cb2e13de19fe11b79bb6c2b6f0febc3b1656205275f691c01b8c0e6ef9a70f8dafc56e4516fab16e519cdcceee3d58e7214de34df35cf436f343a"
    $a1="cb227f47afe814cab9c9d019a8613751d1bd25eafe152afed284e118b58b0078a8c49f0bb7fe912f381c55f257bd8b4ef6bec4b5256cf9ccb8f107cec23e88cc"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4afb4c1859fd78ec03112d82ea605089c78f7fe350ff098fe1f22596b889eaed"
    $a1="19924fa90248276110c813dcc2420accc205e63debb765fe5481a32d3611ffb4"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4750d18fe9450fed836299927b5501d108a3eb413826946f50db42fd06b2845854d7ad19063dd9f8cd544119e7fe6fecfc2bfec593698066c1c91749da467c9b"
    $a1="0a108d5bcebe7fbce3ebe0ed5a1cf0066b0334afa9dbbfad9786ace5c39fc991f1cd60276777ef57d33ca994dc9e28c78274e17d5a1aaa89d01e5c5c808cd37a"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a01466987d9c7e8f019ca34ef0f1bd429625552a2fd151021b84cca58cd67fe"
    $a1="c3e499629f8208dc87b465bdb21682f66751ce949cc3ce7a2095694c0fa77960"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="634c2f94abf7af46ed1bd91e0d9232c19a4377f841926e2a9593a641"
    $a1="c2fe3bf982847e3ddd1367530fbf855e8a9c43621783d172fd2ff2d2"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="313befa3dd5d8b2606045245fe48492706bbe14c7a4b846305f242e6c6d59e3c"
    $a1="e65f6a6be44d4eeed68fec04b7d9be433afc1fd0591e42a280f520b177f9532c"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b0f9e5c2f7266a20e793bc00d82c28adc1ff5c3b903f81ec057cf6a613624b56e759fad9468aa16cf61d203179e54da"
    $a1="4c21117ec7e9dd46365ea0da5f068289c985f8c56f68b35870efe30878944aeffc18d29ca5bc804ae231191a8ef5ae9c"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f318fcacb18e3f9830c1e965eb4ce3066d7aa4a86620bdeca6bcd53bea99c6676645d9e4aaf860cef4d7abbcc1c07d982091fbf6c5b5835e8a308bbf589e452a"
    $a1="d4ddffe7e3cbeb7e980e98e15537dc5913aed29df5c2aee851671e29060eea07856526665092097db9e1db12cb0c7a3680d7f48ea1eb51eb11a039add5259cb4"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="RFRB"
    $a1="VEpN"
condition:
    ($a0 and $a1)
}

