/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_overland
{
    meta:
        id = "2tquNZg0W7XCIKDxbouMSH"
        fingerprint = "bf3787048a97211d43c5d767931662a99f9f412000d857c6fc174a2a2cfe7a46"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="880aa8beaef65966121e8d79ed8b42a6"
    $a1="d94dcf92d61d9df33f60a402b4d61755"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e2b7cd912a2d912"
    $a1="58573d166f8f9ddf"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*EE8326FC0570CF3A62B5CEF5A6798965A1CEEF8E"
    $a1="*BD24DD1014E4A2AB76DB684D9A536824285D533F"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}CZ6+pI6pZmp9ohdyZ5gxOA=="
    $a1="{MD5}HG6YDg7uc6mpUSQ59WZlxQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}8iMdKHHmkKKZVwT3ope9e8ZL5yA="
    $a1="{SHA}5HubECEDSla31fcNktBIFSTnj2k="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="099ebea48ea9666a7da2177267983138"
    $a1="1c6e980e0eee73a9a9512439f56665c5"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f2231d2871e690a2995704f7a297bd7bc64be720"
    $a1="e47b9b1021034a56b7d5f70d92d0481524e78f69"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5889a6a118d1f3968a0216060e6d861eb3b2fa05fc5423674908d92a0c80c335750f12790fa95e03976ab94cdecca47"
    $a1="73114c7a760f92362ccafc80b500ae704167906e9509d6997906df729b4f86e678dc8a9ae7a7f926874920b67b2621e6"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e0537f07091ae104db4a8b939b3c47b1b8c2f4f38c55ee45f871b22b"
    $a1="d9013712ed33598db5fd4ce9b8ed8709bc807fa71b361e9c7e2089a6"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ea15870987d34972ee28de0e6b8ad0217970d473bb0414911753e8a1101cec81ba9f6b0db7fec16b2d0b9cd4c91337896ebdaa033b47955f620834761415c44"
    $a1="5938d9afe029dfd7976b6a64a0535d4abd93801616424098b81ff72daa04cb1c24daeb6397ce04a542405513e4c35746756d328a7f21dd99d5fada7261a25441"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f76043a74ec33b6aefbb289050faf7aa8d482095477397e3e63345125d49f527"
    $a1="c4b97afe643da8e91b649cfabdffe821d270de093e189e264b369c329aa3a82e"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6554dad708a65bd7d3abee2d9c028e2e4c1319fb3ef8a752723b70afd572dfc408d3b1d0d19950f280d8772012d0a35209f5546345c3be1d3367fa34e9bb1e92"
    $a1="ef3c14a1d14912c2dbc35856ee8d08de8b5cd143f8f2a1b8c236f7ef846756e630803fe34243cf58aafa705e03a99d688ea1985a116ad0d1ee2dacf364e3faf1"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b9bbb73c490b862e77461f5b12b60ae92c5460901991c39ce31b7da24f1d878f"
    $a1="5616213d19391447e21fd7a3119ebd9ebf17ef493d3760ef89a4a769b62729a4"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0f81b51cf2be501fff5405ce1426bab4fb53a8bc0089ad4e19fa38a6"
    $a1="d3b41d589a345a9f032ec864eb83dcf994e92c42a7b7943e12d7a493"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9e60db57b96a31d91a6e93b7f4416d257d0b22ab081e6b293e7d23301a9521fd"
    $a1="afec5811ca4b60e82f6b4f88b484edd8420f01539205074dd897fe9003c11c8f"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="420677fb158e8c3207566ddda5f7983239b89f99d2229fb03594b034cdc3d7f3a2253f202fe89931b7953bea6497ae5f"
    $a1="07bc09b5d98a45b3a068a1b342c86374b5a5be23a847e706ac5e7827e273fad1baff63eb5f68424efac7f596b5471f9a"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d887a0e79eb31a236584b5fbc521b86fb5fd317e9d5b381844d65da4e4f318bd354699208fd8f155f70e471e9a5048b815292fdc1f8b772d37410049a9cd1d89"
    $a1="6884d4025cc74257c32e357331c3c876da1609b7009d612d0da5197881e101efceaba542ea7fe1d216d3886a972723ad3cda8865585c29bba6711ceaa23a9525"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="RmFjdG9yeQ=="
    $a1="NTY3ODk="
condition:
    ($a0 and $a1)
}

