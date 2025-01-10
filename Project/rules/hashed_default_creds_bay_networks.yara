/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_bay_networks
{
    meta:
        id = "1B7H5Gi8HnGuXFtSYlbQiH"
        fingerprint = "589661c12278c5a3c1ed35b122919b7c60dae7e75e61c5aa1257cda69bca6cfb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d5e9e0db50ba46b948853221be26da2b"
    $a1="d5e9e0db50ba46b948853221be26da2b"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1bea6e365840ca17"
    $a1="1bea6e365840ca17"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*1FDB0D828172183735F1ED9E45E6AF3CE04DE9D1"
    $a1="*1FDB0D828172183735F1ED9E45E6AF3CE04DE9D1"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}6R5jSBV4aN6d2LJcga6/uQ=="
    $a1="{MD5}6R5jSBV4aN6d2LJcga6/uQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}jux7xGGAjguKKHg9C+waOiLrCCE="
    $a1="{SHA}jux7xGGAjguKKHg9C+waOiLrCCE="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e91e6348157868de9dd8b25c81aebfb9"
    $a1="e91e6348157868de9dd8b25c81aebfb9"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8eec7bc461808e0b8a28783d0bec1a3a22eb0821"
    $a1="8eec7bc461808e0b8a28783d0bec1a3a22eb0821"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d376d415ff3adbd0789a49e08380520f5e7822b9a6fa5039943bf2eb12def6321d3899471be27e27f69e2fe8a58e29c"
    $a1="7d376d415ff3adbd0789a49e08380520f5e7822b9a6fa5039943bf2eb12def6321d3899471be27e27f69e2fe8a58e29c"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36e21f2bf0c4247e491d0fe56b2874f8de7aa584a04e88254cc14bbe"
    $a1="36e21f2bf0c4247e491d0fe56b2874f8de7aa584a04e88254cc14bbe"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f2a46a9101d3b65c419c98a9ffe73c154196bc3e87379491746cf5a70ee0b5e4d308b27b28f77960582d8ff88ab7c3c4930860436bf05d6d5517c8e3f9efb8e5"
    $a1="f2a46a9101d3b65c419c98a9ffe73c154196bc3e87379491746cf5a70ee0b5e4d308b27b28f77960582d8ff88ab7c3c4930860436bf05d6d5517c8e3f9efb8e5"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2d3ceb7abe552344276d47d36a8175b7aeb250a9bf0bf00e850cd23ecf2e43"
    $a1="5d2d3ceb7abe552344276d47d36a8175b7aeb250a9bf0bf00e850cd23ecf2e43"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="910a5dd56e159138447be1627f041efd4a2d76795420b001460c9088f4e0d9d5e7e32276518544b40ac958491793d557b62fe8c1141794bf94ee98ffe681283f"
    $a1="910a5dd56e159138447be1627f041efd4a2d76795420b001460c9088f4e0d9d5e7e32276518544b40ac958491793d557b62fe8c1141794bf94ee98ffe681283f"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ef65cc2ca9c5aea4bd3a676ebe0d4d0830ef86d040b6612912cfa92a177e919"
    $a1="5ef65cc2ca9c5aea4bd3a676ebe0d4d0830ef86d040b6612912cfa92a177e919"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64a5f4e4de37bf608e98ea275502ca5a18e4438280cab8467e59b98f"
    $a1="64a5f4e4de37bf608e98ea275502ca5a18e4438280cab8467e59b98f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10414145323772df86d67f55a07a80e989ba7d893f8fa9a79031b2d7000ecdb9"
    $a1="10414145323772df86d67f55a07a80e989ba7d893f8fa9a79031b2d7000ecdb9"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e93d6fd44e5a6e57fc6083328ed79695f48fec43cab2e5b2d797084fba8ab17ddcceba629dbbf75c6fef680193fb4c40"
    $a1="e93d6fd44e5a6e57fc6083328ed79695f48fec43cab2e5b2d797084fba8ab17ddcceba629dbbf75c6fef680193fb4c40"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9590db8c6413f2ef63a7c9c616a73be75b4c1a95fa38a802858077a9e2d4ad8b644be584e0457ed6248426dedecc970259ca575adaf1f0a171c9e0085617387f"
    $a1="9590db8c6413f2ef63a7c9c616a73be75b4c1a95fa38a802858077a9e2d4ad8b644be584e0457ed6248426dedecc970259ca575adaf1f0a171c9e0085617387f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2VjdXJpdHk="
    $a1="c2VjdXJpdHk="
condition:
    ($a0 and $a1)
}

