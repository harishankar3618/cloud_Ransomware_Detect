/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_atlassian
{
    meta:
        id = "1I7WrlHTC2vv7O085Vq4cz"
        fingerprint = "afce9c608da0d1a140a8d91e55db6425adcc6038d31062c662078d3d8009d94e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="b8741d00cfaa40237c3bb7195ccc34a4"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="58e0f9d49806a4bedf29e3c368e4635f"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="46cd3aaad1927e1f85318ef93cb6cbdc"
    $a6="8846f7eaee8fb117ad06bdd830b7586c"
    $a7="c2ea9f38c2f3a9644a08834efca06f70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2e19393cc5ef67"
    $a1="0ade3d656c0c51f1"
    $a2="5d2e19393cc5ef67"
    $a3="70e319ab67d975ea"
    $a4="5d2e19393cc5ef67"
    $a5="16fb0c0e50810356"
    $a6="5d2e19393cc5ef67"
    $a7="12a507a15e1e7ba4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*37C0FC4B481C259C62A871D39414BFD44F19D98F"
    $a2="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a3="*E12BA429616A9EC6A279F2D578507FEDF837F403"
    $a4="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a5="*5B8552F2BCEBDD4D11CF2E554F39263B7C9207D9"
    $a6="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a7="*5F0388AE069A781ABF124AC24BC929F36352BA2D"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a1="{MD5}7Kxv5en2YZo5LRRuiwxpKg=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}8CWLZoVoTBE7rZTZG4+gKg=="
    $a4="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a5="{MD5}9gOdRLKUVrIPjzcxVa5Jcw=="
    $a6="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a7="{MD5}npiYx9q6fk5iYpbcfJm9Fw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a1="{SHA}lmNVU1tW8atp0b5yl3Ir/0WUNWM="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}5SyFTVYx7sdGi6Rye0x363RfKWU="
    $a4="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a5="{SHA}hMKQFd4z5dIkIjgqNyyrpcWPjAE="
    $a6="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a7="{SHA}6ouNieS3Mg1zI2s3WnaDpMzTopY="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="ecac6fe5e9f6619a392d146e8b0c692a"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="f0258b6685684c113bad94d91b8fa02a"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="f6039d44b29456b20f8f373155ae4973"
    $a6="5f4dcc3b5aa765d61d8327deb882cf99"
    $a7="9e9898c7daba7e4e626296dc7c99bd17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="966355535b56f1ab69d1be7297722bff45943563"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="e52c854d5631eec7468ba4727b4c77eb745f2965"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="84c29015de33e5d22422382a372caba5c58f8c01"
    $a6="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a7="ea8b8d89e4b7320d73236b375a7683a4ccd3a296"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="ecc8b9e30f105b8f50cebb6aca60d3e6106cd2a65b34fc315a69a26ba6336316b1ebfa55a89e18cf828d55cf3f69b544"
    $a2="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a3="5c1488428584f373fe5de7089ac4dc2d6af42bcc038f9876918ae33b4c3c0678e5a9b90bfb05947722b3637d462666ba"
    $a4="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a5="2a161a2ccc61d47bf69a1c3710d7e4e81625ccedba205552086aa0bf5a902cccd0213065a2fe8b67230f562cf7ce5310"
    $a6="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a7="a28d1366f93b98aac429dcce1a670edf63488c0400720a77c2fc4890f514e93c0476ec6b6df5e388eaf0b7cf7a154cb1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="187600a5bc426f436a588ce4a150fedcbba494c9e5189b8fbc2c8e78"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="edcbf9795847b8a2127aa24594e32fb9e47158bed610a23afb09236f"
    $a4="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a5="531105236d0f537062e00dead709e5586948380805ec402c12e1f772"
    $a6="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a7="f83fe22c5d1f29fba0410c28e50a91ffa909f84570152558d7d3fce1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="9ec66837c9fdc1508e24acaa41d148e22e03bd473fc5afd11d230c587c766be13c8f865522bc6bf3e0eaf927c97b6dad80594881bedaf1c06542b55842f45698"
    $a2="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a3="4cfbff66f656e328b2b7c593bc198174b1e09b113816040c8f567cc26f03c6abe13ef411f6f5e4c99d7928c23e45ffcb5714aca00bfbc626c8d31ce068dfa8fc"
    $a4="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a5="2422209232976a5ab86c86ebe89e63638ecce4c6eb6fc09896e5528b08c89f9db46cabc46f352c12faeb6e08afdeab43b5924f111c5c375211696d267d4fb980"
    $a6="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a7="36f0d36e6f020fc648af15606ecda7c25fc78db989fbd0eb5948504b389f92aaa3c3b934b2ae18f1104490a033f732efbb03526938ded59e944be89e0e9c6bc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a1="f469beecc6e76fe41fc4556460ffbc64e57bc2161422a9d54657232e3c631e1b"
    $a2="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a3="8a2cc0673b1c428315fe84c0138d95c3ddda30baf81e7d9aa821f1ca47098193"
    $a4="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a5="e3b89e9d33f88e523083d8b4436adcc3726c89e97fd3179a2e102d765d1b16ed"
    $a6="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a7="766cc01117955ddd300c57d26a3ad99462ddc11c7446ab610a5baf7a4b993221"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="8ba5b1805544195a73a4a523850d088f20f9a6618ddfb82fdedfaa7d3b90753a24869010a56c396928719fc85a2eb7160d5c800de75390032c7c41ee9b3fa41b"
    $a2="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a3="d0648eadb01154c79b43028fe4f35825d28c13cb0deb390ec754d89c6530c1ed5781844f20d0b133a5507bf08821e815cb69876c93faf003a84e4eadaf9b1031"
    $a4="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a5="f249d4309451f14dae44fe0fdd87cc1e34d2720d3b09e220237e81bb673879ecdbc7fb00efad6311ec531f219fd7088a02deeaa48399dae0b6dd6134bb9bcdff"
    $a6="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a7="bfbe0941012164e0ebe7773db6dd1e1847501917d16d34c44aab160b67a45091f69ec0bb56f4de91d6d5b953adabef6bc6867230d89f645e294300167937250d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="1a4644c3f2b6600a4056f5db7c82b54abb23d9a3187db7f777a7f618aa7c1623"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="db896e1aec0f06f4ef36f589bdc2e7dc96d4fd0deb51538a90806f6025ae3291"
    $a4="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a5="8b1d631ca5f3da655b5ab728ab0712650f16585c86b2abdf1606dcd2bdaca61f"
    $a6="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a7="76463344ed6927e84913687b34962e1fe36478daf4d948328c697de561bb4987"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a1="1e6f2de922945eeaa42204a8d5d8af95f50609578e3e8429507254d1"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="584329b667261e773acb3f183233dd682c225a0a9bdc551e0f10da8e"
    $a4="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a5="eca85ad4df91e877b0c299df0cd0dae2a84457bdb1dbc0a4a119643e"
    $a6="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a7="f948650be931713674a3be682d6b6a1b58b2a6849b46218491b5cb09"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="33a944926ae2633d9ce18cd7c2c8f7295b5632061ab3e8cb1adc1dceaad2fb2b"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="ddad25fb24bd67c0ad883ac9c747943036ec068837c8a894e44f29244548f4ed"
    $a4="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a5="657a4cf2a64d6fc3a8d217a4e1b79547d09efb1db74e8eea4e4cd799132c8bfb"
    $a6="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a7="136801b319f82bcdf4e6b1fde390e8bbc2bfea542fa749ff6b7d625d0194359f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="e045c6bddd0cc3c6cf894ee706ea7f5af2e77f37a61fd98f8cd5e12aa0a00161dd595f3e8fbe48c6be437a30b6148fe8"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="34fffde42c88523308447aa4af6b10f6ef258ab6e15a0a4c364fcb40b1f980febdf801a72ccd980fd2669ad4f40396be"
    $a4="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a5="9e0407173e24b9c7b4f0137ffa93f405f8b38d6ef86853a5b28d35ae0e7b07c685512cfb17521591d9ec43b3c9c16e87"
    $a6="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a7="74f4f7f06d611aa589d314f00862805a1fd0aacd6570abf369f3b4530356f0944c06c45e7d1f72b3aa0a603baae0488c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="ed49c59a1102e2d1a9e587ba701749ce0a830119501738eaafd88dba2b1ceacfff416233e480b370a2ae5984aee680b69eca0fe6ae2075e57ba3f0f6394d4bc1"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="7201dcc5994fb5d74bc79c39ed7c755924c0d29a71f2ddbc257f35c69f06b4f730b357f71469e7087597e77e9538c300ea5c988dcc57e21a3f93a9a1d466310c"
    $a4="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a5="c4bd18fa15530ea1532d144aff5e7665dc92db28e03c7a0a421d1d0e16948c05178f47df0d5044c35a2c8a2be82e3ec881e81d4127dc6c301a188be799e14aaa"
    $a6="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a7="da0c5013c9573a8180a672f335ab7d8f7dddb4a39d71514c40193fa537afb39fadde316eec144d73524adf70e5bcb4b1d5ba67150d3d52e5df29058418dc5a57"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Q3Jvd2Q="
    $a1="cGFzc3dvcmQ="
    $a2="RGVtbw=="
    $a3="cGFzc3dvcmQ="
    $a4="VXNlcm5hbWU="
    $a5="cGFzc3dvcmQ="
    $a6="Y3Jvd2Qtb3BlbmlkLXNlcnZlcg=="
    $a7="cGFzc3dvcmQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

