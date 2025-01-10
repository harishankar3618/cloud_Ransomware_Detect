/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_main_street_softworks
{
    meta:
        id = "1vVBLhMtYXZKcVyZ7Vctm7"
        fingerprint = "64a484d7514cfe39c6209685cd15038573e5e5c4b26e9060936ef46e7476a49b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="2ba8bb51fd1a5505bd7d9ed344b07b9b"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2e19393cc5ef67"
    $a1="72f5b80a1daaedde"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*1E1FA26957F28D2FFE3FF107995CCE408E2C298E"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a1="{MD5}4aaSRTjp+ZQ+Wge4cJV+yw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a1="{SHA}QXkVUd7Cne2Q8GGicLDbh5xOZjM="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="e1a6924538e9f9943e5a07b870957ecb"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="41791551dec29ded90f061a270b0db879c4e6633"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="573e6fa7047c0d4a785f52ffcb74555f3ebd75e1f6a43fa1740e0a6389f8c27baff8d02e7258c0b48e9ce7cdf244c8fc"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="9db270ad5ce302a3c95ab9cd3d0015e450fe0f46046841fec5e4a7b4"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="29671304a9445c3cc1212649a84d4115b6fe2de9fb894775cce13b6c920c10b3002a950b06f437421c58649ceef1bf322d6739651f2823effaa8f0915a251793"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a1="4113e4ce86a97836e2b4af4d0b495d7caac48f2cb58d7fc1a6365cb2b227d6ad"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="af15fe7572609ba221cad33675924792956b5ab7e93aed80e20e9a48753d5256fdae83d78022f522c6afdadc3fb909f585724d1359fa7bfe8583129400018a9f"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="dc7c9960c34505258a4f6d5e91419c963b9b3690ca3fa80d2d6c60bb65cbc803"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a1="41d68d532e92a4db7ca99aaa6b23b8d592e906fadf0eec58b4dad613"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="bcde1febb22a73b25669e5c511b719c43ee8a8554e77ed3fa4977d52d608cafa"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="67dde4cc941f6e1608ab506391530f5044acb9804a37ee39e5a80e88a382d549d0bc19d0374d0a008733a2f7f96ffadc"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="3eb644f122ac4bae03b7c49392dbfd68836bfd8e8aa9b35c90e18ed73ceb1f111c8a250eeba4eb4cdf1011591053ee0a5d97d2814ab40db1a45864c035674fb7"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_main_street_softworks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="TUNWRUFETUlO"
    $a1="cGFzc3dvcmQ="
condition:
    ($a0 and $a1)
}

