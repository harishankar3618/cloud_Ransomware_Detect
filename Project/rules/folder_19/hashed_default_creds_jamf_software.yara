/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_jamf_software
{
    meta:
        id = "6jCMMFbP37R7iSXcfs4Ke8"
        fingerprint = "528f13dbcf7c011417eb40cb70ac5f53d5dc0f24ae36a55f1b746760cf9cd9ec"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7be8c485b3eed3a0ed82c1a8bbb9725"
    $a1="a446a079e227e510f8cadac13eaee18a"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61351c195f90c1eb"
    $a1="1ae0ef236b6c282c"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B8B7B8C47EF8381F4C2BBD441DAF0E52AEE035DF"
    $a1="*2EC67DE471878D7E3BE41589ADBB6C713F9E0B47"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}8FTVbHIBGbd3e8jVfiYwtQ=="
    $a1="{MD5}vFQQ2iB+wOf5/lDQn3dQJg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}aRkLHhQ7OviyjXupREqVPvo7nOg="
    $a1="{SHA}4sD0bCxH1Ah3CJUzCaAtYJYKZ3c="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f054d56c720119b7777bc8d57e2630b5"
    $a1="bc5410da207ec0e7f9fe50d09f775026"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69190b1e143b3af8b28d7ba9444a953efa3b9ce8"
    $a1="e2c0f46c2c47d4087708953309a02d60960a6777"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f1f3f46cd24860be8274a1bc432301bbe3c4b710ef1f595500e8ae4c012d46611760233b7513e8afa75b8d7b58dab25"
    $a1="fe8233906c40a7f03d90c280915dc63c4b173c7f7acb1450b2c06086cb347aedcac428d8ae7aee4068443f72dfac0e36"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fbe85236a7ca7f172a5eeefa880087aa92bdb17cfc40d27d3155b935"
    $a1="76b5686201a3937541a78416639ba95ca8ba8a165f483b686bbea56a"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="263eb25c81a54f5b51a04e457ec11140f8623ec66fdb27fa6bb62c43c726f78811b5198e288466d730ccbced6cd608b9cbcd651e836bc606752dc8da41bffed1"
    $a1="5355c850cd7d3903d5bff20508757481d54c15e5828691ee8e8734f3df65634db08671495dbfd286564a5b072cd039383493ea1d1db3e32f0d8731e6dc284dc8"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09e52c17ac962b591ea8189c2a62dd4b7c6b457ed0f1e037e67839668b7868ab"
    $a1="67985c6d991a91da72c095585165d2d0731c24a73abc3650d3835b3d82bce817"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7d2e7147ab744f008ee2071e3e3f8ef17b505d9505bba3f0de7b762271de4ebd3ce553d1069ab1bd5f8ed80a53d98de2d08fbccfc4fb905e262523a5136e331"
    $a1="a63e3bfcafe40e9c85820bb2d686c7b0780c445170611930a2645ad5086eaf7aa2b918ccd4526019f05a235bad1862ce32c9a755d488d69e471de99d125b56df"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="174119b30e74373f9caff78e07e1ab8c5e3e792f6c3533703f6d3d901ca148e4"
    $a1="934aa7a5cb89646405a6f76ac8ebbd5efca783e93152d26f15721aaeded0aa48"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ced4261881d2b2b1f262cd29ce9567500b511809897cbe810c15f988"
    $a1="3aefc4810452f6284fd800ec6b1ff10c9d2df2ed8ab947a52d8d7a3e"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9cf7d7e93d287dedaf38c841e555c826c15e633e020d5b283a4f4a6d171ce534"
    $a1="8e067376dca90310c9a248bd1ed572d4fb5269703eb19ef290328d86c1d4c0bb"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44d48cd2d2d323d686ecb2937980dafab2f07f2e81e47c2f6fec30fd75f179242e31cdf2f00ff687679d2a8a69af8383"
    $a1="775d63c79167a78b66fe6f46b4c909b2c4175fc6ff62a43d802055ebcd347757c32ace9cd9edc8e06764b6b651be8de8"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7971dd2752caf9dead4a023ce9b9773225f958b1c36ba8ce0e13ea59fd0d32a008daf9bdc2ffc5ae57815f832afd2c2388f54adb3781ac1289fd0ed361efd2aa"
    $a1="572420a19fa2fd8467d2fc1f1f8b3b4bc7378597816867367b0dfaca7e92ee58e34a4e58bdf56a984d4f4bd8da5311783950bfc372ff30af001e955f0e31f2bb"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="amFtZnNvZnR3YXJl"
    $a1="amFtZnN3MDM="
condition:
    ($a0 and $a1)
}

