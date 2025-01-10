/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_trintech
{
    meta:
        id = "6mHSh5jIH1QW9JRXUCA21K"
        fingerprint = "6c4f486392a1ae886928400fce800e70d97611f9d0c39a0f2754ce5865381517"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74c17aa7b8d9a0dd7fc356ef356b7941"
    $a1="306e57aa04129e317c2cec787277a6f4"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ee8d69f6290f102"
    $a1="6ea3c396763fdf54"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2F874F8AAF1A18F36EACD61BB227B8ACCE3F565F"
    $a1="*785BB6358EB1BD42544B427E927D87159F8F2E6B"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ztFt7smvTl/iJXt4DhYKPA=="
    $a1="{MD5}FulfWaLPjnE6I2zkn5W9yA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}sVoP4Pj8wC1jGWCKDGUdkNF7Rr4="
    $a1="{SHA}gr3wOHtK0m/WVOr+YpFrMapUWsQ="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ced16deec9af4e5fe2257b780e160a3c"
    $a1="16e95f59a2cf8e713a236ce49f95bdc8"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b15a0fe0f8fcc02d6319608a0c651d90d17b46be"
    $a1="82bdf0387b4ad26fd654eafe62916b31aa545ac4"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62fb33c82319c9b810ec04e6f857100d715960c743fb880838e86ea7d8f2dc41198278140f45e98e3e55ada662d31e2b"
    $a1="a48da4451de79b6cc9c0e48395e9d8625183a011e4248f1379f43205a5ae9a0629757fb1fb3cf4f47952f462ee870efe"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="170894208f021feffb91aca490600acaea3a932b9870a32df2793a87"
    $a1="9dceedb0317d45e49acdd4d91644523b27c48538e4a96bad38efdcde"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="300ba997a1b5fac7d1591d381ac7291541e775802099043be00d9573e4955023733cbe4573782c8a2f6126415d585f6e4592710b4b8a920bf9cc16c50bd3706f"
    $a1="3c4389b521fed93a9434a46aff9d5add9f78acece5c2c3ff0e9ad5b78884d462a93eea8df86a4695697883be016d2219ad1893ce01c6d40009b27ad8196598e7"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="486032732772c324ef3251cefe67fdcce6088e77f147a7595a5fd04e2edb39f7"
    $a1="4782469c4e7ae366076c322f3b75578bbaa3458503e2ba02d1211683a93b761e"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de4a5bc70779aefbfb8deddebde56b4868b9d438a9b856534cea96f123f8705eab29162659245d39df7cf93f5b49e124d4cde3494b4947008ab97b4179b82769"
    $a1="c2706534a4e08c444c758b85a91babd1fbc5f26829de718c2b0c336905567e15c8eea00577fa27c3e46c9bed1dc44ff7818c2c2354f3557c777cd8d9dc2223d9"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7604c9180b01da8cc678f0f6a875a699e4778bcaedfc29f1045832b11c554fb1"
    $a1="fe98bf2261492e84a6be0c2d905330f94dd265a7b5df333ec7380fe4d97d6941"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fed41821df5df4c89424276f8fbce6402bdbcd0bc8d9baae031fddd7"
    $a1="c79c0db7e25384ebadae5270c4045cc4060b35c5d49b33e7788b156f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54dd7d295ea01bf21b7a2b38cd8d21da36402a52209784922bcc4f52c540ca79"
    $a1="d325d41ae8a7fd3c30f998af5d10e4042345a36696f4abb09ab707e9e4eb9045"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="196cd38b3751770b63e1611bcf669cd373637840035fe7542ba148d00d1bd088f07f2b6ceddb1001d91baddd6f8e8bd3"
    $a1="7719fe51b1829509bd3ee190bd1580d4d28d39646e9468440ce339604fe2c04f3f35ccc203076f89c62bb43f6e971636"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b956247fe139c97ca596ff757166efedf599a6cca9e0aee1ded270926301652bf277f74ff8eb3941cd0958947f86b2e94b5205bc1c104fb10ed9ee763028d36d"
    $a1="13b03cd2ef924d74d9634aef0a55fed48e6c2a51919b0492bd0bbad877c90ed0c0f06cc86a913b49e99e0bc3dfc47e65063a96cd9b09232fc9f19be4a6d55a22"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dDNhZG1pbg=="
    $a1="VHJpbnRlY2g="
condition:
    ($a0 and $a1)
}

