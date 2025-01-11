/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_kodak
{
    meta:
        id = "2X8kX6FSJJlFJNVfOOj41J"
        fingerprint = "96febb90aa4b9ac8bf94e2abcc6df7e2772026da6de374495f86168613069032"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24a00b67c3feb64064c348a370cc3b1f"
    $a1="f4c36945cce5c05a9d6b4531dff36dbf"
    $a2="24a00b67c3feb64064c348a370cc3b1f"
    $a3="8c2ea3a7b69ce9fa94f41881087667a4"
    $a4="24a00b67c3feb64064c348a370cc3b1f"
    $a5="516eb4ef252396110a96e7e7dfa5c5fb"
    $a6="7b592e4f8178b4c75788531b2e747687"
    $a7="d697885efa5d17b05c9449e0636dea11"
    $a8="8a68981fb3d9befdb6f440f137324546"
    $a9="8a68981fb3d9befdb6f440f137324546"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql323_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="487825005ab2cd2b"
    $a1="0057a2a446898b90"
    $a2="487825005ab2cd2b"
    $a3="4a8d04ce02c15ef7"
    $a4="487825005ab2cd2b"
    $a5="296a4a8f37d62144"
    $a6="4051fa79125fece7"
    $a7="0778475a4922ba0c"
    $a8="56d7a57b107d747e"
    $a9="56d7a57b107d747e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql41_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*04FA1C7BAE48871D1C541B0B7180DEC994478503"
    $a1="*EE9872CA8DB79E5FC4D539EC55FE38399FBCB524"
    $a2="*04FA1C7BAE48871D1C541B0B7180DEC994478503"
    $a3="*91323F01AC53E6A371EC6C603E07D953D8380147"
    $a4="*04FA1C7BAE48871D1C541B0B7180DEC994478503"
    $a5="*39D3BCB34AE5C2C0F33A47AA9CA8CEE64F9C5D38"
    $a6="*845A9ADD7E1A82B6459804066B3A45D0025897B6"
    $a7="*AF57748CB0F2DEEA7E473FE7CBCC2A135071A202"
    $a8="*DE597F01CC5D219FFE5896B9A8119B950125DC7C"
    $a9="*DE597F01CC5D219FFE5896B9A8119B950125DC7C"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_md5_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}c6z/bKqx00VPEbnUyKzcSQ=="
    $a1="{MD5}NGWs2ZbKs+bPBjce9JuGqA=="
    $a2="{MD5}c6z/bKqx00VPEbnUyKzcSQ=="
    $a3="{MD5}03Mk0UCz9NayQK82Bi9NXA=="
    $a4="{MD5}c6z/bKqx00VPEbnUyKzcSQ=="
    $a5="{MD5}QYVgtbrTUpuLpDjRt/2L3Q=="
    $a6="{MD5}MZ9NJuPFNrXdhxuyxS4xeA=="
    $a7="{MD5}Pda5Jl/xjzHcMN9ZMEsMpw=="
    $a8="{MD5}wrp+eFxJBQ9I2pqsxFwrhQ=="
    $a9="{MD5}wrp+eFxJBQ9I2pqsxFwrhQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_sha1_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}mG2rLK8RuX+78rQ+Ym2+qY51Ss4="
    $a1="{SHA}hcBrhnZ6L9+Rip4wf5Nqs2HNxAo="
    $a2="{SHA}mG2rLK8RuX+78rQ+Ym2+qY51Ss4="
    $a3="{SHA}XpWgW1U2qoIPKOrXpkW6/hMe4NE="
    $a4="{SHA}mG2rLK8RuX+78rQ+Ym2+qY51Ss4="
    $a5="{SHA}bldtS8FikNfxNnFDV0LxoLCYfeg="
    $a6="{SHA}ESu3kTBHkd3PaS4p/VzxSbNf6jc="
    $a7="{SHA}aIyh/y44AOyh6+PPqaA90sOtJ9I="
    $a8="{SHA}Mpy4trqMQnvnwJspgpXGVUFcesk="
    $a9="{SHA}Mpy4trqMQnvnwJspgpXGVUFcesk="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule md5_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73acff6caab1d3454f11b9d4c8acdc49"
    $a1="3465acd996cab3e6cf06371ef49b86a8"
    $a2="73acff6caab1d3454f11b9d4c8acdc49"
    $a3="d37324d140b3f4d6b240af36062f4d5c"
    $a4="73acff6caab1d3454f11b9d4c8acdc49"
    $a5="418560b5bad3529b8ba438d1b7fd8bdd"
    $a6="319f4d26e3c536b5dd871bb2c52e3178"
    $a7="3dd6b9265ff18f31dc30df59304b0ca7"
    $a8="c2ba7e785c49050f48da9aacc45c2b85"
    $a9="c2ba7e785c49050f48da9aacc45c2b85"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="986dab2caf11b97fbbf2b43e626dbea98e754ace"
    $a1="85c06b86767a2fdf918a9e307f936ab361cdc40a"
    $a2="986dab2caf11b97fbbf2b43e626dbea98e754ace"
    $a3="5e95a05b5536aa820f28ead7a645bafe131ee0d1"
    $a4="986dab2caf11b97fbbf2b43e626dbea98e754ace"
    $a5="6e576d4bc16290d7f13671435742f1a0b0987de8"
    $a6="112bb791304791ddcf692e29fd5cf149b35fea37"
    $a7="688ca1ff2e3800eca1ebe3cfa9a03dd2c3ad27d2"
    $a8="329cb8b6ba8c427be7c09b298295c655415c7ac9"
    $a9="329cb8b6ba8c427be7c09b298295c655415c7ac9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9010057c7aff690a8e7df72f2a8e88c73506d6e7082cb1a6cb5c382f771a78f33427a3cf3dbad6f240179492766dd8c9"
    $a1="dcdbb7cae4ba4c301f747cacc237d32de08cc72933e8392fd2f7e0dbe7e9dbace37994945d6877b367f26369d11f9f6b"
    $a2="9010057c7aff690a8e7df72f2a8e88c73506d6e7082cb1a6cb5c382f771a78f33427a3cf3dbad6f240179492766dd8c9"
    $a3="2efcd5ee58d1ea5cf9fe574675efa4d26d3da99a225ff16f29264604a7450b1370882d38e77170119aaa9e86a9285ca1"
    $a4="9010057c7aff690a8e7df72f2a8e88c73506d6e7082cb1a6cb5c382f771a78f33427a3cf3dbad6f240179492766dd8c9"
    $a5="08f5ddd2951273523ace0db98a5afaaa471b57f9f385f936793990532aa698b20e3d600e773d7e462925e9f915fe764b"
    $a6="d141b7e90779b15793cce4046f86faa9d32950d7e542761874460231eb94bcfec5d37b5f87581cba666973a1b22aa4aa"
    $a7="53c04f7aae30ba990c9400179ad890679f601ccfad0f3d54f422f7fbf6d5f861af85ee102f43f9e2c0b8cb7f6c0a181b"
    $a8="4db800350e79f01139d3565cdfd6534c58a1172a70213cc096b7b7d8e314694559f7dbcb410f65addd9b18b87916e81e"
    $a9="4db800350e79f01139d3565cdfd6534c58a1172a70213cc096b7b7d8e314694559f7dbcb410f65addd9b18b87916e81e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6e18245c22d972e525a5339ff9b162b9b2d1c7ff60885554ccbeb58"
    $a1="7ba66c615caeb48d158ab4bfdebdb92f9417692e7e4f75a7d0eb17df"
    $a2="c6e18245c22d972e525a5339ff9b162b9b2d1c7ff60885554ccbeb58"
    $a3="9b9f995bdc0d1115e2c520647a2870831fdbb20dde9eebff9cc5c942"
    $a4="c6e18245c22d972e525a5339ff9b162b9b2d1c7ff60885554ccbeb58"
    $a5="8d6f710723a22d47c4bf33367d9166cdde65a47835a6d60954763f1e"
    $a6="91f0572f12a77295e530583937e9d463c37c11760562e189cbb8188c"
    $a7="6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6"
    $a8="7a1aa63dd4f07ef81ed2dc00fd3660a61d353e937ad9261f18e86667"
    $a9="7a1aa63dd4f07ef81ed2dc00fd3660a61d353e937ad9261f18e86667"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d64327c3c5c1a339eb93cd061bbfb20c2dacc8a67b65d73b0da06320d1f6ccbfd110efda25361ae296eb27e23e0e32eb64da4f48e2fa3069ba02cd6bbc7e998"
    $a1="4807c8287291d9d4ac8bd9d673b7a0027a7d2b750b93a2129fc21058f2dec5e9ee8eb1accf0cd53a47694879bf066c49e6c714c015a8ba33d2eb1ebf84e172b3"
    $a2="6d64327c3c5c1a339eb93cd061bbfb20c2dacc8a67b65d73b0da06320d1f6ccbfd110efda25361ae296eb27e23e0e32eb64da4f48e2fa3069ba02cd6bbc7e998"
    $a3="39e7aa3caa773526e546250718ab7ab0b2aa3d0638b7ac7689e5a95232254def975c11eb606f295645f849c4e5d602362daac436af8e40831ddc1aaaf8c4f327"
    $a4="6d64327c3c5c1a339eb93cd061bbfb20c2dacc8a67b65d73b0da06320d1f6ccbfd110efda25361ae296eb27e23e0e32eb64da4f48e2fa3069ba02cd6bbc7e998"
    $a5="e7bb5af8bd4663db22eb55a150bb6040658df4cac017aa369479daeb1042fed754d0ee8ee36694179301853e56166178cff20f4d7941deb8cc76d5fa38f430ae"
    $a6="911b0a07a8cacfebc5f1f45596d67017136c950499fa5b4ff6faffa031f3cec7f197853d1660712c154e1f59c60f682e34ea9b5cbd2d8d5adb0c834f963f30de"
    $a7="99c389f40e8478f52c5180a30965d0cd9c5b7773361b50878876a8718a6a9471f4ad12cb258571ceaef23e7059537c15bcf0433ba218cd815422234afe3d81fd"
    $a8="9fbc985c6ed1181abbdceac999dcf86f3321b4ab6ccb3c5eb3de0d769d2263bd298dd0cfb15c73a74b802b1796b2a6450a9c23d438940f4a84e7b1abb88c0951"
    $a9="9fbc985c6ed1181abbdceac999dcf86f3321b4ab6ccb3c5eb3de0d769d2263bd298dd0cfb15c73a74b802b1796b2a6450a9c23d438940f4a84e7b1abb88c0951"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6a6cb14af365591a498c456589b151e4d1b174ee90da0cd94b96a7ad7dd9b8c"
    $a1="598e519219f23461b638164fede36f184a05c88d1ef2a40678d79540a4604cf2"
    $a2="c6a6cb14af365591a498c456589b151e4d1b174ee90da0cd94b96a7ad7dd9b8c"
    $a3="dc9cac60f7626286cbb9bfdfbe3c4aaca67f40e63f384a41f6f02133c7e39e45"
    $a4="c6a6cb14af365591a498c456589b151e4d1b174ee90da0cd94b96a7ad7dd9b8c"
    $a5="04b7621748c79505370721bd391337188a01d04cc0212759f250eea466a59816"
    $a6="0be64ae89ddd24e225434de95d501711339baeee18f009ba9b4369af27d30d60"
    $a7="360bf3a8254ab93fc69e84ce6640d78535a34f3cdc0b1bdacec6ccdd93726a79"
    $a8="d677190e0a9990e7d5fa9e4c1bbde44271fb8959c4acb6d43e02ed991128b4bf"
    $a9="d677190e0a9990e7d5fa9e4c1bbde44271fb8959c4acb6d43e02ed991128b4bf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b23d988d4f9b76e98c7bcc821842946c9d2555586e715509e11826cde9ef3d506e1632420bc4de06c18fc53ea0d17920e0c1b4408e2891c2af518abd2d6f324"
    $a1="f1ff122d8d8d5655ec08af4ff601641a1c8fb703b5b370f6faf267d39412fa3452699eaccd26cab323812b5a0350b2b0ece3aed847385f7e7ae3febdba001ffb"
    $a2="7b23d988d4f9b76e98c7bcc821842946c9d2555586e715509e11826cde9ef3d506e1632420bc4de06c18fc53ea0d17920e0c1b4408e2891c2af518abd2d6f324"
    $a3="50032f97949698ca45e3fb1ed6b4a03b84a43eb5c1a2e1ae9d9432690740652db4f15d2a6f6787cced92bfa93d22a9a9b30c660f36a2246042c3b41185bf99ee"
    $a4="7b23d988d4f9b76e98c7bcc821842946c9d2555586e715509e11826cde9ef3d506e1632420bc4de06c18fc53ea0d17920e0c1b4408e2891c2af518abd2d6f324"
    $a5="01cc4e6c694668a0e8b645dd5b3fcdd9f2f768bd7f1634219698c040a8671371343e91baf7b0e081289d9392a099ddd6470c80714e140ac4932405cb611e8ba4"
    $a6="38b87a7cb8dbaed67f4a22bf16a2098fff56dbe813363739a8310ae55ee506c01e27cf78a48f8c34c36d428c5ae4363f577baf6b2a7ebcf736b4506c082e1158"
    $a7="9ef332732b6811d22395262813a1666b4c183a24138b22d2b0c7eb97ec23c745439b8242aca59df64c270c0bd561ac9d1b2b85a0c915ada4dde4afef7eadacb8"
    $a8="953356f07bcfd347bcd4df72861aa54771c87947526ab5ea7b1c5f9676e436e0c46984591883647cd9fc2dbf68388935bafd5c34d54e52e69a854da431cdd952"
    $a9="953356f07bcfd347bcd4df72861aa54771c87947526ab5ea7b1c5f9676e436e0c46984591883647cd9fc2dbf68388935bafd5c34d54e52e69a854da431cdd952"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f24da37059976cf07646827165fb93c9ed56aed19bdded1d0805756a279d722"
    $a1="b9aa61b65cbd2fd9e69bd7561082d6848cefc41937da481dc38cb525d8a22a6d"
    $a2="1f24da37059976cf07646827165fb93c9ed56aed19bdded1d0805756a279d722"
    $a3="ae7e5e149aad2e9a2be604f920e8520f924a29632b43d734a6e81c773605a0d8"
    $a4="1f24da37059976cf07646827165fb93c9ed56aed19bdded1d0805756a279d722"
    $a5="e17fa0e023d886895f44ccc9c2f6642cddd5f6f8b1dc8da8a78ba4ffc733d15b"
    $a6="d92248532a1bda4f87c76748e5dd87350b1613cbbedd7970c54dbb98e2aeabc3"
    $a7="a071a59b54ffb10629f3ab2165574be5683603a04701ad5d0210499a93d7fdb2"
    $a8="897ff9bf3f0989c89e46835e7685a4a0ffcb6c483e9a1797e11c28d705d74987"
    $a9="897ff9bf3f0989c89e46835e7685a4a0ffcb6c483e9a1797e11c28d705d74987"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48879ba9304d8855cbbe8c5ce111e0f504112803bb35a78c870d162e"
    $a1="394f968ef0d4e367a2a1159f395add1f2d6a71a3b257787e0991c2d6"
    $a2="48879ba9304d8855cbbe8c5ce111e0f504112803bb35a78c870d162e"
    $a3="aa7e91ddd91706f6a638e843a9da0a33142ae064e7c77e7bb7221a11"
    $a4="48879ba9304d8855cbbe8c5ce111e0f504112803bb35a78c870d162e"
    $a5="35515d8ea1e270b7743a966efa155c424b1d0a97a0cae07305d9aeab"
    $a6="d8eaa941480d41fe4fe825d721876ff441c801d99e532293b58500c3"
    $a7="aa5f36002e489d9e5afb85761f57c6d6948f48f6ee81b1811e11f28b"
    $a8="c45e6d4a6530ff3706cbb89d6decf95215bfd7387ef5d1bc0705b379"
    $a9="c45e6d4a6530ff3706cbb89d6decf95215bfd7387ef5d1bc0705b379"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8e0c5cdd254e2ec0fa82a184a704747a84b961ba2c8e65c8ecc9b73dce054f20"
    $a1="ee2db87d7e41822d79cf016a0d92f4cbf15b5fb194b4e0f3e33410d67017ca50"
    $a2="8e0c5cdd254e2ec0fa82a184a704747a84b961ba2c8e65c8ecc9b73dce054f20"
    $a3="7da749a8870dd4a3d62904108edbe42f9c96ff293911dc6c38afc7b1f4f8c836"
    $a4="8e0c5cdd254e2ec0fa82a184a704747a84b961ba2c8e65c8ecc9b73dce054f20"
    $a5="4f24fd3ceb02c63c6fdff3b7fff921bd17240479fb0aec632c63d123eeaf8d55"
    $a6="edad46f180bc906586f1a2635f97c126a68e198a5c990c3bb62d5c5208ac91a1"
    $a7="0cbde9a2c19b092dbaf72e1f40c534ca2e82e3a6c76e89991d78b03541a0e15c"
    $a8="91bc7765fde5a1b73d63c9bc9d9ccdec515c2f149d297990526996d48e2393ca"
    $a9="91bc7765fde5a1b73d63c9bc9d9ccdec515c2f149d297990526996d48e2393ca"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d753a10ef05f90e417efd13a1e773ef9498277672a6ac9b911be3d502fa8fc374675a2b449711bb66547f043d7639a50"
    $a1="0ec4286ba88500d77744e4622cd9bc5d254be13f5be5a9e85d73f07c5e83f0c07e07e4915fff78741f91f41c5308708a"
    $a2="d753a10ef05f90e417efd13a1e773ef9498277672a6ac9b911be3d502fa8fc374675a2b449711bb66547f043d7639a50"
    $a3="d48dc32833c86685c6bd1f4d1332366829151722514d6968d284179ca6b6600295a0ee7659d60e75abd1139fc9fab141"
    $a4="d753a10ef05f90e417efd13a1e773ef9498277672a6ac9b911be3d502fa8fc374675a2b449711bb66547f043d7639a50"
    $a5="c54a3f4d047897ad45fb6933bc57672f8c74ca89f35e0a050d64c1409326737cbaeb3deacc5e0f96181adcf66c1697d2"
    $a6="958b70eb14540c59cf49434cf58702d7e186ffbd7ccb1b41651edd53673dc6f9adf295322ce18177ea2ce75dc9c324a1"
    $a7="885ce4423c696e3936895d764fc64f95908d2d320e36dcf36a6c282d7c878d2c17384e31cdd34b4ba230bcaebc938bcf"
    $a8="46fcc10389c81d0e23a943298f68b0590df5d3a9f7bef73261fbf08f3fe76eda697a7f83c645464491549ca852b193cd"
    $a9="46fcc10389c81d0e23a943298f68b0590df5d3a9f7bef73261fbf08f3fe76eda697a7f83c645464491549ca852b193cd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe1b65262021ac83a744628d789754b19980d9735033f6a93c4900a1b8752b97b73a654a78c51486edb6684abe70431e18d48e96efa81b83c9645fbb7e484b2f"
    $a1="0fc5e04fa0532ef97fc03dab2928a6ecce56d9ed8b022adc8d1a3824907e0ebd9220445bfe0598bf03a53934331b43b6d620424c8d24c747293c92e6cf215832"
    $a2="fe1b65262021ac83a744628d789754b19980d9735033f6a93c4900a1b8752b97b73a654a78c51486edb6684abe70431e18d48e96efa81b83c9645fbb7e484b2f"
    $a3="289260912ae594f3c86f7b268576f5161ed747b8d9693e53d6397f7a1a5c66b7976812b9938ec5e248ba37a7008fa63eb50f24db27d5958cc2538194b4f8b78c"
    $a4="fe1b65262021ac83a744628d789754b19980d9735033f6a93c4900a1b8752b97b73a654a78c51486edb6684abe70431e18d48e96efa81b83c9645fbb7e484b2f"
    $a5="f415ac98c933780b31622dd2d05fc9f83df1f585f0db108559eccc8a8659b7df653cf70f5a2fb86b44bc7f88cc566f9a669aed1a07d063de75963cdff23b567b"
    $a6="6cc43bc019055903f09e4183bdefc203b4581384bdd60c80def38cde01a23c80eebd2cd07f09da3c0d72afef293a1a9057a993993f7fc4ed3498ef8032899234"
    $a7="94306468b6d78f5a35b5444e846038770f57e37f711996fbd7afd000e963a6107639b1a839c1c895fce1a67386c0c6923bd7f3db35a9783289158dd2d00a8966"
    $a8="f1343b3626745557e40e3014d28a07766a31c925778a9509b048d518429b72973d8be7ff9ab3e78597885f321c5f4786e2a61b51436d868479e40cd7daa91242"
    $a9="f1343b3626745557e40e3014d28a07766a31c925778a9509b048d518429b72973d8be7ff9ab3e78597885f321c5f4786e2a61b51436d868479e40cd7daa91242"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="UEFDU0xpbmtJUA=="
    $a1="TmV0U2VydmVy"
    $a2="UExNSU1TZXJ2aWNl"
    $a3="TmV0U2VydmVy"
    $a4="Uk5JU2VydmljZU1hbmFnZXI="
    $a5="TmV0U2VydmVy"
    $a6="U0E="
    $a7="UEFTU1dPUkQ="
    $a8="U2VydmljZQ=="
    $a9="U2VydmljZQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

