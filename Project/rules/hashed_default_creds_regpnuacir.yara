/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_regpnuacir
{
    meta:
        id = "1q8MhFZv5276foT2hh8nAX"
        fingerprint = "af3d0668d80f681704e0f5fbbb6cb1c01f31402a746cd61b766c75e82f0d1a2a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12318aa9e8464e83d0d99ef189f37ae9"
    $a1="f0470cb823905f34632d64ea9f78f662"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2945c362797affed"
    $a1="1da1a5f82de33500"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*348B2E74CDAC5EEF8E3548D4AE4A967DB79A00F4"
    $a1="*1C58CD0E5E4FEE7B944D9DAFB6F9D44F19546571"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}1U0XAq0PgyYiS4F8eWdjyQ=="
    $a1="{MD5}bZXLw/iwwHet7LwxMjW4NQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}uYZBXJMkFRPTPQH89TKmxHrE8+4="
    $a1="{SHA}aMqpQmcrHoUSTaKpBGwkXNYTCcM="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d54d1702ad0f8326224b817c796763c9"
    $a1="6d95cbc3f8b0c077adecbc313235b835"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b986415c93241513d33d01fcf532a6c47ac4f3ee"
    $a1="68caa942672b1e85124da2a9046c245cd61309c3"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fdb9c3a439c356436b33762492e8d9a7c2aab1c31f135f1345f71353912b8d7c93321e2dad31941e379ada0fce7d01f"
    $a1="db286047f4506f3b7c2e110b8c0425ece106d769fc0416fc307f2308563a6b510de342840bd0ed18b5a4ce978d8e5bb8"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="16a72b36ce4d3ab7d58f2e11d445bd81725e2960af2160b40d010eab"
    $a1="773b7e92797eb2f7176cc82ae23d252d971739eb2f029e33abe767e7"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e53125d5130816a5e6ab3f160ed93d1f498edc3fdacf89ec901c749a09a2d01e1713a3c454f221af5a8069a9fc4829e648a8fe51cd43e35ab4e6c11e8f4bd54"
    $a1="ac73f333529ff75720ee24f8963653d237a1b34ec2956a1143fed5ca5d4a53ea2c7b40594f2c258a0f34db0d49452d49cf43581e431da691df4abd63aa2e5144"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f9f10b304cfe9b2b11fcb1387f694e18f08ea358c7e9f567434d3ad6cbd7fc4"
    $a1="485600b958a10477f44c1839f8bd7ce4934a4409be451d258f7cd433e19afb6d"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40d092076d9173a0d632b4ba20427d832009da5a8edcf65e080f4b790f2466ddd558d2b5a700bbbeec052de30c551bb40bf289c6697d89a091da477df7583ccc"
    $a1="8b5d353b7f1f8f96d3ada7a56b92b25d7d98c9e807a802ec537e1f144d3a144fdf088caf039a21d2eca78edcf68b662b1d8d9aef80fec918e458151753dce9d5"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de613f8c4e16e20707b811049659a3bfb6de9a154885c4e63bc4cbdebc387bda"
    $a1="cf5d9105309f036fd3449ef4fe73905e6833a5f5ed6e84517da6b211404a12c7"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d85a99dc2399dfd78468a881e5813701010e7d89c8b6075893bae08a"
    $a1="7da6a646362d266261858a7d7f61e3e59d6bb630dc117d291737dbf1"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a80f3ff71527ab559be9f18eb4205aeb85ea7896f55534a960e50a018e75322"
    $a1="ad4dda808bc8ebeb2aafe9815bdcc1f176c9a80e2f5d92fc16e444ce8da270d0"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="833f2b67dc4ca68257c7613202b75cf45439036d2b88f4a7a02ca9430418f3fc8f2fe4e371aa83cda2812ceb51fc9e48"
    $a1="f5df22fa097933f4c11acdefaf7eefa936c9dd136cae8cdd4b3fcb1ab85a1657bc106e7460812bcd996c65c57d96594c"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8059160be47a1cf875f097587f340c5c3a91821d78bd2fcce01583313e37806f48f7f47e428a43d0dafdaff454b7d208439a28dae530bcba9c3d9004d61948f6"
    $a1="08271866e8bf85bb557857824e1a7c837aa3aaa85271337679b629e821ab8139b1d451a8ca904c06dde295741a309634c8a90b456bb1687e2c8c20eb79f2c567"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ODgwMTc1NDQ1"
    $a1="MTEyMjMzNDQ="
condition:
    ($a0 and $a1)
}

