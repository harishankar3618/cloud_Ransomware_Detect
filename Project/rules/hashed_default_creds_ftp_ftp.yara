/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ftp_ftp
{
    meta:
        id = "2jiVEQC08FD2gOfvWZaMMR"
        fingerprint = "fe4033169d6082f4fd63c63292b9ebfe9c2dde8f4593946f0ccd0aeaa64faae2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9865c4bdcd9578a380297c5095e6c852"
    $a1="9865c4bdcd9578a380297c5095e6c852"
    $a2="823893adfad2cda6e1a414f3ebdf58f7"
    $a3="823893adfad2cda6e1a414f3ebdf58f7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c7bc0f525947398"
    $a1="7c7bc0f525947398"
    $a2="57510426775c5b0f"
    $a3="57510426775c5b0f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*89DED2CC215FEBF4D5077792E8CBF7B3A3CE6A53"
    $a1="*89DED2CC215FEBF4D5077792E8CBF7B3A3CE6A53"
    $a2="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a3="*11DB58B0DD02E290377535868405F11E4CBEFF58"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}/xBLLfq5/owGdlhykqY20w=="
    $a1="{MD5}/xBLLfq5/owGdlhykqY20w=="
    $a2="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a3="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}dha7h70F9kOeNnK6GyvlXVvraLM="
    $a1="{SHA}dha7h70F9kOeNnK6GyvlXVvraLM="
    $a2="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a3="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff104b2dfab9fe8c0676587292a636d3"
    $a1="ff104b2dfab9fe8c0676587292a636d3"
    $a2="084e0343a0486ff05530df6c705c8bb4"
    $a3="084e0343a0486ff05530df6c705c8bb4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7616bb87bd05f6439e3672ba1b2be55d5beb68b3"
    $a1="7616bb87bd05f6439e3672ba1b2be55d5beb68b3"
    $a2="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a3="35675e68f4b5af7b995d9205ad0fc43842f16450"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="adb545c1a26865a6849223515fab5965551871330b08a79bab66c0bdc8d33df11791c92dbea55591b55bf4e7e30926f8"
    $a1="adb545c1a26865a6849223515fab5965551871330b08a79bab66c0bdc8d33df11791c92dbea55591b55bf4e7e30926f8"
    $a2="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a3="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7895d9a045f4794241b69df3d77db44df5f05c4bc4b24e3b44a12c1c"
    $a1="7895d9a045f4794241b69df3d77db44df5f05c4bc4b24e3b44a12c1c"
    $a2="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a3="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="004faa89a51aec526b9e89bef712c72253f40a929e7f284f5a4c453facc98d6b90e33fa01f950cafa6932e0f18a28ada89548f7248bcc5b3932d227287e63185"
    $a1="004faa89a51aec526b9e89bef712c72253f40a929e7f284f5a4c453facc98d6b90e33fa01f950cafa6932e0f18a28ada89548f7248bcc5b3932d227287e63185"
    $a2="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a3="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f35e175b07fc080eb57fc9db22a3ce477d87bc5447466815f55864d3b6e6586"
    $a1="1f35e175b07fc080eb57fc9db22a3ce477d87bc5447466815f55864d3b6e6586"
    $a2="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a3="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="816c3133386798ff22a70f32ea8e0952869b99faed26aa6df3b180ff140402ec00cae38b14273d278b02343c9450e049be080f0fc72c9920c17c1c792e11acd3"
    $a1="816c3133386798ff22a70f32ea8e0952869b99faed26aa6df3b180ff140402ec00cae38b14273d278b02343c9450e049be080f0fc72c9920c17c1c792e11acd3"
    $a2="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a3="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="238041a05ef5fb96bbffd6c5de66310bbf24d41406a2305189936e935ed91505"
    $a1="238041a05ef5fb96bbffd6c5de66310bbf24d41406a2305189936e935ed91505"
    $a2="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a3="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bec6a07ce9c9b3e091598e7ba0387cffb0840666125019aba3570d28"
    $a1="bec6a07ce9c9b3e091598e7ba0387cffb0840666125019aba3570d28"
    $a2="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a3="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7d7743a4f3ccba2cdb10c43509f49a0b400086a4dd195441b48590ecd5136a3"
    $a1="f7d7743a4f3ccba2cdb10c43509f49a0b400086a4dd195441b48590ecd5136a3"
    $a2="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a3="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14452f57c382ec3a99a1dec4f1a8a47a9e5bf0f159383f4bb913cf6130260f405201598865b5c577fcfbe1f9fc4e2843"
    $a1="14452f57c382ec3a99a1dec4f1a8a47a9e5bf0f159383f4bb913cf6130260f405201598865b5c577fcfbe1f9fc4e2843"
    $a2="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a3="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8a0bdb3959e47ca7ddac9de50e22d980cfdbfda8717f40ee66ddb75835a64fe90a120e940c102e7d28ddf723d10da2cd11218121051756ce234b63671a455ad4"
    $a1="8a0bdb3959e47ca7ddac9de50e22d980cfdbfda8717f40ee66ddb75835a64fe90a120e940c102e7d28ddf723d10da2cd11218121051756ce234b63671a455ad4"
    $a2="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a3="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZnRw"
    $a1="ZnRw"
    $a2="Z3Vlc3Q="
    $a3="Z3Vlc3Q="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

