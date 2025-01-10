/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_lasa_aims_mssql
{
    meta:
        id = "4BfOqrN3yCLPj1djQGhWLb"
        fingerprint = "a7edb13daef8a1c28b0fd25038d7ba84e3175164c0e13b9c1043c4c50a6e140d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="82c27c0d313e3675b244272e1de39e68"
    $a1="11a01c4a0f2f228796c93fa0ca1a634d"
    $a2="82c27c0d313e3675b244272e1de39e68"
    $a3="68c4c94736a69417e75df41cb7e4a2e5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3434abbc5748a7c3"
    $a1="45b07dcb6b0e20fb"
    $a2="3434abbc5748a7c3"
    $a3="07756a0949325dd7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8A7C22DABE57CA223754F7CBCEA247C084E2D5A3"
    $a1="*0B0A27832C339662F96E0238AD92FCBCB992A7EA"
    $a2="*8A7C22DABE57CA223754F7CBCEA247C084E2D5A3"
    $a3="*45D8BF1922E6E3FAAF50412D79DE9153B0547141"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}tAI5BYtBJW6+RYDeaiaQHQ=="
    $a1="{MD5}c6zZpZchMLdQZsgllaH64w=="
    $a2="{MD5}tAI5BYtBJW6+RYDeaiaQHQ=="
    $a3="{MD5}MHgfH8L5NCzrGtL281pR2w=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0v6aFCDCZA7q2DHBDgttiQ7przM="
    $a1="{SHA}tSHKpuHbguWgHJJKQZhwy3K4FjU="
    $a2="{SHA}0v6aFCDCZA7q2DHBDgttiQ7przM="
    $a3="{SHA}QlQ6ScTkFqD7fFp2JtDSJnWcOiI="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b40239058b41256ebe4580de6a26901d"
    $a1="73acd9a5972130b75066c82595a1fae3"
    $a2="b40239058b41256ebe4580de6a26901d"
    $a3="30781f1fc2f9342ceb1ad2f6f35a51db"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d2fe9a1420c2640eead831c10e0b6d890ee9af33"
    $a1="b521caa6e1db82e5a01c924a419870cb72b81635"
    $a2="d2fe9a1420c2640eead831c10e0b6d890ee9af33"
    $a3="42543a49c4e416a0fb7c5a7626d0d226759c3a22"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afdc9c117556279082cb7d7c933ca5e651a1dbd9b78405ef3d90329997050a4a6396f980b55b84a9e77a4a6572c63b00"
    $a1="63fc52ff0cf52087b8b5fc53850973d288f6982570d4b469c8dac1e963a93772d928ae1350913b121946085f0a63b853"
    $a2="afdc9c117556279082cb7d7c933ca5e651a1dbd9b78405ef3d90329997050a4a6396f980b55b84a9e77a4a6572c63b00"
    $a3="dce4f511aaee332d23fdec1d839f2597e533203f550c63c0559c9017181d6b9f92f6244ce99f5d5adc7ee5be64edd58f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04797b6853310ab91c3de92127616fd4fa975f611a5ee2a6a09f3736"
    $a1="c417c5952fa1d63472b612f11e45809ea820ab918be37121fc257e6c"
    $a2="04797b6853310ab91c3de92127616fd4fa975f611a5ee2a6a09f3736"
    $a3="c4fb75c197e41d86d69bb807cd1b3725b5c80f6be6d8304efb1dd50a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c5bc412b9af5b52063ed1bbd577f1faa55d95d3706500d45d219340709e4e50dfec14b2e4dca3970d08934498ce0d82d2b652ca4a5fa7d2e51442d6519d93c6"
    $a1="238b90e6e2382ddafadc35266b2fa9a371fb3962b675ccab1b5538321f469070d0f3762f29b21ac7ad772eb6bd299d09f8e75d38ed8b7067965d5d5f26ebc3f5"
    $a2="4c5bc412b9af5b52063ed1bbd577f1faa55d95d3706500d45d219340709e4e50dfec14b2e4dca3970d08934498ce0d82d2b652ca4a5fa7d2e51442d6519d93c6"
    $a3="b6d398e188218d67f3d4939f9e1f6dba57f7e01063c50f585c53ab0bd4f804f1651bf41d32749c2d2dd2b2581b86a0effe5ba7d12fc364a5990908624be5d129"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c7611bc6a334a5ca549c010c57b8340d08bcf14e1af7a28faddcc06ab6536e5"
    $a1="835d6dc88b708bc646d6db82c853ef4182fabbd4a8de59c213f2b5ab3ae7d9be"
    $a2="3c7611bc6a334a5ca549c010c57b8340d08bcf14e1af7a28faddcc06ab6536e5"
    $a3="67719f714cfff1bef08a87c4611ffacfb4cd965e0f049d831ae4389b24f83249"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="276d88d0ec2a613b3b2dc0d6a0e111e09f7b2f7954c9b0b675779da3f2ec536d895f50845bf054d34741caa34522028927d9c5b85014720175c488089b0651d6"
    $a1="c389a08ca48765ed7f0303e1823e4c20adf79b08368733b97fcb20b7c23d41e7487f826b4ee7c9c66b8e9d5ea50021271add19e347bfbfe0d5c6a053cf848589"
    $a2="276d88d0ec2a613b3b2dc0d6a0e111e09f7b2f7954c9b0b675779da3f2ec536d895f50845bf054d34741caa34522028927d9c5b85014720175c488089b0651d6"
    $a3="5de737932b1842eb2c7132ac46dc2412a6a3b28b684b4f18cf00d37518739fff9418b7c337db0edb2b909e8a4fb5003e4dfa1673b6af4d14f7ed0ec3257b931d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6dd76f938dabc37748c5934da402d450a3344e7ad93f3fe02dc98af57750c15"
    $a1="6204076fc988d9c8ba327799ea12528be066aad0192027adfcd3b505067edd3e"
    $a2="e6dd76f938dabc37748c5934da402d450a3344e7ad93f3fe02dc98af57750c15"
    $a3="10181969db5f4cef12345d13bff7fe535e47cc11e54b634be963e760f36aa021"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e61fdcc8efbb8136d3dc046b6e2fe9e1f53418f664b6299d658d6f39"
    $a1="cfbb56a314e406232e84144aa3b459691cc889b7b7d7406dcf2aeec1"
    $a2="e61fdcc8efbb8136d3dc046b6e2fe9e1f53418f664b6299d658d6f39"
    $a3="dcd3a40649223daecfa713aeb59a40a4cf65236565af0c564a5d0efd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afffd853f9c95caa3bd6db4c74bad7395ee52e5592f13fedab9c5b3ff59cef82"
    $a1="aeae63318b23cc3826a1b396f8ce6c5b83c89629acc8e5ed6ff944eb21d047ed"
    $a2="afffd853f9c95caa3bd6db4c74bad7395ee52e5592f13fedab9c5b3ff59cef82"
    $a3="38d0cf8a108289625fff55195a6bc3e822c6c7ef42a798e793de5a21de558fd6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b840b1ba3c825da0c4223a4b0dc7bde0494a10d61224cc039630d3b5277daa52a8e57e895312da3db1fc1d7804fb97ac"
    $a1="0ca063dc16aa3e8234bbd5644bd93ceb65324c6cf85b00f711c63505ce5e05adc49c233115a1e153e8ad0947052037ca"
    $a2="b840b1ba3c825da0c4223a4b0dc7bde0494a10d61224cc039630d3b5277daa52a8e57e895312da3db1fc1d7804fb97ac"
    $a3="12e4c0dacec605771b0709aa18a1766858f553bdbe2055050c3005333d117b5affa19debff5b4bd7153f0bb78a459ad9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="42b63c14492e96ea56e4ddff3c8789b6c9fb1c6020370a20806b639a7a4aab1be4deca84f71398ab7534d404120d768163e5e71913dc7ca7e12e55081fcbcb93"
    $a1="b12c327f742aac769cc3a8ebcb2dff2cb6bbf4ef7f8edd42ab65dbebb1cff8e72da7eef015355396474167708e54248fc8989a86b2da61c84f8fc5d500d2bd11"
    $a2="42b63c14492e96ea56e4ddff3c8789b6c9fb1c6020370a20806b639a7a4aab1be4deca84f71398ab7534d404120d768163e5e71913dc7ca7e12e55081fcbcb93"
    $a3="857ab6b10cd5dd98fb7aa7487a835517cddd0355951eb5357bdeef1dee81097f5bfb6bbb9063565c7952111f01f3a114ed564f249d4902a9130ebabc710c6731"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QURNSU4="
    $a1="QUlNUw=="
    $a2="RkI="
    $a3="QUlNUw=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

