/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_kodi
{
    meta:
        id = "3Zh7v4YncQeuopjqnUlV41"
        fingerprint = "98a86d0e6a9220e72d77c4b1d742538556fc452a68255d025af04d467e98f22d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86a57579725615cd87b45fe96394da9d"
    $a1="86a57579725615cd87b45fe96394da9d"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e8057dd53a77553"
    $a1="7e8057dd53a77553"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2249595D6A53B38A77AA4AB2091D9B1A71F88735"
    $a1="*2249595D6A53B38A77AA4AB2091D9B1A71F88735"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}xybwojDHqCXHAyDh59wbKQ=="
    $a1="{MD5}xybwojDHqCXHAyDh59wbKQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}isU5p5FVoAMoNCZKw/bb048cgS0="
    $a1="{SHA}isU5p5FVoAMoNCZKw/bb048cgS0="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c726f0a230c7a825c70320e1e7dc1b29"
    $a1="c726f0a230c7a825c70320e1e7dc1b29"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ac539a79155a0032834264ac3f6dbd38f1c812d"
    $a1="8ac539a79155a0032834264ac3f6dbd38f1c812d"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7ba5ce9b53888c18adcc0ddced9317bc555f1ecb4375e2d134d8ab5e8d12f7aff9c9e822e14c8575d74a68955e0ea23"
    $a1="e7ba5ce9b53888c18adcc0ddced9317bc555f1ecb4375e2d134d8ab5e8d12f7aff9c9e822e14c8575d74a68955e0ea23"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="364414f23829c16fc363869401d1f2e6dbedf732600cd5c4844fb614"
    $a1="364414f23829c16fc363869401d1f2e6dbedf732600cd5c4844fb614"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c946ba736c9d7cc4ba42ce723bfa3f53116b2b18065bf3a7f7feeb371e213916aef6072619f3882538c9b2c912c565aed42a11183ead6528ddb575e1f6e85ea5"
    $a1="c946ba736c9d7cc4ba42ce723bfa3f53116b2b18065bf3a7f7feeb371e213916aef6072619f3882538c9b2c912c565aed42a11183ead6528ddb575e1f6e85ea5"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="972e92b2ee3757ece2112bc17f21879ec2df77e7996338d07372beed0280f0ec"
    $a1="972e92b2ee3757ece2112bc17f21879ec2df77e7996338d07372beed0280f0ec"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c9806b38fabda70251c32fc04c4ddbb1c535a08480a24ff85be39784986e62eebc05472590452e6188ef42a355905064828d03a96a28e2fd1856a2f5eab8ca85"
    $a1="c9806b38fabda70251c32fc04c4ddbb1c535a08480a24ff85be39784986e62eebc05472590452e6188ef42a355905064828d03a96a28e2fd1856a2f5eab8ca85"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c97c5737fb17579fe5b7edf1189b7f0f00c3d945d8e782f66a35b51c1aa214f2"
    $a1="c97c5737fb17579fe5b7edf1189b7f0f00c3d945d8e782f66a35b51c1aa214f2"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="52fda87612ac679192389d29312835a10608f21cf096a726cf31a8d3"
    $a1="52fda87612ac679192389d29312835a10608f21cf096a726cf31a8d3"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d593ca80668ff9941bbdce23a382f4482f7a0616dc70f2bc76fda528bbbc69b0"
    $a1="d593ca80668ff9941bbdce23a382f4482f7a0616dc70f2bc76fda528bbbc69b0"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6dbdc356c10d30113880cde6614f1dc87ffe658f96cd1c9cdb06ca57f928fd11b72b00bb8712e7b5a9269ad37cbf02dd"
    $a1="6dbdc356c10d30113880cde6614f1dc87ffe658f96cd1c9cdb06ca57f928fd11b72b00bb8712e7b5a9269ad37cbf02dd"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8377fee0fe489ba99075f2691d5d59f84ab22471f5cce8345888bb1f56faefb230c8f25abbe880007f249925d3ee5e471dd5e559747ceac4aabd9cef62a3f493"
    $a1="8377fee0fe489ba99075f2691d5d59f84ab22471f5cce8345888bb1f56faefb230c8f25abbe880007f249925d3ee5e471dd5e559747ceac4aabd9cef62a3f493"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a29kaQ=="
    $a1="a29kaQ=="
condition:
    ($a0 and $a1)
}

