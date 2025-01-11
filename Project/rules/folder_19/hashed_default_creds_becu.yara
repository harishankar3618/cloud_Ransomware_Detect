/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_becu
{
    meta:
        id = "5UE1Ra0qlyBY4zXAjgYF7M"
        fingerprint = "d8ec997c6083eba2b58e02fcbd69840078b69ac64e66e835cfe0355a9cf7ef54"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="039d59247b08efb9689cf182c13dcb7a"
    $a1="d07fa4a6c97383641ae3880fa7de9656"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ed445c31056dd44"
    $a1="13d08c31116879c1"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6A8E030805B0F85CB6C5CC5E257D94E772DFDAA2"
    $a1="*5926117488D8A48AC157A5C8789E317F241E036C"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}OZhIfbAbO1uYpj855ByBYg=="
    $a1="{MD5}alNWBgndy5E9j9wfCU9qyg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}eqtLrw5lEHlmjHweyShGL+IcEWw="
    $a1="{SHA}JoYbWZ1jII0p22YW8dZt+K/cR4U="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3998487db01b3b5b98a63f39e41c8162"
    $a1="6a53560609ddcb913d8fdc1f094f6aca"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7aab4baf0e651079668c7c1ec928462fe21c116c"
    $a1="26861b599d63208d29db6616f1d66df8afdc4785"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fcd8daffe3dcd237ce2635d95d85e88acf35b2ab3ce629f6ef065645006ff34365f0f1f34ede6814f08958cbdca16ca9"
    $a1="c8f4e06ab3c3cf212c77ff2a380eeb0d0d24a89bd4f9388640ca0cf95291e9411c48fada50de313c0558e68120ffb3c3"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05f4a1daf9a07ebaac0967a6d191537ca0d414a3d863ce3734a792bb"
    $a1="18250460059f5cf002f219bdf70d720b8d7eaa2f250a8aaa56dadea9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="52e5c5bc0f9511d4bdb9d6626c913bd1fdf13a8e5e6914b148b86886f3dcd7a23bc27896f86b9a009036fbad55158ba7e329433406d84ab45973b451e27d6a62"
    $a1="45fe64d53670a60a32fd45fbeb8e22c2505278209fce59c97212e22c309fb047632305ab94e13afca1e7ddb44da2869c6f5d01ef9010604b74ef24e5921edbc9"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="186f35856751d71617baad9dc7df6e7ab5d7d17348fdf473597da929977731e2"
    $a1="16d1b91e6218e62c6d0a5abae61abf83a55581c92e6d9da0087a21fcd615c3a6"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5665e3ed29ccb7016bcd620f16b0be405ac8d19210ff3bee077cfd3080fe33fbf88b052e8de7eea48e61ed2944a44f7a1c82d2cf42bcb48e77cb153c732f9708"
    $a1="33509b6581c62b1ae48efcab4188327c4946fe143cfb141765f6657c1c63dea5b9cd715aab8be2955febf9037b63e23888e523454161ed0ad24277ba80ae54eb"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8aa688db0aeea4d8e424029de5b991d395decc589445887b6b82a926073145c"
    $a1="ebe94dc8983771d3bed8ff7fe832471b332b07f1fe43ecd316fb5de0283b962e"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="20f0181b0270a5dbef694a7ae73caf821d35138e998cb40e59a3d422"
    $a1="7e610c66661efb5363535db0f09e02ed10ed3db0468a1807e4593587"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d85a634098f37c08551692653735f515c0c668da8ecdb7299a3c481256ee9012"
    $a1="e1e429a92357a8522f6e8d63a1ec3f7f20b63399063eb7d24f2e8b5ada5d0a56"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7b69d913f823eb310165402b8102b5d589f41435e64936b7e7fe899386aa29df4a6423eb73445194d5ba3b5b7c623b7"
    $a1="26b96a280c54b03133b7821eaa1c34b289d8cf6ae0081fb4b694d030016249f159acba3c64ffc8eb8ac10c63bbe37236"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="910199c58fbb150603f4de110cb20e0f694a5744503421016fb7f90f95653f3c04d64d1250d76372558494214410537df2da2a9670bebb1c2435551b85cc30ce"
    $a1="e5b987007670291ebcc757270fa96b43976e24441a7b385fb408b5d072a9a5179555d3fe602526f3340bbf13c7ed322e457e3c2fb73739cbdbcba51b4ab8c379"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bXVzaTE5MjE="
    $a1="TXVzaWklMTkyMQ=="
condition:
    ($a0 and $a1)
}

