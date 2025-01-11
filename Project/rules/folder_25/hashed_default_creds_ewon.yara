/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ewon
{
    meta:
        id = "7H51RvzAebJZ7tGsbuGMRk"
        fingerprint = "a8e6a9ce7521ad4017dd5df7b9467918b047ff3bc53f4cd9261bbbb312b3b239"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e8c03ccbc34f2e2e6cfc57102c91c09"
    $a1="5e8c03ccbc34f2e2e6cfc57102c91c09"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7cd1bea82be4314f"
    $a1="7cd1bea82be4314f"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*3DCFB64FE0CB05D63B9AF64492B5CD6269D82EE8"
    $a1="*3DCFB64FE0CB05D63B9AF64492B5CD6269D82EE8"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}sJxgD93Fc/EXRJs3I/I9ZA=="
    $a1="{MD5}sJxgD93Fc/EXRJs3I/I9ZA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Qu9j54Nu9iLZGFwaRWBR7fFglcw="
    $a1="{SHA}Qu9j54Nu9iLZGFwaRWBR7fFglcw="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b09c600fddc573f117449b3723f23d64"
    $a1="b09c600fddc573f117449b3723f23d64"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="42ef63e7836ef622d9185c1a456051edf16095cc"
    $a1="42ef63e7836ef622d9185c1a456051edf16095cc"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f290520af1f0a7529e696507f69ec5fc3e9b75fe834611ba3fcd82dbb1ccd4ae754a580537baadf97c2db43ed36e07e"
    $a1="1f290520af1f0a7529e696507f69ec5fc3e9b75fe834611ba3fcd82dbb1ccd4ae754a580537baadf97c2db43ed36e07e"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aeaacafd0817d01e6681d528040efb3e47fe79930f363df1b2d6d39b"
    $a1="aeaacafd0817d01e6681d528040efb3e47fe79930f363df1b2d6d39b"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0858562831f7cbb5b461ef0d73c68ead83f2c0910d0f2e0811b455f532653d208b43e3f93a5532508c7ebb70cd7e7be8bb53d58b4c7c69f0764990657f1c4e1b"
    $a1="0858562831f7cbb5b461ef0d73c68ead83f2c0910d0f2e0811b455f532653d208b43e3f93a5532508c7ebb70cd7e7be8bb53d58b4c7c69f0764990657f1c4e1b"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86f65e28a754e1a71b2df9403615a6c436c32c42a75a10d02813961b86f1e428"
    $a1="86f65e28a754e1a71b2df9403615a6c436c32c42a75a10d02813961b86f1e428"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="42373117c429fcf616c460f81e3c2e20c8718c3793508c65dd7692f21a1eede776e782371d964b0c89acadbe6dba8200950443e5cbc99165ae22bd9c4d744ebb"
    $a1="42373117c429fcf616c460f81e3c2e20c8718c3793508c65dd7692f21a1eede776e782371d964b0c89acadbe6dba8200950443e5cbc99165ae22bd9c4d744ebb"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c684fc5eee9f629a619a613bb39938910feb4e39b465fc9a62324a695756035"
    $a1="8c684fc5eee9f629a619a613bb39938910feb4e39b465fc9a62324a695756035"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff7c40ed3c1ca76b55393cfda50b3c0f14723624182790648e88692c"
    $a1="ff7c40ed3c1ca76b55393cfda50b3c0f14723624182790648e88692c"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="184cd019129767f24837c19af5f50de7d9cd933566176f7a9bc5b15a76a309a9"
    $a1="184cd019129767f24837c19af5f50de7d9cd933566176f7a9bc5b15a76a309a9"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="227e8bec444f05d5459fff38cd02b171ecd52fcf3b62932ce65c7a9c7a804bbcfc6b521fb85cba8edc4bbb3e4f74de03"
    $a1="227e8bec444f05d5459fff38cd02b171ecd52fcf3b62932ce65c7a9c7a804bbcfc6b521fb85cba8edc4bbb3e4f74de03"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3f30619b5c9e4f9483890ad9f676583dcbfd605992d9dde1b570b88126392d01fdace49bd4c4c0f509c24fee605467f21e33d8aa41feb28ebb3f23d7641462b"
    $a1="a3f30619b5c9e4f9483890ad9f676583dcbfd605992d9dde1b570b88126392d01fdace49bd4c4c0f509c24fee605467f21e33d8aa41feb28ebb3f23d7641462b"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRt"
    $a1="YWRt"
condition:
    ($a0 and $a1)
}

