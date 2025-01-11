/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_webmail
{
    meta:
        id = "7J9Zu1vGjEC7ZvSTL8W11B"
        fingerprint = "f17d6c0e6e962511080e9d0f42259605f4c8ae49be7331dc8702fcd1539d70fd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1b26c7d0ee32e2365626f3f09c647095"
    $a1="8039375c9da8322eeef1c4b1541a58a7"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50c86b3d051d8324"
    $a1="79047f2028d4fb4e"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*D3D77B4E2772DB3B7E8C3F7F2EFC288C4C224A76"
    $a1="*C930EAB8CD25E07A09CA4B2992FDE1EDAC863423"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}rcKuChmFrdnLWykliugRQg=="
    $a1="{MD5}SsN//Y4GlL78ZrOEfXbbpw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}7wHnWwywcRLpVzoHMW8BrvsjJJU="
    $a1="{SHA}q2hF2FKsdRIvKzcPnnJEf0vyeD8="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="adc2ae0a1985add9cb5b29258ae81142"
    $a1="4ac37ffd8e0694befc66b3847d76dba7"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ef01e75b0cb07112e9573a07316f01aefb232495"
    $a1="ab6845d852ac75122f2b370f9e72447f4bf2783f"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fda1ad15cebc440f1ee1cf2ad9e461ac118f0cd18b4c7606e2431b9f99299ad0f0c74ce4e3c3ad82e77ec0490c8cd219"
    $a1="dd4783315f6cd993fb4fd1782fa139985f2e7d769ba7913db01b1838b395f439dad3e743fd36c4c893253d7537f88dfb"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d16eb92a4605ccb3776a13a8ab8a83f8d7c4a98fbffa817c0131205"
    $a1="599071a98e1eef8835e0150bf9fa0f152ce6e7640ff5a11918a5b485"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f4d38cbe29495795948267dc429ce4b62e955ec2bf26fb48f0312959a71ecdad4523462c1f216bfc68b28ef18e8f84cc3b3a1c410edf711c93bab1b86b33297"
    $a1="4a066e718cf5276324b77c84f582020e30f764fcc163cdbdfc65868fb8fd526b36b6159fa3699004580c99c77277fda3f8442b428b5ed0fd58fdfaceabddfa9b"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eed59b8a79fef142936244983c1fb3cc2987d19c5d8029b61a25c73184c6ad42"
    $a1="f642974cfcb13951bb7d2f007a01d957bdde662a313a3e5c2cb08bb54f16f07f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6253051754f33993bff0378422ef21c5929a8704073e44d2488a14fd239399a89f55485601e96d99d8c3de1c0e41e6ea71788d552bbff8e49419aba78114294"
    $a1="6b04b4f75c204b0fe79f81a95624c159b824a2107803b32eef68b10d23406a0fca96c3a0386e587133a0d9688de6551608277865faec3655729b585c76519f99"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28928974ccf464a079b2165c676f5baaf17eae83e058d67fac0d53c99825ccd8"
    $a1="9c65f56deac0e6c933237e2c9ca6955a1d64d7804f97c959adde0dfe283bd426"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2121be558996192813a468a057809e53ad07b0f395781a2315c03b28"
    $a1="0a2d0d775dae3c3d1c55d3f5b54f6a766124938eb25435203082aada"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee66b0d22776c2f9f070b5b971f35a64d56dc2ee50a839fa8dfe1d510dd3b2fd"
    $a1="a3b7526009c38f90a86e2b5f93522c2aa32fc3b955ff985c80f4b97ebd3025f3"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c47a2b5caa3bd7d18d6e5be62fb501a5521b12fa2f6e8e1b45b9e504c3fcc3d19d7593aaea7caa3744f2d8df5360b82"
    $a1="2c3faca0bb3ca624815393ff6e5f233fe6385761df9bff7f97f4fc9ce3760b4838c5cce80e53805972a2d6ff21fb5daf"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca94cae11a0d00fd99fab03ef31115b68806b1efa1f19cdc78ef56c44f7458bb62560a684e481efa407ff3085af74de657eead373794822a3950b76b756652c"
    $a1="71ca8e625d2845307565ac9bdb13b4d58a537bb16f16f4d2e6983d30b43cd77e707cb2f1fc3e92bcca1d00684e21f440e822bd3f43ef90bc142f08a891bcc110"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a29s"
    $a1="Z25pZmZl"
condition:
    ($a0 and $a1)
}

