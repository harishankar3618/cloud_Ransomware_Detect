/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ncr
{
    meta:
        id = "1LlJ5Ank9jDugZR2lFnGDu"
        fingerprint = "5419f711f49c263a56a8ffaef9b101b068b22b6424e4e8ba5d82b08516c37a6b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6982d4aedb6c39b2ac52c9f99c04198"
    $a1="b6982d4aedb6c39b2ac52c9f99c04198"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fe2e5064eb0481c"
    $a1="5fe2e5064eb0481c"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*22F1A07B2CF33D0341F28D85E2D4E2B006658856"
    $a1="*22F1A07B2CF33D0341F28D85E2D4E2B006658856"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}e/LhcNVgM++kcZ6VfHdXsQ=="
    $a1="{MD5}e/LhcNVgM++kcZ6VfHdXsQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}2mlTE/eEMN3uWwco/H3My8kFKyI="
    $a1="{SHA}2mlTE/eEMN3uWwco/H3My8kFKyI="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7bf2e170d56033efa4719e957c7757b1"
    $a1="7bf2e170d56033efa4719e957c7757b1"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da695313f78430ddee5b0728fc7dcccbc9052b22"
    $a1="da695313f78430ddee5b0728fc7dcccbc9052b22"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d4cef224efed81a7a3b5bdd4048adad9b8cb98618ca87aaa23ffe45617f2aaf762cb67d8ecf9b00b1ef51888e4b9ee43"
    $a1="d4cef224efed81a7a3b5bdd4048adad9b8cb98618ca87aaa23ffe45617f2aaf762cb67d8ecf9b00b1ef51888e4b9ee43"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c7f2ff58d8294f481981f9668e83c29530487759b600f4fd7f75ced"
    $a1="4c7f2ff58d8294f481981f9668e83c29530487759b600f4fd7f75ced"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d22a867aea2dcca38246d7458624853195e17c484cfc42c9ce48e385042c27fc17430f6f5f547e168d1e9abc71c02490ddca494ca2d847a921640a4f22bfa075"
    $a1="d22a867aea2dcca38246d7458624853195e17c484cfc42c9ce48e385042c27fc17430f6f5f547e168d1e9abc71c02490ddca494ca2d847a921640a4f22bfa075"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6339b64898640df06d70bc408ab27e54de6f9232ce61beb7f8fb24fef016387c"
    $a1="6339b64898640df06d70bc408ab27e54de6f9232ce61beb7f8fb24fef016387c"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48963e6f0f72cc8bff4cdd9c516562bcd3ea46997321e13a2ff4446aed6aa09ec9655e32310d13a478d4259c7a582958def0d27ab658a5229e34a4bd99dbed78"
    $a1="48963e6f0f72cc8bff4cdd9c516562bcd3ea46997321e13a2ff4446aed6aa09ec9655e32310d13a478d4259c7a582958def0d27ab658a5229e34a4bd99dbed78"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1858642eccc09de43b53250b27c1e7ba0e61439780dfcd1704e1ce2e6ee773c2"
    $a1="1858642eccc09de43b53250b27c1e7ba0e61439780dfcd1704e1ce2e6ee773c2"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e728b376090f379c8f313cb7f4009339d42f3862b5d1080355f88cea"
    $a1="e728b376090f379c8f313cb7f4009339d42f3862b5d1080355f88cea"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09d583c51f7781a4c0d5b3dae75c82684f799f3c81871aa274aaf9019f963844"
    $a1="09d583c51f7781a4c0d5b3dae75c82684f799f3c81871aa274aaf9019f963844"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68c04cd0761d80e1894bbb709438c6c14b4e65cdaa82899d34907b049cbb98cf354161eec0b4f16a39c412edad867ec9"
    $a1="68c04cd0761d80e1894bbb709438c6c14b4e65cdaa82899d34907b049cbb98cf354161eec0b4f16a39c412edad867ec9"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cfbe72bc0c2ebae0a0b1d44e1984fae6cba5ef2c00191bf69820d66f73af82d7279d50a16f2a47bdd939f396e2fd4af412ef7547fc87e524d7c209b27b76c3bd"
    $a1="cfbe72bc0c2ebae0a0b1d44e1984fae6cba5ef2c00191bf69820d66f73af82d7279d50a16f2a47bdd939f396e2fd4af412ef7547fc87e524d7c209b27b76c3bd"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bmNybQ=="
    $a1="bmNybQ=="
condition:
    ($a0 and $a1)
}

