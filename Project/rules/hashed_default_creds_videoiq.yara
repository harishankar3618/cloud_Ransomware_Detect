/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_videoiq
{
    meta:
        id = "25rjD2bqh5l5wCfGhdxFaD"
        fingerprint = "9fc937575a7f4debdda2156af21d29149ec489f4b929269a9b1e2d72b0628d40"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b547e99ae0f3800915f05cb7a152da11"
    $a1="b547e99ae0f3800915f05cb7a152da11"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="154725bc64cc054e"
    $a1="154725bc64cc054e"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*40224614CBB87FF21A56337FDF63ED9041147837"
    $a1="*40224614CBB87FF21A56337FDF63ED9041147837"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}CTSMIKAZvgMYOHwI33p4PQ=="
    $a1="{MD5}CTSMIKAZvgMYOHwI33p4PQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}D00J5D0gjV6SIjIvvHCRzuoaeMM="
    $a1="{SHA}D00J5D0gjV6SIjIvvHCRzuoaeMM="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09348c20a019be0318387c08df7a783d"
    $a1="09348c20a019be0318387c08df7a783d"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0f4d09e43d208d5e9222322fbc7091ceea1a78c3"
    $a1="0f4d09e43d208d5e9222322fbc7091ceea1a78c3"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cbe8fc7bd50b262e822d039459015cb5f4fc3255a86d3fd14c81140153dc714b24bb7a2e2159842415aba43e63b3189"
    $a1="6cbe8fc7bd50b262e822d039459015cb5f4fc3255a86d3fd14c81140153dc714b24bb7a2e2159842415aba43e63b3189"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64cd35385184bab91d1f394b3f64e935fd4bc939333c486a70d9a946"
    $a1="64cd35385184bab91d1f394b3f64e935fd4bc939333c486a70d9a946"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abe6267e41571ad4632231ccab1936e34c91ee389b02bcafe90a6391012bba585138edf92ccf349a451722d8236937fc26fa22c1edf0f9de6851bc96a9a13b82"
    $a1="abe6267e41571ad4632231ccab1936e34c91ee389b02bcafe90a6391012bba585138edf92ccf349a451722d8236937fc26fa22c1edf0f9de6851bc96a9a13b82"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0834c2d60725ac5902257b3b78dd161ad26d1c0290dbf1e47cc14add5b8c8142"
    $a1="0834c2d60725ac5902257b3b78dd161ad26d1c0290dbf1e47cc14add5b8c8142"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cb52c5f42cfbe6a67675d1aba438a50b6f411071de6380d17e89856d99f476c560b3ba2da418eb3dc274a6241fc53b1a0307d7146964b73e953bbd4b58d8837"
    $a1="4cb52c5f42cfbe6a67675d1aba438a50b6f411071de6380d17e89856d99f476c560b3ba2da418eb3dc274a6241fc53b1a0307d7146964b73e953bbd4b58d8837"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c417c6a97cf0da54c21c5214ff25871cd5298dc953f5e8c8c517659eadbf44a4"
    $a1="c417c6a97cf0da54c21c5214ff25871cd5298dc953f5e8c8c517659eadbf44a4"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d263b1a42751fec04f7d158f17d618e58e278ecf7ada3dc66c3e097c"
    $a1="d263b1a42751fec04f7d158f17d618e58e278ecf7ada3dc66c3e097c"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90e6263244bbac7413c1947f2306e13af65ee6507c6d46e3493b276ecc098871"
    $a1="90e6263244bbac7413c1947f2306e13af65ee6507c6d46e3493b276ecc098871"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ca7f171379319d935814bfed6f0a11570dfd7c07821d890236d052e4e77c588f521c851ee9020113bd58bfceae0bd338"
    $a1="ca7f171379319d935814bfed6f0a11570dfd7c07821d890236d052e4e77c588f521c851ee9020113bd58bfceae0bd338"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d7fe5e2e1ab20da6becbbbd478b7ef4d3d28fbda00f8f66a7881e2794d413b5e5bea54ee5667f7136554eb35115d91d7a8c830b9895a383a13ea4874d8dad25f"
    $a1="d7fe5e2e1ab20da6becbbbd478b7ef4d3d28fbda00f8f66a7881e2794d413b5e5bea54ee5667f7136554eb35115d91d7a8c830b9895a383a13ea4874d8dad25f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3VwZXJ2aXNvcg=="
    $a1="c3VwZXJ2aXNvcg=="
condition:
    ($a0 and $a1)
}

