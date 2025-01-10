/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_tsunami
{
    meta:
        id = "2vbiI33mE8km2XgemBZSyl"
        fingerprint = "2c693281514db3f2349a8168fb446e99de6d9b7615ee5f5d5562610eca088ccb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54b5028cc3062efa2570258decd2d27f"
    $a1="54b5028cc3062efa2570258decd2d27f"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65da332005fc3fd1"
    $a1="65da332005fc3fd1"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*DE02B029744CBDE885B76F04F823DDB01C361551"
    $a1="*DE02B029744CBDE885B76F04F823DDB01C361551"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}iw3jFaAAU0ehtyk4yOq1+A=="
    $a1="{MD5}iw3jFaAAU0ehtyk4yOq1+A=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}f1cgWsUb2e5CF8wyc5XC0cltwh0="
    $a1="{SHA}f1cgWsUb2e5CF8wyc5XC0cltwh0="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b0de315a0005347a1b72938c8eab5f8"
    $a1="8b0de315a0005347a1b72938c8eab5f8"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f57205ac51bd9ee4217cc327395c2d1c96dc21d"
    $a1="7f57205ac51bd9ee4217cc327395c2d1c96dc21d"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8088cce58d09184bfc1fd3e950454ef4918d5360724ba6cf608df77ff182aaac15b6e83990b04f139fc76264b1e2bda"
    $a1="f8088cce58d09184bfc1fd3e950454ef4918d5360724ba6cf608df77ff182aaac15b6e83990b04f139fc76264b1e2bda"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58d5546153aaceef37594766908e264a2b28bd9a0cd55fbb77c36adc"
    $a1="58d5546153aaceef37594766908e264a2b28bd9a0cd55fbb77c36adc"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2ca825ca637138f338b75f5a3a1fa29ba7048e9bcbff41c48acf8ab7aa308e84b910e1969087385917213b89278af76606f5ca3150652a7b4537afcb28197226"
    $a1="2ca825ca637138f338b75f5a3a1fa29ba7048e9bcbff41c48acf8ab7aa308e84b910e1969087385917213b89278af76606f5ca3150652a7b4537afcb28197226"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6ef1856e376fff10d5159f5f6f5a8d35cb7032a3954c32a616ab9b91e7d19d3"
    $a1="e6ef1856e376fff10d5159f5f6f5a8d35cb7032a3954c32a616ab9b91e7d19d3"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd771f69114d62cb014c91fbc6fabdcd1afba71292a1fc5b075100c88370eb53b056f1af869215d3d6a47ce61c75a298001fb9506849ee148a33285722801fdd"
    $a1="dd771f69114d62cb014c91fbc6fabdcd1afba71292a1fc5b075100c88370eb53b056f1af869215d3d6a47ce61c75a298001fb9506849ee148a33285722801fdd"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c274bf0354e35825ec32b0e7ca3d00f8e4d2a7770c84897fc51694556c6e6a6"
    $a1="0c274bf0354e35825ec32b0e7ca3d00f8e4d2a7770c84897fc51694556c6e6a6"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95dc57af00498c9d56b2eb6b07d6209428e5de48270e0a32cb4712b4"
    $a1="95dc57af00498c9d56b2eb6b07d6209428e5de48270e0a32cb4712b4"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f89fc42704de7715afe014d0af4923e83bce4bff3c83fb3a5f31f90f33a1ffa"
    $a1="6f89fc42704de7715afe014d0af4923e83bce4bff3c83fb3a5f31f90f33a1ffa"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db4e5f8ca077e67b99cfb99fae79bcd0e66a4caca86a5f2ab1218ebc380ed3ad5864672cef70fe2559af2990c0c2abc5"
    $a1="db4e5f8ca077e67b99cfb99fae79bcd0e66a4caca86a5f2ab1218ebc380ed3ad5864672cef70fe2559af2990c0c2abc5"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7669b686528cc066cff0c08210e26843c2131daace677c38b031c809b865a3b4c32518494f40df88529ab7e3485d09c5e658165758718617c6467cbff687491"
    $a1="b7669b686528cc066cff0c08210e26843c2131daace677c38b031c809b865a3b4c32518494f40df88529ab7e3485d09c5e658165758718617c6467cbff687491"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bWFuYWdlcnM="
    $a1="bWFuYWdlcnM="
condition:
    ($a0 and $a1)
}

