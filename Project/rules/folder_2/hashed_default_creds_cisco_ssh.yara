/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_cisco_ssh
{
    meta:
        id = "2WNGGqwL4rOKlYUZVhWucI"
        fingerprint = "ddf98087bfe83fd62d1a38cd9a81d2a2f6427538838da3549369d5d177ea9be4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c800f13a3ce86ed2540dd4e7331e9a2"
    $a1="5c800f13a3ce86ed2540dd4e7331e9a2"
    $a2="5c800f13a3ce86ed2540dd4e7331e9a2"
    $a3="f228a3a3c4f734aa12449e2bfc0a652e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13304f67671f2f3c"
    $a1="13304f67671f2f3c"
    $a2="13304f67671f2f3c"
    $a3="78dbdf4128040620"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*310AF8D67AE450FB86125F07FF75D1583528B45F"
    $a1="*310AF8D67AE450FB86125F07FF75D1583528B45F"
    $a2="*310AF8D67AE450FB86125F07FF75D1583528B45F"
    $a3="*25F807BD25B92C3093960A1B6DE8E95BAAEA53D4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}3+rxA5DlYK6nRcy6U+BE7Q=="
    $a1="{MD5}3+rxA5DlYK6nRcy6U+BE7Q=="
    $a2="{MD5}3+rxA5DlYK6nRcy6U+BE7Q=="
    $a3="{MD5}dEtB8NzNMuv11SW8HGSvWg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}eveMkR1bSL6h3CRJ2diVE6vrS+U="
    $a1="{SHA}eveMkR1bSL6h3CRJ2diVE6vrS+U="
    $a2="{SHA}eveMkR1bSL6h3CRJ2diVE6vrS+U="
    $a3="{SHA}mY58X88WgXOYXclPmaA3PsKy3zQ="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dfeaf10390e560aea745ccba53e044ed"
    $a1="dfeaf10390e560aea745ccba53e044ed"
    $a2="dfeaf10390e560aea745ccba53e044ed"
    $a3="744b41f0dccd32ebf5d525bc1c64af5a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
    $a1="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
    $a2="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
    $a3="998e7c5fcf168173985dc94f99a0373ec2b2df34"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
    $a1="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
    $a2="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
    $a3="ebfcce5a94d625804ece72a70a1c36aeaba58bd2f034c9522e9c24a5dda030f66c106ff31255656c7bcb92c824c546da"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
    $a1="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
    $a2="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
    $a3="8eaa349e8a15c4dfa4c30fc6645740d51a69a9727aa77f28d1a8dbff"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
    $a1="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
    $a2="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
    $a3="8fb64d78d481ac40eada3c93b77944e2c76d42e8419cbbf7f2aa2fa3ff1c167e51b908f5058bc7977da0afa68094494678ce2dcb343557a8446c7170215c2c42"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69"
    $a1="e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69"
    $a2="e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69"
    $a3="57c712d37789c12225e9fa5c5af81338cfb2a7787cf84047d52d2b40fb73afb0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
    $a1="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
    $a2="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
    $a3="6f3d05b7c73920e4214486dbfa505555926e97baeccc530f509fbcb0ffc0b423d8a709d721fac41bb1c0ed365669f2430d0b8bdd16c462885bbad2d10275b396"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
    $a1="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
    $a2="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
    $a3="2008ddb51e6f0e192c7ba137dbd27e689f59e6ce514c31d4912f58a32b7210a6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a1="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a2="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a3="3e7cf6ccb212cddfe99cd22f7d64667033ef35354acead16cf9955ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
    $a1="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
    $a2="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
    $a3="38ed6422dfe4b7c24ef3a3d98839028a140502cd003b88c28228907ae901a1b4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
    $a1="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
    $a2="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
    $a3="71d64884648a064d2db9283ee86d2b83aeccc7b3f5365e528100d8aff72d5809cde102e9e3fc68dffc3a5cfd97226c9b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
    $a1="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
    $a2="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
    $a3="02acdb33bfe258eb053a656c0faa07cd4792efc9a1875ff056154ee6c80823ed5200c7ea4f8f2e9f688179dc96eae2e0c6a010818286fabb7d263f3a4ff0784c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y2lzY28="
    $a1="Y2lzY28="
    $a2="cGl4"
    $a3="Y2lzY28="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

