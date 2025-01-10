/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_schlage_sms_mssql
{
    meta:
        id = "2aRIy2U4YTimuEIoe2ZrRp"
        fingerprint = "a3c86a5263f206c891d93ba418e9fa20e4117756085eed87605c7baf6e79e63c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d22825a471801535dd101a8e803a4bb1"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
    $a2="d22825a471801535dd101a8e803a4bb1"
    $a3="6cd98bbeb78e2fe1bb3af336eff4a0da"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26d11f8f64ffefa5"
    $a1="077ff75a4925858c"
    $a2="26d11f8f64ffefa5"
    $a3="496243e22bdaa7ae"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6C370B79FA6C66B01F1E41711BFBF46DFD29762D"
    $a1="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a2="*6C370B79FA6C66B01F1E41711BFBF46DFD29762D"
    $a3="*CE624A915A6ECB07B43AF7BFB6F35EE40D616583"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}O1PA/fQnO1VGEIT8EP4jNw=="
    $a1="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a2="{MD5}O1PA/fQnO1VGEIT8EP4jNw=="
    $a3="{MD5}dCmqhWPmSjhQdVKqkPszHw=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ETMhUVf/ksxhoXxKY4Xn6cGOiQ8="
    $a1="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a2="{SHA}ETMhUVf/ksxhoXxKY4Xn6cGOiQ8="
    $a3="{SHA}S2s2I0OnQq1AdD8+GOl3AjYHZ0Y="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b53c0fdf4273b55461084fc10fe2337"
    $a1="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a2="3b53c0fdf4273b55461084fc10fe2337"
    $a3="7429aa8563e64a38507552aa90fb331f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1133215157ff92cc61a17c4a6385e7e9c18e890f"
    $a1="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a2="1133215157ff92cc61a17c4a6385e7e9c18e890f"
    $a3="4b6b362343a742ad40743f3e18e9770236076746"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae958cc6b467f74d13d9b4223d48b7c22a513f85f1001c80ca5986040fe51d78662405653b08f0f53bbb39980a2840f3"
    $a1="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a2="ae958cc6b467f74d13d9b4223d48b7c22a513f85f1001c80ca5986040fe51d78662405653b08f0f53bbb39980a2840f3"
    $a3="9bc3a99dd6aa1babf302dcacff9eba070607e7f92c51efc9826697547a32297b24744525528e243597edbb5aa0c3f346"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ef0a48857e59814ce0ec978f684b4580eeae835e84ed01df137e377f"
    $a1="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a2="ef0a48857e59814ce0ec978f684b4580eeae835e84ed01df137e377f"
    $a3="8022ff7825f35bbeed2415087ac9899542a3ffe21a6084e16efe9bec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d479e13acbb40ee9b9038180f1953186a2ad22516b2b5ed6d8715a07db2bb465117547575d8415c6561c58d315949bf2b9afdeb9566049b2504281cb41874be"
    $a1="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a2="4d479e13acbb40ee9b9038180f1953186a2ad22516b2b5ed6d8715a07db2bb465117547575d8415c6561c58d315949bf2b9afdeb9566049b2504281cb41874be"
    $a3="7ccf8f59491f577b1405d4f1a6228d73eb7d45e67f156bf5459566307e72325a5318d85133c3078fa74cbaa04f5b0e92e681a09e3e3c87ba596e8d8005eaf0a4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="264de172cfe8b910cc5e8eef630ff78cac224101f14a01cd3661f66044691eaa"
    $a1="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a2="264de172cfe8b910cc5e8eef630ff78cac224101f14a01cd3661f66044691eaa"
    $a3="043e98d3441cf2d70e089418ca866efc8b14c496f71c3ee6eca3e6113dd17d2c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61399950475579b5b2441312e3506af9de933917c42dd432c5a145eb5cf32ca7b9e6f6eccd34ba8cf501cce9926d7dfbb73094fc6afaadd5dd7f4ae63858905c"
    $a1="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a2="61399950475579b5b2441312e3506af9de933917c42dd432c5a145eb5cf32ca7b9e6f6eccd34ba8cf501cce9926d7dfbb73094fc6afaadd5dd7f4ae63858905c"
    $a3="16d2d1ca296c5929e0f1129225cee04ced9671246a688e30fb0c8822ffcc4e594aa33630a80ff1c87d5d58d492c7730bf36190e21628c1e20400b095fdebce4b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4247843133c0643f01f0994852c52ac076535a4b17dd62ad6450a3d6a80f63a1"
    $a1="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a2="4247843133c0643f01f0994852c52ac076535a4b17dd62ad6450a3d6a80f63a1"
    $a3="2a40a2d445c601b9ef86c2d92fd47b50b83c820a1776e4a745feaf941528119b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e82d2968d2b62a52a50c3a4becb4adcb8d4f0a5c6e5aee14a01a68ed"
    $a1="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a2="e82d2968d2b62a52a50c3a4becb4adcb8d4f0a5c6e5aee14a01a68ed"
    $a3="1f2b34adae97ba0be8aec562b00df7d82ba894326901788bc4ec25cf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e398f3018ecedb0bcdb4e05ffdf78f2d98b0ca456680ea2eba89d424f3e388f6"
    $a1="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a2="e398f3018ecedb0bcdb4e05ffdf78f2d98b0ca456680ea2eba89d424f3e388f6"
    $a3="e3af3655adf7db74a945a34e361f8fa2ccd791da8e4727c5b853c81fdc33f483"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c9a9f1fe5c2f7e69c342bedb55caaa6d54303c596f89734b36fc7603602eb3f13b25db9d916ab415cc55e03c9f0453ac"
    $a1="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a2="c9a9f1fe5c2f7e69c342bedb55caaa6d54303c596f89734b36fc7603602eb3f13b25db9d916ab415cc55e03c9f0453ac"
    $a3="f1489c225acb5ebe3c774772b80f34fb955dddc69a8c66f210e63eddc681aae0b3a5374624666a60cb41cd809d077c27"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bba69ca5f704e7bbd4d798e059559d2dd07d6095f086e9b30a33635f08477e1d34f6a7dcd58eb79efda23b9f80cb6b1ceabca6e713a4021a45a938cdd552e8f3"
    $a1="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a2="bba69ca5f704e7bbd4d798e059559d2dd07d6095f086e9b30a33635f08477e1d34f6a7dcd58eb79efda23b9f80cb6b1ceabca6e713a4021a45a938cdd552e8f3"
    $a3="6ff1755e0fecc408e984ac26c8776c950bb31a429eeda7ccff39770b77314d9aacd339854ca8a3dabc4b087e95f6b216421523e070bb0d02c77792f73a35ec3b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2E="
    $a1="U0VDQWRtaW4x"
    $a2="U01TQWRtaW4="
    $a3="U0VDQWRtaW4x"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

