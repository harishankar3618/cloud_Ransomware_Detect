/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_guardone
{
    meta:
        id = "49rQffDvf0ulFBoOxAvuHl"
        fingerprint = "a2694dd3e895c0a15c88b6f06f7c62205eb75d14da969b019c60721d17e00d12"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa40632a7b38e63c4dda8edabce89c16"
    $a1="9d95d5a7a19e3ad3223f5f9722bc3654"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5cc1a09f5810fb96"
    $a1="7a783a251b7a7f94"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*CEDCEEE123BC694A37C020239D968FE25095D5A7"
    $a1="*C25D8649E1B208EA92191FDB2D4688F5901850A1"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}zFseN5ydeCcjjS79BDUJwg=="
    $a1="{MD5}8+yoqVlBNg9eH8pf/rBJFw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}enuRFRY24NyNuZyT6wbsb6jR28Q="
    $a1="{SHA}5/ZFx9R7NF1wxb6p+7QdlLv6+8Y="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc5b1e379c9d7827238d2efd043509c2"
    $a1="f3eca8a95941360f5e1fca5ffeb04917"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a7b91151636e0dc8db99c93eb06ec6fa8d1dbc4"
    $a1="e7f645c7d47b345d70c5bea9fbb41d94bbfafbc6"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6df6203da3bc5d7ee3c31d4cfb2a625381b677c7966268314a2dbe00fe400464a359f9bf7d2ccfd1aecaca2b4b3412a4"
    $a1="183c8b5575ad115092768178d8f3d3c98c54d01504662bbb5381f74105d2ecb82e8dae6254a4cbc2b78688dc03b77484"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04ce1fd1988903ad3701106413b25d49468fc7c4562918538edc6fd6"
    $a1="a7d8eb0a6e01add341f25df790b1d7258358daa90e1c5f1925248e53"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8e387cedef6ec30192678c258b1a7eee29e90337a570eb40bcd8139f56e166c1e4199bf72a70f719dc2d4109300744d4a10eca9f6b979135a61a27ec420b63e"
    $a1="0d74e7fbc3640f1ededab305ff0009ca90db7330e01002f6220ed66c319fd736a6752e0538867535b1488dcbed178ea140a20844d45e32ecfe21e8bef49a0240"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69fb5444c9427eaa8a70ce32e5ab950b9a81920fd7640a04cabb65c46c55d0c5"
    $a1="fb259aad25841d6cc5f0fcb3576e11a33002802a09980190488895d6239a9e39"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8545495a00f90df3fd67024713f7764f1a1a57290e791cff49d2e3ca2917442d26eac358d0279075c60ff1d951d889e92dbb8d9c5c74daf4ec686fe5a3669b3a"
    $a1="41965264f09107147961b6403f12de5b1d8953ec7ee249e917acab68724d6c5000c8726c50b40e093a0881eeb4e92c7efec4a9925fab561294bd96092bbd82de"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23ca0413cde6e0bd25bad7939c03ae138381f759855bb5d5ef73e7f0b6cd293d"
    $a1="51dec5e150e324ac88fa9664d19521e335f32bfb0b343a2053eacf2575e75145"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc775e50b91b96a8b602da52e3e43fb3d74c1e7a217683f60a5cb447"
    $a1="7262d70b6c09248613dd148955d76f203a9e519eaca4aa1f91f928f4"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e5184f08aea8115aed0c70e297c5a9b618aea4efe96f5fd87fce169dc020f6a"
    $a1="5e4d2874a8e089b5180b497f41a141122145b624ef72bde5ea9f78a4f8e9036e"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b58da853115eb388c5e9210e21fbf56aa8aff19a5b4a03cb989afdea87eb01db936947b1a57cb25c1897d56f3596ab28"
    $a1="5f0168368ba48f6fd4464d8fc0ec4f21bba83fa2f7de57b0b6c2bcd6bde90185fc93a6a44ca59c4d6e15c44e4ab8a60a"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89ad8fdd72a8909f03f5fb53e309d26dc38a55d240620ab9034100e60c410edcf0c6f57771bad72f889f4a1e4dee4704741ec2082f85749540beb69cfa87f9e7"
    $a1="15a4b64a7d06755f56d0e82eeb2c3f4de7ee32f1f6c16647e04e43a71096f598fb4ed44a7f0c425289c4ba3c9d7bc8cae31a50e123a43a949878da526b833239"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bi5h"
    $a1="Z3VhcmRvbmU="
condition:
    ($a0 and $a1)
}

