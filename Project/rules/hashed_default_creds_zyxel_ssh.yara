/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_zyxel_ssh
{
    meta:
        id = "8b5UoLb8qpwGZFw7g3FPu"
        fingerprint = "931d47aaa920a49fa1523b91d2f78750efb820577a8ca3acf62390b2f0c783be"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3893dc5543bf510bcddd9e6a00700cf9"
    $a1="4b1c17e86d6a31b04979b4d554a73f71"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d1962a71d8201c3"
    $a1="6eec6df64bad5baa"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4AE3EC6068E548FD3BC718337B56BF68F36FCC64"
    $a1="*2FCC881E45D8A7084FE41E9F111A83938BABC066"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}OoWBCrOMY0rjH2xCG8BERQ=="
    $a1="{MD5}DaZexcxqL5xRGy5FEChYRQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}3oydGeuu6xZg/cmidyO0mYJ8d0k="
    $a1="{SHA}1F/q51yzfPht8FOCKS0n1m+pUf4="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3a85810ab38c634ae31f6c421bc04445"
    $a1="0da65ec5cc6a2f9c511b2e4510285845"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de8c9d19ebaeeb1660fdc9a27723b499827c7749"
    $a1="d45feae75cb37cf86df05382292d27d66fa951fe"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="672737e7130b76016fd70da90a6335333abf04ea8307be4c8b0c5e3088f87d602dbec8b602480be4011cf4edaf449614"
    $a1="1feb54dd8d55fe3acdcc88bbefa920c7d57cbf14be8e12271c428cfa460e04f38caa37eef53f34c141dc1674a7967ba8"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73d45486175c2dfd38dde3d9c224a96c2364f8a02dffd3039e1cee7a"
    $a1="b9d6be0a741186f9057b1046240a6df19364bba94ba228519cc6c556"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f628ac307c494ab7620b51935842da4d18b1a150910133b39438cf551745753920dbba90515487e33168e917002b45ee73cded3014e9cbec09cee0f736d11fce"
    $a1="ac190ec2765fe303f43f1f5aae982aaa64f0c701a19d6e540ff421d4d53b347c7dd784620b8b030c315bde81a0587adbc387a7a270e76a096126df8dbd7fbd8e"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f81474dd5c6fdfd0b86d874390fa7e5b960e29c4f7f1e860635ac3bc5e32a897"
    $a1="97eab8eca5407fe0bd1af1eb4f1e4fe0c4760ea48aef889803ac7584586e2cdd"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa04814d76ce71ff41174915b0f6add1a36645683395290c98a9fea0e9b043f924b96446e22c7badadc80d46f7e4b54b1a7d70b669d024982c0ce8773461f48f"
    $a1="50ef1ff7afd840785894fe8447ab0175436d1a0ea24b8fc05b60049e6ca7242d19d8a53aaf65149f8c0ce5416d4924977dfb39f41d227b0cd01542059ec8ac77"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e725df21b16a98b5f874683d3565b972e134c009a193cb17a41df3652ee0fb3"
    $a1="48be671246741fa37fff3e382f72646a7b1f0bfcf762caf5fe37e276b6348aea"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5941b2b71710b18d8edfdd60680bb91a4ec86d5b8977798debcce383"
    $a1="f34188f6d2656d5b004f971527c55270dadc7a5d1132d28a5621181a"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="337160cd0065da43c33c0df1a7903dd16ed8547ea91733366a614d0072ca5add"
    $a1="6767dd7e79ed2ea1a11ee88be0f0d80590d25697aa2b5d5b8a37421a9bbf625e"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0e4eebde2872cc827253b095351ff431bce62c6207c0886354b53fb660f1a0b566f05afe3de0b1d31deccd9bfc7a9dfc"
    $a1="59e8791b3c6afcaed93cca20f50282848687f5f037287d8510e2a04e30c41c4d1133066dc1382b1c21e8ee0edf9f0dd4"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca618b265911ee80b3288cbd3c51281fc31d0e90432325e037c11b96ded04ccdad3dae2637c507f0a1b0e32d20ef8b37f0d97de4bb2ed9c506f512db2e09ecf"
    $a1="59f6d83edd3122738ea7c4d28ca71317419d790311f2664b44155b5d8bd2bfe36d932ef5cd99da1cd36dc34cfc19bedbcc2d17c2259eaddd2c1c55d77e14f86d"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="enlmd3A="
    $a1="UHJPdyFhTl9mWHA="
condition:
    ($a0 and $a1)
}

