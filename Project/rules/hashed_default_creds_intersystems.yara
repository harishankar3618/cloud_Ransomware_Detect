/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_intersystems
{
    meta:
        id = "1lfjP3ggQOEWxI1AYOzJ32"
        fingerprint = "fc6ced93913a04a2435eefb5c53507f6a1d5da93373c256f32abfcd97c2cc41a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4fd0ab5b46db3d4bae053b78d3345800"
    $a1="f441f41aa59214cccc3d4ba5ed1550cc"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="789bbd8d262f3ba1"
    $a1="6a77f1277b51f67f"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*BE353D0D7826681F8B7C136ED9824915F5B99E7D"
    $a1="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Nry7gB9QUnOa+CIMbqUUNA=="
    $a1="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}tMVu6NKFQWbexmZE9UG4UkcQWyw="
    $a1="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36bcbb801f5052739af8220c6ea51434"
    $a1="54b53072540eeeb8f8e9343e71f28176"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b4c56ee8d2854166dec66644f541b85247105b2c"
    $a1="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8a7c455d373266f5528ca765beadf67b8cd9df1f8c3fcfb5fdbd7541d0a4a389eb39360fb6439f474cf0e538101df97b"
    $a1="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31a97dd618f14542b2694706a865537fc1303f3072c8cfd61369cc9f"
    $a1="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a67db7f97aeccbbad8cede443d8cba9cd66d3935d47be40b48a93cbb5a1afc61bbf0bae8a8c9654c0789284151da1ccdce97e30034a8e0414db08f512a8366e"
    $a1="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="518b67e652531c5fe7e25d6b2c3b4ef6224e7d90da2091967dd47eb082b26a19"
    $a1="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f100c65b0d6bcfedac6fba6625e7705217433b4759a70287da5a5153bbeb5c23df492b60360d6d5b3efb5faeda2f626836b6c76d89d7dc7ca902aad40ae3abeb"
    $a1="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7a48923c6d9fedb521d303597779f531e1c2b667b5f128bb9a61d840292111b"
    $a1="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b31e6c41b571759de5fb9d4b5a59653bbdcb345000ccf982be94ece5"
    $a1="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2440602c0d1c3adbb2ee9485506eed4b1ec0f20bcca3ea2ddbb10a351fe85911"
    $a1="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f518f8c6ec3a806a5ad3cec99463383f94edf16486960bd62882c11ab7b75cac1f512ec2f5b8dbef497db829643c4418"
    $a1="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff21aa55877cf49c500a8b286a5e430cd92140fc466facbf1797cf9674c38a6a2d7d7d45b69d87f76710e16f33c3b37858aa9d802d22a824578fb56c61e6ace6"
    $a1="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_intersystems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3lzdGVt"
    $a1="c3lz"
condition:
    ($a0 and $a1)
}

