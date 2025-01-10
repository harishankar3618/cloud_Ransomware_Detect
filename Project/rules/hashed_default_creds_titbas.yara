/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_titbas
{
    meta:
        id = "2SSAoAh9B6ALPiJbZmV4W5"
        fingerprint = "aad583ef739b3c61516d6a4d69cb8f5e27fc71aacbe895c9642ed17d92a8b568"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c345ef38a826f84633a9f4147bb49c31"
    $a1="f8b0c34035173351f6ecbe70d58a2024"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21aaf05d113ad4dd"
    $a1="14499d754adeccc3"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*CA0B6529782B186DFF504056E97DE7E215E8A242"
    $a1="*67D0062E7BAF8B6037783CBBAAB19946364A28AA"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}MqL3X4ORMN3eb3a8evWdXg=="
    $a1="{MD5}46pGEy23f0evOumaX532CA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}szB56vjv4HTqcXTf6uGqxQ5rkPw="
    $a1="{SHA}ApI/V/UihAeVB0XgovaB5evOSJQ="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="32a2f75f839130ddde6f76bc7af59d5e"
    $a1="e3aa46132db77f47af3ae99a5f9df608"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b33079eaf8efe074ea7174dfeae1aac50e6b90fc"
    $a1="02923f57f5228407950745e0a2f681e5ebce4894"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2bf6a6403cf4db534d4475b623d954b47c94346205aa0dff368208c9bf17b2ea82adcd2de2b23817811784a94777379f"
    $a1="b6b91770b927e68ea6198bc4b53e9e722f24652580b3f4446588ebe3c7171c2dc49b3613f7134ef6b286c3cb14dde5f6"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dfe91c06d872d631af4c14cca30a6277605ecf2403b6b08065de0620"
    $a1="da870fe5041ff72b2d0ccf747b9fb4ade5003cbdf0d5c2726fb7f4f5"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d2aa3cf52c1169c42e1c03341f4ed0e7d709d3c4bbfd5ceb1e1dc1ab66dcac4c98721c4c07ab590654404e21296bd15fd3ef70b6a536a2fec58dfc3f5c8ffc8f"
    $a1="6d54fff35aabeaa7b70caaf0da953d6fc003f9257da3ce74aa14861123732b8bea9f2df6c2e3fdb4dfe7f6b9f06b836b46f715836bb9c7513002a48689687209"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29761b5f5508f92ef28a1712097d4dc0ff1ae7ad35f1f0ab233d151fac351ff3"
    $a1="644a6d40e00843025bce83ec8c2311d17c6d2b6a3a2ba0a917815cfd9515bb1d"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="df3071019dace3235c3765614d8136588bb704ef6229289e48769df35cb534c6dee175881d44bc06f915e685585a16587d3ba9b964123ffe22a8a00badcb2b41"
    $a1="87cbfc2d6506ef091cbe587e7b845076edec5b1e122322dbae920de7f76827caa8861ea9183ff5bc08c9693ca05c027431e8e345fbe0326f069d3e4e91ef0813"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7a86871c1936035a6999f46404ec60e1bd6591284ed87412b3e47563ae11f3c"
    $a1="bbb79502cc6e173f4371e1cb85a640e2adae7ce1151d1c609f606e3079da0f77"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce19a3aa677b82806e9b670915d5f99d15924ceff14b29d805773884"
    $a1="f2b9a1aab3f989b52f5f04fb6dbbd1fbdedf8069de078f22c7ccd7f5"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a15b810619da2116e404d84e3ce40c3e7ab3b2165b1ecebc033d7fb314d0ee44"
    $a1="509260e47b66dbeb5b473f62fa7834f89ad3dffba17c34da26c0e06eade2f882"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73f67733846f098795e6ad87aee12c7540a5010c3589891c7f1006d8f0a98092a87a544071dc2d91a18567e218d07376"
    $a1="8d1c35d23636f3a4437e936a6ceb0d3b6dac6873b84042df6860f5263853dfec30462c0491ff6dec497b0ca1958c2f5e"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d08426b06b925f20460c8a7983a3e7f4528c842e7d8a1eeaecf869e0271ed6371b5e9ed09070ec6f9ac1d87b3903576a8b3f69e6ea66fa50773486e7581babb"
    $a1="04a95d14009ea231eb4653afe74bf8d1d60520c8793c42233befcbaabc8251358f167e8782fd0cc28c9441b70382b4b3b652152ea505849faac2f145ded71c7c"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aGFhc2FkbQ=="
    $a1="bHVjeTk5"
condition:
    ($a0 and $a1)
}

