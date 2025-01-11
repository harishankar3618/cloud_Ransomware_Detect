/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_jasperreports_web
{
    meta:
        id = "412nKdLIbATcTXzioBTtrb"
        fingerprint = "338c11970ddd521b9ac799e4b383c326dc6fe5ff131720bfea7593de7fe7f530"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d0adccbef1bff9e91b3bf97d5227655"
    $a1="7d12dddeaff695c2c74dc78043a7faa4"
    $a2="7d12dddeaff695c2c74dc78043a7faa4"
    $a3="7d12dddeaff695c2c74dc78043a7faa4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cc3e6ba065162b0"
    $a1="154a62c87a7c7078"
    $a2="154a62c87a7c7078"
    $a3="154a62c87a7c7078"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*3792637D0995C22FC1AEF939DA506C5011EF2856"
    $a1="*87ECE1144502DFB74FD0B26A847683674C484658"
    $a2="*87ECE1144502DFB74FD0B26A847683674C484658"
    $a3="*87ECE1144502DFB74FD0B26A847683674C484658"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ak3JEz1fO22f/3eK/zYZYQ=="
    $a1="{MD5}DXzG/fPUMrfwhVcTxQodvg=="
    $a2="{MD5}DXzG/fPUMrfwhVcTxQodvg=="
    $a3="{MD5}DXzG/fPUMrfwhVcTxQodvg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ZstFamEoKVPyEqbvjuY2Os+4+3w="
    $a1="{SHA}SJmoSfajzueeKtW33ZPQp/J21JM="
    $a2="{SHA}SJmoSfajzueeKtW33ZPQp/J21JM="
    $a3="{SHA}SJmoSfajzueeKtW33ZPQp/J21JM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a4dc9133d5f3b6d9fff778aff361961"
    $a1="0d7cc6fdf3d432b7f0855713c50a1dbe"
    $a2="0d7cc6fdf3d432b7f0855713c50a1dbe"
    $a3="0d7cc6fdf3d432b7f0855713c50a1dbe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66cb456a61282953f212a6ef8ee6363acfb8fb7c"
    $a1="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
    $a2="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
    $a3="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48edf17268dc2f757b35d442d540f840809a974e289721019d101d8e3552e2abd5f68c16599a531ea361d370822144e7"
    $a1="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
    $a2="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
    $a3="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9468b5307d3514f902f81af5ee8a488bd244ed4c1bdc02d6f17f63aa"
    $a1="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
    $a2="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
    $a3="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d99824d0cb6804c4996fc34f06ab2563de34e851f0c3fc25a2c0cc632b12ab2ad63dd4a6cbe39e4105ec08d6f6e5d5fc799dd70a3ab47ad83aa584febda5d5b"
    $a1="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
    $a2="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
    $a3="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="017fbc0e001b5e9c16908c754f9607dc886f25d08b2cbadc788b8b267df199f2"
    $a1="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
    $a2="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
    $a3="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="00de78040cc8520f9a7290ec4f00e9436de01dc310dc6db4fc9e8c65d56c073a5c2f07fe07d168590cfcf3f0b739086b5bc5829e2d8d31af109697ad7d2b02d8"
    $a1="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
    $a2="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
    $a3="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a88f86c26a1f2fb9a6bf045e564f68f97bcd613637a819f10f0981183833f739"
    $a1="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
    $a2="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
    $a3="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="38d451cef0eed09b331be920a49c913572c59e9c1e7af5d1899f70c5"
    $a1="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
    $a2="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
    $a3="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ca50b06be31750289916ce72dbd7e109be9aec3c1bdc0af80412dc2a468a43c"
    $a1="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
    $a2="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
    $a3="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c02019ec9e70d96b6adbc7c2ad0848a01034cb1eaff489ea690c04a14af8c729bd215c8c39f65ab98fc1ad4adbcfffc"
    $a1="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
    $a2="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
    $a3="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ae30ea303bad8626c29abbf3932ff11d9f8999d028d5cca978a85eb7e9ff4226d1f7e78ec0d9959ac88b412f0dac7022ee9e036ce05f5a845c9c4711b4a7139"
    $a1="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
    $a2="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
    $a3="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="amFzcGVyYWRtaW4="
    $a1="Yml0bmFtaQ=="
    $a2="amFzcGVyYWRtaW4="
    $a3="amFzcGVyYWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

