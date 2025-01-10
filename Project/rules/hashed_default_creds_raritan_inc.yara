/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_raritan_inc
{
    meta:
        id = "1gWc7apiEHmSYr4ZvHFqeo"
        fingerprint = "bd9ac49039f79adeeb8b7840e11ab5d6adfcfd93f2e24778629fe415b38d3841"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8749288952ede39aa677d5eecd6145a7"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8749288952ede39aa677d5eecd6145a7"
    $a3="837320dd341ee09fd9b952e4e33b35f6"
    $a4="b75d67d5262c636a684977b47a9d991e"
    $a5="cb9765b786722cdab4b7df7e4a42f04c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ca052e32963bcfa"
    $a1="43e9a4ab75570f5b"
    $a2="6ca052e32963bcfa"
    $a3="64114f66164c1a64"
    $a4="5193c212068240f0"
    $a5="482165255b529f94"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*80515436B847E9D9A263148CDC1362D484E93DBB"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*80515436B847E9D9A263148CDC1362D484E93DBB"
    $a3="*42710275B0BF9F0CDFD3947DDF9D0278E913A53F"
    $a4="*6244517EAB99157322B5B9C3EBBB4307D8659471"
    $a5="*9D087988F4F0B6B6D2863A23E54B388621DE8944"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ipE6QEP9vsdW779R2U5MyQ=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}ipE6QEP9vsdW779R2U5MyQ=="
    $a3="{MD5}QESNt1EP/7bi/naR9fuRtg=="
    $a4="{MD5}+6Dc72H70CaC3wlv0J7Zcg=="
    $a5="{MD5}e5jTXEF08d44lUKHjRBCfQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nNtkqxHQ/bMRFpFzySAXZpVW714="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}nNtkqxHQ/bMRFpFzySAXZpVW714="
    $a3="{SHA}infhsSGiZILbkOeHVwTVaKi7y4M="
    $a4="{SHA}MKXYBzEivg/Ys3pvsG63NHXlAmA="
    $a5="{SHA}Z3G5Kw4Gir8oXvxoEBF/c8CxU2c="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8a913a4043fdbec756efbf51d94e4cc9"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="8a913a4043fdbec756efbf51d94e4cc9"
    $a3="40448db7510fffb6e2fe7691f5fb91b6"
    $a4="fba0dcef61fbd02682df096fd09ed972"
    $a5="7b98d35c4174f1de389542878d10427d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9cdb64ab11d0fdb311169173c92017669556ef5e"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="9cdb64ab11d0fdb311169173c92017669556ef5e"
    $a3="8a77e1b121a26482db90e7875704d568a8bbcb83"
    $a4="30a5d8073122be0fd8b37a6fb06eb73475e50260"
    $a5="6771b92b0e068abf285efc6810117f73c0b15367"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5cb8c6846552673518ae8b78a4950c43a406b7c2208bd2e7f917f444cb5f931b81e255141ae1ef624a96d0bbcd0dc4c7"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="5cb8c6846552673518ae8b78a4950c43a406b7c2208bd2e7f917f444cb5f931b81e255141ae1ef624a96d0bbcd0dc4c7"
    $a3="1f453021f42ec182912866f62259ff70a4d8cebdf97ab03f8002e3871fa14f1675bb979183789815b6794a51b4eb616d"
    $a4="4fe7ac3fdef604776dcbea0e93407236be27a4ad56dc570bc145c640c7bf6900acbee0630f2edf3f15b4133b3bbf304b"
    $a5="84d8cd8acbcd91f836a3d440ab3edab80eb202c58af43514ddcde5a184c31e2c9886902567187645fd950d1a479bf6a5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bef8463d6d042e951dae3906ec0cd092029223b073b8634b64d0783f"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="bef8463d6d042e951dae3906ec0cd092029223b073b8634b64d0783f"
    $a3="1d7f29bd053ea244cb4c39d4b4758d68868e7fe0d5031c3202b30b4b"
    $a4="2273f31a2ce0171d91a63943138149edcb17ee3f9bf248398506b7ee"
    $a5="a9e31f5c79585cc6de4f60c1658af408180f23e41cf4a2f1c4b9d0a3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8f8e7789282abaf2e2af29ef7316b1a9881cfde07fd929f22227fcfccc48bbdd88d5881a41057fdb4dced0c6d349780ea7dadc0d0444c49681f0422fac51a23"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="f8f8e7789282abaf2e2af29ef7316b1a9881cfde07fd929f22227fcfccc48bbdd88d5881a41057fdb4dced0c6d349780ea7dadc0d0444c49681f0422fac51a23"
    $a3="e84b372bbef62b552b98b7d54c7339841e2bf687a7cabefc8c76205da7f2dda67cfdbc3776d80224ea38825aa501b5bf88d05075e8b5441e62220c013463fbbc"
    $a4="4a3103085e438b82cc2d7bee8abe9a7a15964051386bbd06f5187d562e98f2255c870f400ff1a47f7621c23bfb8b3dd67f069b11cec8c3fdf5ef48e2d5010c84"
    $a5="d005ba24545146557756c648a09c16305b59a65fa091da96e856ebc8800b0ddf3cf14cbe1871a3b2f1ea8e7c6fbe0d015de6fc3961a18b39a328934f0fc6a7d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e35bd923db41777ba04b35a60180face8ae9980185bb1c20f769252d435cb89e"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="e35bd923db41777ba04b35a60180face8ae9980185bb1c20f769252d435cb89e"
    $a3="9a59f8de5c30f0b090106ddd0b380079180ffe58e76555e7e00b896157538c51"
    $a4="2fee81287225ebdaf3e72b1f8653be61698d05852741ce8614f88ee06c006bb0"
    $a5="70f1e97bc20f97d4a3c23722c7d0499d301afecf0c91273f8842bc8d682fab00"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="281b1e56e41aec067aaf5e8fe63a06a71d673d45fb5a5f1a86c334fd00b5c136ff7f96e67d1c89e7e952e5f4f8f8b5bc56503ca166fe80746c0a40ab1785e309"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="281b1e56e41aec067aaf5e8fe63a06a71d673d45fb5a5f1a86c334fd00b5c136ff7f96e67d1c89e7e952e5f4f8f8b5bc56503ca166fe80746c0a40ab1785e309"
    $a3="9c93ecfc807036a405c19a47d90313c1557ad1c5da76ec4744fbde445292d4488693462ccc2465501af28406db8ea6922a2257f6e5c0a14b6cfa39cafaef8feb"
    $a4="028b2f6a7c2584fe1541d4b14fe089bfea7813546753b81451dcd03bf0df8e2e00309c539bd357f5b1e67b963388d0c3662f23232e8945e1a55d6c87b8eca2ae"
    $a5="38db7ea89709383c6a76ab6c282bcb0d0aaec8be35a1f3842fb78e9081f7b4c1b34e3ea123286030575eab30004b10675a987660ff66d757b91a88b0ab292aa3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81f91510b3839c8485ec17d96c4ce9ea9a413bcce1aa40553d82b6cde7838b26"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="81f91510b3839c8485ec17d96c4ce9ea9a413bcce1aa40553d82b6cde7838b26"
    $a3="79555e7ca8c9f0ed3121c18141958523018e9a3515cf7d495c8527911e638eff"
    $a4="798109f4ea6168c47c6f1c57367b403356f64f4b10d13adf2f259f5d5b464957"
    $a5="f0640d2dcbf0ad5cb64e48724abb1c0d0ff2ce6a6bc767be8541257d71697663"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10e7a0882a9b9d786c626098121b1456abfa6df5d7fbdf2efd864f7f"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="10e7a0882a9b9d786c626098121b1456abfa6df5d7fbdf2efd864f7f"
    $a3="584206febaa19efc32de0293b59f0427953405f7465ef0536bb42c1c"
    $a4="6757b05b886d0e0d6fbc5fb63436a8109a68aea24996fc99d27c4d2f"
    $a5="e949436b4c6b5b92db66d8b2c70750ebf1f84ca1e7d5cc2c4a6712ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea4924c8a593b7b108fb0504ad8fc158a426a954504621da8426fc0999cea173"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="ea4924c8a593b7b108fb0504ad8fc158a426a954504621da8426fc0999cea173"
    $a3="9d1c35af18eefeab7224f81320cb7fe2135b6bb21851876a2806cdf65c5d074a"
    $a4="e9f06df6fee11b6dea41c31259d3595441905c185999c1d6f14a003a78ef3a77"
    $a5="54bbd8d043c2f16607ee065e62e5f6158d12ed55991fd33e6573f4022c269e31"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23aad933df4b3fa35477fe3eb824281ebe623c2bbb526a156ef17d235ddd38b8fc23e9adcba6a31b14fc623ae3e2219d"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="23aad933df4b3fa35477fe3eb824281ebe623c2bbb526a156ef17d235ddd38b8fc23e9adcba6a31b14fc623ae3e2219d"
    $a3="f31681e64e051c1505b9cfbe4bf37f01bcc36d7932b568b3a4105cb05aa8b8104769a048ad1f5e7271a24822fc2f3c25"
    $a4="80a47d0fb171ae6d635f79c29a4468941cfcd6a902b1cfd22a608965ab5b4a726280e1983096f90dafafd549ea38eb9e"
    $a5="7fcdac8be28ccbff986903ba79f3afa3bb981f8dd1aa64c977cb6aaa2fb13c26d055c5849de2e99e36a033eeb0f5c24c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61098a6dbe7a295c9189dbf9c9f7ecdedd6e956ddef82665be76ed0667d0fd1515c0e6b6c9e58977529620971a9f85dce5bc35daa815e776a6014e534ab01425"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="61098a6dbe7a295c9189dbf9c9f7ecdedd6e956ddef82665be76ed0667d0fd1515c0e6b6c9e58977529620971a9f85dce5bc35daa815e776a6014e534ab01425"
    $a3="3a2079e49f06fc48a28bb1f133c15d34f9e8e38138ebfe24173a70ffb2617b0649b4f77ae6ef5c2ea8c0f89e5d6a5f92a9b285608bb49efc1e7571db5e46e45e"
    $a4="649c3606bd57ca8ff7cdeabf3a0c6377fa08ff31cc5eef953602f76f4f63a5a145f5996ee3f197746e2d26e3729047a9104f35a0973f3c15ebb4a7703882c109"
    $a5="d82f2a6fe4ed94b3654417f8b07149e0602f1a7ee82c15d9ce0e90c73409b2c42de74783a6c66b4ddcb9ac4ac47ee218e9d151c24dd383fc056003389c9bcc91"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="cmFyaXRhbg=="
    $a2="ZXBpcV9hcGk="
    $a3="cmFyaXRhbg=="
    $a4="d2ViX2FwaQ=="
    $a5="c2wzM3AzMEYwMGR1bWFzcyE="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

