/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ericsson
{
    meta:
        id = "6NUaDlYwStwUx1U98sfwDi"
        fingerprint = "ea6f4092e79af0ab541f93d453c5d54f386fe1afeddd007e6d37eb0469d96602"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="198d23ce47e7ab51349d595a24e451bb"
    $a1="198d23ce47e7ab51349d595a24e451bb"
    $a2="7d891ab402caf2e89ccdd33ed54333ac"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="0333c27eb4b9401d91fef02a9f74840e"
    $a5="1004f9d3cac7359299a976fd0fcef99c"
    $a6="5655c692e5c9b6ca60eb7d953cf8a921"
    $a7="5655c692e5c9b6ca60eb7d953cf8a921"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7dc3ee2d6b0f3b5a"
    $a1="7dc3ee2d6b0f3b5a"
    $a2="0a1838273cbc9961"
    $a3="43e9a4ab75570f5b"
    $a4="14e43c2d31dcbdd1"
    $a5="533bd8590690a0f1"
    $a6="2e12a3be3ee1107c"
    $a7="2e12a3be3ee1107c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*EA65B77CA9F825F8D7FCDF0D5AE96993216972C2"
    $a1="*EA65B77CA9F825F8D7FCDF0D5AE96993216972C2"
    $a2="*69156C3775BC63A03BDF56AD0B48E2BE5DF601DD"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*094B6D391FDDAA4DD6F16725D9E7E2B7E7BE81F7"
    $a5="*4C2D3F337EC616F0757FC3FB16A2793EBF1E949D"
    $a6="*751F84EF302237A40832D400DF60EB981B16541E"
    $a7="*751F84EF302237A40832D400DF60EB981B16541E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}DYUbGMExPHaycx+xvKU6+A=="
    $a1="{MD5}DYUbGMExPHaycx+xvKU6+A=="
    $a2="{MD5}wh+Wm18D0z1D4E+PE252gg=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}ZX+LjaYo74PPaRAbaBcVCg=="
    $a5="{MD5}aQkOGqj1OXq0G++QdIFsyA=="
    $a6="{MD5}ubg7rWvStPfEAQkwTPWA4Q=="
    $a7="{MD5}ubg7rWvStPfEAQkwTPWA4Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}OqJFYuXdvAL3NU0EzmjgmDyh73s="
    $a1="{SHA}OqJFYuXdvAL3NU0EzmjgmDyh73s="
    $a2="{SHA}dQXWSlTgYbes1UzNWLSdxDUAtjU="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}kgBezzeI+uqDRqeRn7oCMhiFYas="
    $a5="{SHA}GtaSKFdQtYttjhs6zftkmHS2ulA="
    $a6="{SHA}t4DSUqEsjEcgmcWJ1ymm1gon3Hs="
    $a7="{SHA}t4DSUqEsjEcgmcWJ1ymm1gon3Hs="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d851b18c1313c76b2731fb1bca53af8"
    $a1="0d851b18c1313c76b2731fb1bca53af8"
    $a2="c21f969b5f03d33d43e04f8f136e7682"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="657f8b8da628ef83cf69101b6817150a"
    $a5="69090e1aa8f5397ab41bef9074816cc8"
    $a6="b9b83bad6bd2b4f7c40109304cf580e1"
    $a7="b9b83bad6bd2b4f7c40109304cf580e1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3aa24562e5ddbc02f7354d04ce68e0983ca1ef7b"
    $a1="3aa24562e5ddbc02f7354d04ce68e0983ca1ef7b"
    $a2="7505d64a54e061b7acd54ccd58b49dc43500b635"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="92005ecf3788faea8346a7919fba0232188561ab"
    $a5="1ad692285750b58b6d8e1b3acdfb649874b6ba50"
    $a6="b780d252a12c8c472099c589d729a6d60a27dc7b"
    $a7="b780d252a12c8c472099c589d729a6d60a27dc7b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f89feea53b3d49c93be9bba04242fa183701f8dc45a96978254f1afead273efeb73c2acab0fdac339c281731894b2221"
    $a1="f89feea53b3d49c93be9bba04242fa183701f8dc45a96978254f1afead273efeb73c2acab0fdac339c281731894b2221"
    $a2="42f7113044c011e770740189f408d58fa50b795bd67a83a5dffe7b31a6463841de17df777ecbd9666ebb69e3a5be7d32"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="1e363b70c602295e1f204dadd818dd5f0706b6a5e6a47372f255ed6369a94962396774c254e720b007df320049e1ba9e"
    $a5="a8b4ba4b574d2d02119efe4adecb700911fa1e7a3c9e24b38c5495635a54d7fc92a1391b25caf622e6feb22fd2c1b932"
    $a6="e261dcccc9be0ef2af5803709466bd985ae371bc9b22fa5aad80f51a80bc627edc259ff738a025e9ac933681667a6529"
    $a7="e261dcccc9be0ef2af5803709466bd985ae371bc9b22fa5aad80f51a80bc627edc259ff738a025e9ac933681667a6529"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ffa2a1b27f9a7b2bccec3d0efc2b0bf25c178be55fb8b3fd93c8d77c"
    $a1="ffa2a1b27f9a7b2bccec3d0efc2b0bf25c178be55fb8b3fd93c8d77c"
    $a2="f0e8b3c2dda2512b55e4dc5d4859b1877e98109c7c4e755ccd2a5763"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="e9a17768d48637bcee3b5ce3ed21ccdb2c39c5d9b089444908208b2e"
    $a5="6cb0e3de5bf9bf402fd61c59da949ea0eb90e08c24c5da49878ffe43"
    $a6="e9e648bddc054e8643beb7194d056d9ff74dfabc2ec32376b8ba615a"
    $a7="e9e648bddc054e8643beb7194d056d9ff74dfabc2ec32376b8ba615a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9776ff6e746cc815066e024ad18130c1b9acf5d45c9afedabd831c0656a7011a103e2d9d659747456e62b6098205eed4cee616cb57122cf8a9e5eeee07d63fe8"
    $a1="9776ff6e746cc815066e024ad18130c1b9acf5d45c9afedabd831c0656a7011a103e2d9d659747456e62b6098205eed4cee616cb57122cf8a9e5eeee07d63fe8"
    $a2="1625cdb75d25d9f699fd2779f44095b6e320767f606f095eb7edab5581e9e3441adbb0d628832f7dc4574a77a382973ce22911b7e4df2a9d2c693826bbd125bc"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="5766d45bdba1152105abfd9662e551401a9756f1a37b3a3669ac590390479e9220591027098d61eff70ed6d0314d2cac7128f488df052ed7318ead76ba5f2f7b"
    $a5="4fd54a51b6680ee7cf925e084aa10576a46213cda660c2367898b31f545b2fb24b69dc7c4c7fc252d75a333e57a1432878641ff6ea0b8b0547cae85779a34e0e"
    $a6="585d09bbd0230435c6600fbc2f9858c6878b183b024f459c5e11f389106e835528423846ee0cfeab5ee870288bae56f2ff052a7942ddcb2ebfcb91e6664ac2bf"
    $a7="585d09bbd0230435c6600fbc2f9858c6878b183b024f459c5e11f389106e835528423846ee0cfeab5ee870288bae56f2ff052a7942ddcb2ebfcb91e6664ac2bf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f56e488201f458dcf845761b65ab0109015b569b5a5ac7809d6a2a9a0b62626"
    $a1="7f56e488201f458dcf845761b65ab0109015b569b5a5ac7809d6a2a9a0b62626"
    $a2="37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="106a5842fc5fce6f663176285ed1516dbb1e3d15c05abab12fdca46d60b539b7"
    $a5="2afbb1b55c6a2417ea3a1294bb7436009df69b1c112a6d06d381bda807ee05ff"
    $a6="c7d253870ab8de3825e3a9b5ee603e21abd0dfe62763e8e2fc1fc9f4684e8a19"
    $a7="c7d253870ab8de3825e3a9b5ee603e21abd0dfe62763e8e2fc1fc9f4684e8a19"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86dcb3b0f95abbda4b831c34271eee87f75b1ed628464796dfdca8c18edc44234119b734689182664206e4e34f1ed5483bb4a4c34cb3c7a8de709fef04cd26f0"
    $a1="86dcb3b0f95abbda4b831c34271eee87f75b1ed628464796dfdca8c18edc44234119b734689182664206e4e34f1ed5483bb4a4c34cb3c7a8de709fef04cd26f0"
    $a2="6a3712e2b92f69ead391b691710a587f21fae1e7b83b94b7835344eed1c463cfe03816e61922646f7aa0b581f3ba35842b12e556b2e4e0644c0f1d1d0549a79f"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="81f783b70f8bf5cb39bafba79d696a6dc531475f6ae1b8bb819f380c852b4a776db1cb84b217c41bfd844dce41cfb790e31a4b6e12a7c12b6efb5b29eddded62"
    $a5="87480ee4a7f233177b6100e39313a05bab24bb1f8e55dc238435f0552f8df680b2e1ddbc3c02c25666cb024e710effbabdd48497842e0cf8f43127484b88e1f8"
    $a6="e4fe8c2f97a24e355e600db1e13520c09c323ea214f544ff6f0f4023ebbcdd89c91740519f756c64ba094bb108b1d65183e34e24b585496c355f3aaa74574edc"
    $a7="e4fe8c2f97a24e355e600db1e13520c09c323ea214f544ff6f0f4023ebbcdd89c91740519f756c64ba094bb108b1d65183e34e24b585496c355f3aaa74574edc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c683866c00dc2ad95260337ef2b6c46b96f548fdbe2a59936535a7cb647ebd3e"
    $a1="c683866c00dc2ad95260337ef2b6c46b96f548fdbe2a59936535a7cb647ebd3e"
    $a2="4f38de7eea698e71df046d36abca9a5d7ce3f82f829f4b8c0f54a6334209985a"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="0b1eec1552ff1189863e2932eb76a3c3695836c36aaed8301037d8c79fdc8c03"
    $a5="8bd297185dc82427927739076bd1a19f6bc9d8a447f53813fb6e82bfaa53b65b"
    $a6="143b7b8209303b61211c12812a171db7a9934b8a81066e3d8d6e3f7e50010ec0"
    $a7="143b7b8209303b61211c12812a171db7a9934b8a81066e3d8d6e3f7e50010ec0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43de4e176bbd06c3f84e8ffa24abc2b9ccf619eec3f278b3aa85be77"
    $a1="43de4e176bbd06c3f84e8ffa24abc2b9ccf619eec3f278b3aa85be77"
    $a2="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="0b1efbd8a699a51ffe71726a2742d0b40d5c11855dbcaae37f5c104b"
    $a5="4de781bd81b0af5224b5f55613c4b309b479bbcd6318f6fdbbaa3457"
    $a6="f31ce4fb1e19793e94550cf556862f9fa446dbfcc835db2b461f0026"
    $a7="f31ce4fb1e19793e94550cf556862f9fa446dbfcc835db2b461f0026"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d235e963851a33d292c78aeee20bb9c80f4be6ee31b2e38fd8f77297e30bf13"
    $a1="4d235e963851a33d292c78aeee20bb9c80f4be6ee31b2e38fd8f77297e30bf13"
    $a2="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="1782ca260b116c2360821078875e766e03ba1cdb547381416e2fabe1c495804b"
    $a5="5e6196ecb5f28fa44aaf3d2fb0fbc1fdd0c6cd303603bdbb5abfa3e34a9755a5"
    $a6="c09d48b3d5671f93f6bbe8bb21f15e52ab4e3cd035574200694c965b64f75998"
    $a7="c09d48b3d5671f93f6bbe8bb21f15e52ab4e3cd035574200694c965b64f75998"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68c89b100df772d7806b9982b14678f8ca83f8ff0e17a6f95ab3bf3274564afad4fdb1378c80a48aeecb8131fbe89a24"
    $a1="68c89b100df772d7806b9982b14678f8ca83f8ff0e17a6f95ab3bf3274564afad4fdb1378c80a48aeecb8131fbe89a24"
    $a2="f437f71603b12fec1a4c1cdf46af48d0274fc3da86d451c00285697137cd82fb803b543f025e4d4549eb5efb514643c8"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="fbee00eab192ea52017accdefa65aa541c49bf1e5133d8ddea9f185e14cb17fe3ce3f725360a6a24b69fc6242f5073bd"
    $a5="e758cd128de8a0266eb9460c1a91f2046c454c37e47153a5b4f2d8717d287cf907890d82983817b7166ae4cd14ea014e"
    $a6="28066f4563d83e69c2809650f859ca2c6a97b97de635afda527e62ed8660201c6a3c3acd07505bf151da7402896ca1ff"
    $a7="28066f4563d83e69c2809650f859ca2c6a97b97de635afda527e62ed8660201c6a3c3acd07505bf151da7402896ca1ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f96b8c19c3e7f114833925bce79968bd9e75b8f15f3a6cd3858ceae6a97105fa0a22911ba45b9ab8cf840b447848e447a40c65a6b39457b979172633572b1ea0"
    $a1="f96b8c19c3e7f114833925bce79968bd9e75b8f15f3a6cd3858ceae6a97105fa0a22911ba45b9ab8cf840b447848e447a40c65a6b39457b979172633572b1ea0"
    $a2="fbaf1d3516e4849991e8eaa16e401a9d0cebad944297cd80022f9424c8d9d172f7cc94844f529cca51005498f56ca90672ca918cbbfc06c0071b9c12b98f89b6"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="dc2f4dabb854477fbedc841fa433e732db9309922075259d549ddcaa8df2c9421d55d154ebe9c3e65325a8524b7a823726da1d3020ae7477b30c787b707e8d31"
    $a5="65d69364a975c0a17dc28ac55ab29d2cc0b4cf0f013a993bcd9cfebffe3248077bc373763cf5de0a0467033f5a2e9da465e6792349abad8b20790708ef1298b9"
    $a6="5494b9ad0be108474a6dc8a92354ed94b0cf51c7092a28c7a201eaf94891d437a8638bba468c1b0ff625aa9b9e1415aed0943ce8c7be29a24511166b4a1dcec4"
    $a7="5494b9ad0be108474a6dc8a92354ed94b0cf51c7092a28c7a201eaf94891d437a8638bba468c1b0ff625aa9b9e1415aed0943ce8c7be29a24511166b4a1dcec4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bmV0bWFu"
    $a1="bmV0bWFu"
    $a2="YWRtaW4="
    $a3="ZGVmYXVsdA=="
    $a4="TUQxMTA="
    $a5="aGVscA=="
    $a6="ZXhwZXJ0"
    $a7="ZXhwZXJ0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

