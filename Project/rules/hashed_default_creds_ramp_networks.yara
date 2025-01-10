/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_ramp_networks
{
    meta:
        id = "6aYGPGmUcBzvmlYzZ2EpK"
        fingerprint = "0a6fafb36d4aac6490e5669ab1a7066b4b786a5566b82a83e38f58d4c0801bcb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ccf0e02493b091bd69dafa58f082a35"
    $a1="e8e7289454393110d7d4bc415fd463f4"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4725485f3a1dc1b2"
    $a1="38112bfc1812ac9c"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*344C7C92E4C56FD1240390C67BC3082FBC3A2D71"
    $a1="*B25A8734335D2A61C756022889434327771F0299"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}4loTU1xoaqPzQNiKtOeoPA=="
    $a1="{MD5}mV8FlMxpdYWnwasm7z2pXQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}N1ixSIzQPVTptux/M3yFY1821M0="
    $a1="{SHA}lAeH7MoeRxAFl3Smu9zQj7ZrECk="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e25a13535c686aa3f340d88ab4e7a83c"
    $a1="995f0594cc697585a7c1ab26ef3da95d"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3758b1488cd03d54e9b6ec7f337c85635f36d4cd"
    $a1="940787ecca1e4710059774a6bbdcd08fb66b1029"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26444fe9e22e265a60f8ae1391c12a950221f2bfaad5a66afd93e3b24cc942993ded029bbd7375c9820fec9b461855c7"
    $a1="2af7729a74903f5d215037340f165366cdfe763e931e302985f27e8daf24bcbb4f77627cfdcd7d3980de34dd5ea2479c"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68a2abc62150102cd4275706bbfeb64fb61ff0fb35e934791ecedf20"
    $a1="9ee1fc2d590a7ddffc1f0f7c2d1c4e77e07715243f38f9c0b317b810"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1bfdf7251f58046b93d7e60c65f2bfa54fba4d38b18a2c2fda808eedb97e9b378bd6e30af013ee8c584dac979668ef907d5baab20fb88f8d5f5de05b964d878f"
    $a1="6edd25e9d6ce452871d813f690c368689b3a752f349084e9ff778cf6cb3cab09aae11fac90c437a07515bb2e8f635eb0a1b1dc1f19f1a43e3122181e776577fa"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66331a930574620b03aa9936ad5b07db7e90d653c8d5fca2fc6e1480fc1c721f"
    $a1="cf438659125ea1c48ac48d96977cb371c6b81434247cf2aff89d6d0b2be5033c"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40949a4fb7ddf6b9f771ccc195bbe43c93947faa5eee0bfefba906dc03214dbc6eade1b353dd32892cd8df932d6edeba58b745e6cf5c0faad584b6d59f8215bc"
    $a1="f75320240f9b38a2a669e483b60eecbcab967954e81dda3ac41980def81021e998bce6d8c48442b41e56ad61ac077adc58d816be6af73f93c8a6834cc92ed2ac"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4148d74dcbfb2aafda9d5de6d28c3dab08c292f4462aaeb18876f6c6eeb6096"
    $a1="1be1829c5c6c832651cc519b9b1063c1a0af837f094ba6423b1bcb62494a4b4a"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80782e138450cff5f0eb06091957d6d3ecc81f3a391d0be77028f0c6"
    $a1="748ba8e5f604c11ec9c165103584328b3196753804e8f644bfeb684f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37c736b8de3c656e78fa400f46627e72ec44e642f99045216fdaca80329ba163"
    $a1="30fdc4981c34bdeab92ab8ed80b598f19ffd964f49a2edeb0603d2df2285647c"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af49a390faf8c3d40e73a61d894a97d41a7d29e10d5e376d848cdd825a16b065504a3974900c189d4d4170b3d64cf161"
    $a1="bdb5fb19247d8419edaf730b1f6733bb17280c794449285e55d7d5d539b38b3dd427451fa52b9028b1f8119674d31794"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c9a1c3bb8d407b9f37f5a7a855914aa34b7af09ac0f66df7739a8cb07b9234fcbca89ad36804b270a76a09c3a929dc2ed852e4a30d95722e5cf5055d5e32874"
    $a1="ba3460952aa6083903cb2cfd03d005fd3dda1e74b26893e214e9aff6148beb61b294c1399a751c59136b3d467aa60fbcf7a276944362ff760edf525dfbbc47c0"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d3JhZG1pbg=="
    $a1="dHJhbmNlbGw="
condition:
    ($a0 and $a1)
}

