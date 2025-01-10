/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_kostal_solar
{
    meta:
        id = "6pdAz3Vmt5J9A7QVEB1oln"
        fingerprint = "c5855591efa2e91f18afd47570b433a24db034d881420a67071362432621c305"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd76fc119d742c1822450137e16ff9fe"
    $a1="4b24e2c374bdffd2937a966ab96a293d"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5bbf68754b0ce953"
    $a1="2d2a01375f49a598"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4249733C474F9DB0B94CC9BFA18DE55E9A2C6D71"
    $a1="*6644131C64D18EE4646A477172703991C502E3B2"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Ydm9+knoixzWBMypmh77Pw=="
    $a1="{MD5}9jLNvgxLwA3t0+W/ssehlQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Mlkh13c3ePlnHcVaX4HP3zSbzws="
    $a1="{SHA}ZzZzqfet2LNos4HJHktH/i7QmmY="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61d9bdfa49e88b1cd604cca99a1efb3f"
    $a1="f632cdbe0c4bc00dedd3e5bfb2c7a195"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="325921d7773778f9671dc55a5f81cfdf349bcf0b"
    $a1="673673a9f7add8b368b381c91e4b47fe2ed09a66"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44063617e292c8cb2acaaf23ec2445cc97296504f822d7be1676289ded251e7a4b6f89d23995e9234e746b3804c95a34"
    $a1="2668e40017e0d4ce0a7e0ee0f5641f776431b05888d35f78a8583cc8be2c47c37f2488141bdbd5ad02550f718bc89041"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d4fc8435c5503ecbf47b558a3a24478da85362198e52e01c7a5fe4a"
    $a1="350ad7bd8406d1e7970ba86a036b4e531f9f4b1fcd5b7a1b19f8444e"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc93605408e390e4fa85253e2bce6e61157dfbbdaec277cc44a80ddaadae9ca16fd240000b3f830b808748cff8cfb16eaf7c1ee29f8589abb24d94232c7218f7"
    $a1="81d6668f1049d365d9b7b5db82e20231882afe5c999818df3496d4e2406bc5f631ffdb52b5e511b3578aeec7dfebb63d967e3c542f6ae9d29427014572a87de8"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e452b7ec586a404ef1b3099e5fa3c6f91f6d62cea0c3cde060e171ce1771e1a"
    $a1="f751c7bd7329bc2e7a2a98b6399405c009268135f4b50b6e12ff34e99d6dc52f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f165074883982251a573babc53e5bc88d06fc9d1d515f430f00156a82bebb05f260dff63b8569bf498a7ae658a511de6c32dc307466b5f7af8bc130c598f153"
    $a1="a29d22d088ee496d781f66b721cec6bbf515e9bedcd4126f9683944aa43f6d340c80de05723ae8f9684ec383ab7c22c469075b47b3c624e3af1514b879356348"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c64b3c58486b04fae5fcaf6e1b778068aefad832fd78bb0c36072cd8749147f6"
    $a1="6ec8b977025fe1b93e1da4986392adfb2ddac8925a7577b8644db3279c921fe9"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a8e2c9246402bf962c0dd96222ce4625758d9d1496517c939185ab7"
    $a1="91faafd9f960b27b0c1ec88fbfb843f62b10aeec511b4afa5c6ae97b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="850e92e0092a7b5ed8dca9a782d4fa027141dedd938d466527eea2f0c0c3bcc1"
    $a1="bb9ece380b6d7ce363f6a83281dfbcce44e2bd152d0a4a53b630960ec200d2fe"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c27913abeb6bac2904419cb815b21086a5e76a1a27fea0f6e803bba840b323239c0c5cbe7b82d20410fa78f29f9486a7"
    $a1="da2dccd348608668aeaf9a1906b002e98bf9e39f6fa63ad9997ff5e5f47e669b48c65ef22ea93ddb0adee8308804a1f4"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6934ad0a7fb61967d1e74352c50466f935ef8deeecd695f236a11602a118dcc7adf559af0af77525c08eee7d455a30e72f4b813d2e51bdee70735a4d2c5805ed"
    $a1="5e3990769f7e721b37ff5101c129ea64c34552b9a22ce9b63d933b22ce8d65a9a5725341e0f8bb0067b9815323237c4f7899b0e3533c1d5f79addd08130a46b7"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cHZzZXJ2ZXI="
    $a1="cHZ3cg=="
condition:
    ($a0 and $a1)
}

