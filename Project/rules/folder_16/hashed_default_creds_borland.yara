/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_borland
{
    meta:
        id = "4sdqG3RFL09dMUza6X2PVo"
        fingerprint = "2e0480135a267e188cee11f458730143b8f54123833e8d2a6f1c8b142cbc16eb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47f0f9abb19d8ccdb540fa9408fcd7fa"
    $a1="aaad087a8066ec7ecbd0f95514d443f4"
    $a2="47f0f9abb19d8ccdb540fa9408fcd7fa"
    $a3="9728a458444cfd9e0d68ee855fa8aa33"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="358dd0ec65ddd485"
    $a1="6e03baa711e6b386"
    $a2="358dd0ec65ddd485"
    $a3="2add73e42f57493e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5A5B36727E0D98B09E6500A114D733774A49B2CC"
    $a1="*0F8480A9AA9FEDC3612024057AC37A9B80B69B9D"
    $a2="*5A5B36727E0D98B09E6500A114D733774A49B2CC"
    $a3="*84A747E1D08F0AFA1065D999F283522B1025DC2F"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}5dfP/iVlT346HjNBGMcVSQ=="
    $a1="{MD5}APzbkx1P/n/kT7MGFxv+BA=="
    $a2="{MD5}5dfP/iVlT346HjNBGMcVSQ=="
    $a3="{MD5}mX6i3qSFJKxjDkzgOFJk0Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}MXmmXv8lI7veU8mbKZtxnBCjUjU="
    $a1="{SHA}Tj4FJZqym2w36YOnPJm/h02izZo="
    $a2="{SHA}MXmmXv8lI7veU8mbKZtxnBCjUjU="
    $a3="{SHA}BqFO0ckYkBX3XdeWBjNN6pZQoRY="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5d7cffe25654f7e3a1e334118c71549"
    $a1="00fcdb931d4ffe7fe44fb306171bfe04"
    $a2="e5d7cffe25654f7e3a1e334118c71549"
    $a3="997ea2dea48524ac630e4ce0385264d1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3179a65eff2523bbde53c99b299b719c10a35235"
    $a1="4e3e05259ab29b6c37e983a73c99bf874da2cd9a"
    $a2="3179a65eff2523bbde53c99b299b719c10a35235"
    $a3="06a14ed1c9189015f75dd79606334dea9650a116"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7e865b61d14ade6769055a3d265f370237790dd8b1f9f6a5f18fe142e539c48b4700f8ceec2c5b3988b232722d1053c"
    $a1="86bbe6ff9f2c4d98744746c5fcafec418c49a6022551dc86aafd1a2fc55b390b4f4464fc872d28c58a2ecaeb6f7acb8e"
    $a2="b7e865b61d14ade6769055a3d265f370237790dd8b1f9f6a5f18fe142e539c48b4700f8ceec2c5b3988b232722d1053c"
    $a3="dac3eb87aa375e3108383ea7efdaf95e662c44312cb0d5d9f3d0a4ee26c53a9b41126c9e510523edf29ab1635c74fe71"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6af85219ad38647ef723dffa2d25e904612e806151eb9f52870c4bff"
    $a1="a5714cb7afa4506a24f05e4d89f5301ba32e2ed0633c1b4363b45546"
    $a2="6af85219ad38647ef723dffa2d25e904612e806151eb9f52870c4bff"
    $a3="4eab176394a6bfefc9fdf817b0168476fbca31c251cd610ce40dea0e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3fbebc93b9758faa9d46724d4e2b4de2be95aae02fc51f2013a3e987719039ec5a0d6fd50fa2ce83671db46e7c5d6f2509ea708ef11bc3413a917d935fdc30e7"
    $a1="d2250b03eec37b0a31905b48f96e18fde8c50ecda5aeb2effb782619d7900068c661672367b6a0d7c2a046ce91c45210a851d972c3ba41bd6bea749ca406f39f"
    $a2="3fbebc93b9758faa9d46724d4e2b4de2be95aae02fc51f2013a3e987719039ec5a0d6fd50fa2ce83671db46e7c5d6f2509ea708ef11bc3413a917d935fdc30e7"
    $a3="4f533f805800876727fb2ce5273f3d0400ffc937cf421ded43a84857c978874873cd7b5b9c94f55a92311fd89dd44958155443e5956c322302a62c1ed1e88106"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15a596e3c98c407e043751ff3b21ff0358a1bdfdf3fe948b1523893a8e5de2e8"
    $a1="5f2c4152d00cac63465da6225818c6ba60f7ede77c0e759f16f1eb4eec5927ba"
    $a2="15a596e3c98c407e043751ff3b21ff0358a1bdfdf3fe948b1523893a8e5de2e8"
    $a3="b9fcc14006622476f1840fde6bf0eec264761d0536f287278755254e76a78061"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc060574f55a849c98a530babd7cf605d4efbba9bae2357cef498295f5e2936d5c6ca8fedc3ace3cea70a1b6479a8dc7153d4acb1035cdf409f8c70a6ebc60f5"
    $a1="26e0e8245915ed5eb4832976c444c3dfe51302b94672a0199c0bb62f3b66cef6bda064ec6c71dbe0116a30ee48d580eea600b795ded11ece4faaeefa2ad516ad"
    $a2="fc060574f55a849c98a530babd7cf605d4efbba9bae2357cef498295f5e2936d5c6ca8fedc3ace3cea70a1b6479a8dc7153d4acb1035cdf409f8c70a6ebc60f5"
    $a3="01f3a87debcac43d202623639ca66fe3c9c4350104913e3dc7a714be3f8be6ffb7795b1d57fe8206e37fb927f3940c343a10fac2a758719f33c28d0fb270cce6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1017d3fe213d3780bc6515975cd30f1b6cbd03126ac536825b680bd10e198895"
    $a1="b523f9b34e8f40db48650cd29c5da32744d5a6ec9572ef8205fcbcea6bc09bd5"
    $a2="1017d3fe213d3780bc6515975cd30f1b6cbd03126ac536825b680bd10e198895"
    $a3="133fa988725e5b6a1631e8e4244a70f8239138a76449723bedc1f54945cb0d49"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f4c5d5cc94bf3c575ce0591c10afdb793d2bcef8f549ecf1331c24fa"
    $a1="fbb6e56767a076fe0bee77533eac6860e3150c9bae0b42de1f077498"
    $a2="f4c5d5cc94bf3c575ce0591c10afdb793d2bcef8f549ecf1331c24fa"
    $a3="4e1c1e4708158e40de34275fe8ff608c7e3c9831bd9e46d055e34110"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="167756ce76155ba4faace485d41b8b75a8f066bd52394ef7bb27d90242539070"
    $a1="27562d35e43d38adc4e02313fa9982843efeed6e164843d44b1eeddb9ace7326"
    $a2="167756ce76155ba4faace485d41b8b75a8f066bd52394ef7bb27d90242539070"
    $a3="f75b9a62c123b47c2475bce3e47b1ade855fdf8238f016556e672bf8761c449c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5587ca6458c64e735493d8d2af1f62ef95dc46584c4ee6120514e996d3b71bad7eb2b3a322fe26c697eb3f3ed7e8d14b"
    $a1="ae2791a1f954f75280b93e43fabfdc0c22169eb4a4f014041bf99be1f6f45c63883c2bfc4c5b00d9d77d9e343cbcdc91"
    $a2="5587ca6458c64e735493d8d2af1f62ef95dc46584c4ee6120514e996d3b71bad7eb2b3a322fe26c697eb3f3ed7e8d14b"
    $a3="1aea2a317b8ba3bc432ad63c4896c06ed6560e171d83aec1a548bc2ba34009d48021474c3258535e52fb2c266af2940a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="77e64e949250e89a050152df260cbcdbb1cd22e506ca27554f7dd4e9dd96a1dc8d90dbe860789f2507ec403733ad8824038570efe2a445e59e6b9e2f0dcd8c2e"
    $a1="a14165b41dccd687eb18ed144307694bbc4e01af9693fc86dc0ab518a1292ae9180e063dbc78bd8a86e5054b4aea70ea2765215bdcdddbf9eaf688f78d664fe0"
    $a2="77e64e949250e89a050152df260cbcdbb1cd22e506ca27554f7dd4e9dd96a1dc8d90dbe860789f2507ec403733ad8824038570efe2a445e59e6b9e2f0dcd8c2e"
    $a3="7e3f9f76b6fad4c9905cdebaf93f24de322c172522f319ab011280f583ebaeccf2ddafb94db361519ef649a562e4d767f8c9701476f306428eae804fe526beb9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cG9saXRjYWxseQ=="
    $a1="Y29ycmVjdA=="
    $a2="cG9saXRpY2FsbHk="
    $a3="Y29ycmVjdA=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

