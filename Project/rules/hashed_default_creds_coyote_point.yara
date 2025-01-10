/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_coyote_point
{
    meta:
        id = "57djTDECNw8qlTYxzdg48"
        fingerprint = "d02f09ea4a28ba3901c8edbe3ac077710a309b1166839b82cfbe142e43f3f66e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5f3bcdcddbe2441402dedcfafb78d00"
    $a1="9d4bba55537c63b5202dc974f798ec4e"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50b2078c1fbab429"
    $a1="149fe1b1457b4736"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E4A5CDFC1C2E38B6B6CC2731575EB320A6B4B81F"
    $a1="*93DF452196B964760311049897830D31A0165A84"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ebEA6LTAyNSq9yMkO0/P8A=="
    $a1="{MD5}PfENS7KTI++PMRp6ZUKDHQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}KCfA1k3rWUUYYQA8WyytTlwpprk="
    $a1="{SHA}HxkaUlRsZSYFAHH0zwM7t07VF6k="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="79b100e8b4c0c8d4aaf723243b4fcff0"
    $a1="3df10d4bb29323ef8f311a7a6542831d"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2827c0d64deb59451861003c5b2cad4e5c29a6b9"
    $a1="1f191a52546c6526050071f4cf033bb74ed517a9"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afa27ea8161475649d5273a7929f1d3477933c2e028da1c97156c5395cef2def92506565edb7bf8fd61572a2b68318f6"
    $a1="a9d41a93843c5be214435e7e9b5bb68cb1008abd1349fe7aa67e0a5542909a16692833b741851efd00e0345c751a73f5"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56e08e7fb1cf22cf601e8c8a7dca089a6e55138065cf6b280623ec2a"
    $a1="90041d1aeb695390786fd197932cfef8aee05d0b6c01ef57aa8a77d4"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2cae3cff3a4fd172c2ce46c32e90ddc04e8d16dd44dea71ef96ee980d899ef0b3d664142c7a9620949d5510e91b6fea4f7b4f2634f046893319b9720ea38d152"
    $a1="ace0d6400bf7feee4e0a2a0d60dea2585bef845ed948ab153dd54de0433406c4f36e26e627cd3c3b790908bfd879f31a92a8723b0b416326f017e9ebeaddbd7c"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abfb836eacc005c2485b31ba949c995ca5a6bb7ffdef5af67bab924e2fe65873"
    $a1="f8180097071393c1ec63982a1c5442978e003d4812e77b2b0b50f56dd27ee672"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="986dea7b25676a9f428dfb2ad7b34159afca8f57ffe66574e030d36157b4386157eb98cf0314d69b34d3a90a0a13fe770d3f3eb0e990d62712540fd9521218a4"
    $a1="02d3f65c4651ded83a3aabe0c50bcaaa2b4cd04c092bc4bf939f77add5ef0c6a2a93d53aa2d04e63d1242113e91a25abdbfcb6f515c21374b6383560a9be6e60"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18c2d0d6f5c30c2e025d136c68db5b92cd5cd4a5d9b40d4a4645da448410d41b"
    $a1="5d719fdff7350eac86c95884a76e7082a8785bbd5014118bbcb87adfc9756daa"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="964856230ff68101a4bef54f1f1645438f9195f3b0664b2ebfdd0172"
    $a1="3c668c1a78c184ca8ece7c7a70f9632a75e7709e20fd735859ccd136"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28e07df0e9f653279d31423f050874fae0e43e262e8ba6e31ce191f0a29e9b02"
    $a1="a2295409551cd5b997929fa15de81b5c46d24778d7d47fddf78d1619895a94f2"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13f6fa73062634737a3cd2602dc784beea9ba31c0b7f72a0f8ccb4c5adfd211cd983c5b7542a1c715fecaff0e8291c5b"
    $a1="e662e82f18d6d31ad1835f48cc98f4245688735c8ebf3930af6faa186550d24a2845865836e8d9a5260fb8a47be6f4dc"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23ec62c75dcb6d11ed28236cad8ed6fa83081d378fca9c7cb1ca0dc0370960f1f40f00fbde61c89ffeb56d3b912be45246199613989eb5e9f77172ec58870d63"
    $a1="f7e0699f92fb0453618922b080c55e79a5d8ec453eb787ba2c573ccfe6bbfc329cf67e384f43dc73a469bd336f26e55d1634b98ac9253653b86e6148a2ff273f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZXFhZG1pbg=="
    $a1="ZXF1YWxpemVy"
condition:
    ($a0 and $a1)
}

