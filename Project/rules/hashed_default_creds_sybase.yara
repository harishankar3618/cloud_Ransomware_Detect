/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_sybase
{
    meta:
        id = "3PQ1QsvmHprnI3eMOsWPEP"
        fingerprint = "8566c6173202c3b24d2528c954cefe0183a6cdc421ea2464f88534d063e2e109"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="96003623f29d9684e4c293c0cf97ee09"
    $a1="b10958a558a67f06d02340626b10fd89"
    $a2="9bd8519faf47c80f6c8b0e6a40088d00"
    $a3="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f3afd3626b27672"
    $a1="73be5857093f78f2"
    $a2="1514c2c22954d422"
    $a3="077ff75a4925858c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*75BCF5098AD176D126D5C54F0DF48EE336804B80"
    $a1="*A2C4E50EC242F588E79283A8422C3F8FAA61B11D"
    $a2="*E34D90F1EA7153F369DF97F544FAA0A54F27D7F0"
    $a3="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}l3iECgEAyzDJgodnQbC1og=="
    $a1="{MD5}esh+QtDijaZysK1ALPo5NA=="
    $a2="{MD5}U7dsw0RE9bCPmgozNDfjLQ=="
    $a3="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}IGTLZDyqjZ4d4S7qfz4UPKn4aA0="
    $a1="{SHA}Mknxp0kedQvmvDNAoBhudxHP1z8="
    $a2="{SHA}qwsiq0IcABRir0qfOC3JKEdHtD0="
    $a3="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9778840a0100cb30c982876741b0b5a2"
    $a1="7ac87e42d0e28da672b0ad402cfa3934"
    $a2="53b76cc34444f5b08f9a0a333437e32d"
    $a3="c12e01f2a13ff5587e1e9e4aedb8242d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2064cb643caa8d9e1de12eea7f3e143ca9f8680d"
    $a1="3249f1a7491e750be6bc3340a0186e7711cfd73f"
    $a2="ab0b22ab421c001462af4a9f382dc9284747b43d"
    $a3="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="521e2117c8323e893baa0ce500a513ba635ad96fe3156a317c77924723aaa5859debf6b6e69ba44b7a2ab4724091899d"
    $a1="439ece558fe24b03b63ce900cfb5e0bc894bfa395361307b42c94e8b1b03298cc60419aee4b09e0c128aec38638602bb"
    $a2="0bf3b54dc38a203d2213b18247a7b72c22aeb37c969207af6df6bc8dd7f08accb84fe98e32445cba70a2653c9f7fdba0"
    $a3="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="907a4949f53280718e350989d9ea03f7d3ca870f1dec9cbc40f3110f"
    $a1="f11aab589a3c3d46b38008381023298984bffe41cea7611bf8895058"
    $a2="02f771f74780e4827cfef89afd1497da13352697fa89b27db2238aca"
    $a3="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73461cc279e0e1b0d11ba54de652ccc047567f5380f6d6aa6f4f819aab92eaba19a7fda16ea0e6abd1dcd67d42b0928e2fe68a3fbe3afec7dbf325cab0abb364"
    $a1="528036fbe5a60298874181839fb37d70233dd65b8bb0761c7b0ce44242e0eb302a472cfceb5101b89487fcac90de294ea3f47893220d325bc293c46cd93d5796"
    $a2="86fb3bdfd18c375e452153b46e6ae45bb1e96aae0bca4ff19adc93f474c85f6cb6cd8f184fbfaac56e00df0d7cd480998959769aa0c206227254b62b1f29fca8"
    $a3="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7056a455639d1c7deec82ee787db24a0c1878e2792b4597709f0facf7cc7b35"
    $a1="664acdf6ca619f7e9dfcfb667586997040abbba480ef555b2e79a6a9674bca7c"
    $a2="3b3927e40c6e2d6dcd4ae074e706611c76b920cd6cfbd0031e70c13029a0c7d1"
    $a3="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e61c67977e90d04fc2ba0130a3a1ece4b4509afdfa9e58ad706382cc2ec1a94b64d014fce3c06f193bd983afbd2247034627d6c064762b30b983a52e7a4945a"
    $a1="2a4e20a06c9af62af6ea2eb6b070193672690016d0554d0479f0ffc0fd277bedf257618320e3c7af3d8bea6e0cd5d554c9c6bca7c7e05fa09b0bdf7f6cc72d90"
    $a2="8187cf141f305d411400cdcea12f9f947260cdf5e342a8cd2a31386b2bf30a4d4dcb96874a528ef7d010a3e9ba4f0f1e95d7b6e81d967a6c4d763dbf36d7e11e"
    $a3="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f645ae114819272a88025c3b85c285eecd80d45302d8125fd1e27a7c90f84fd7"
    $a1="97da8c4c23c3c98b0495850e1a2d831648deccfadcb9897cf0a7d9da1bee7004"
    $a2="296a10c1711fe7f1786f3fae5fe592a6f6d2eadbed291c7d26e516f2e6b70532"
    $a3="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb3a50b379597148370a08cc0ce1c02cde17b138dfc52a118b1ac4f5"
    $a1="897696d9785a5efa0daa10288d85ed8ccd3314f7cb4efba4f4ca2055"
    $a2="d6af525f61d62899149d0730cec3b754fcf4ca9e1ebf013dc1dbe920"
    $a3="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bea26a68f1c3a2276e3e88002800cc5d269598edf4d618c89e3facedf6792158"
    $a1="8224866b82c8e5bd61873936dd988b02878f819d4d891a8b8325e5ee97940ece"
    $a2="a381c0e0dbbe117c6ae87d9ddebba0f126acd395cee9ad6e7e31f96920f1f458"
    $a3="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12352f148b962be3405fdc721550dd617e9d3b97b038ea6f0219df002dbfed2a1e83842d6b7b2c426589cf3699f5ab55"
    $a1="2e88d0c3103abe99dbb748ae1cd719c2a1df734494a398e6284de4a497fd60774b16deddb0b6e1a36f5c715cbdd275c9"
    $a2="05488b0218445ecb3d45325f70fa27c4867f71a78236deae14a4299a082ba67de1d52dfa2c59cb227e1ed16f29b65e8a"
    $a3="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b2aa94b914d29b3c350ba58b4bc7108f8169dbf26309ac5ddd439421803a5bfe26a9665fce60fdc20348a2348d86a909eaa9d6921a9bc6c9daa8b6a4433e68c"
    $a1="2b165fb340db361f9351ec845a3824bb58317f65fa91dc6070e89400520e3daa20b0db0627f67847b3da532c4cbe04ca63900de44d384d1f90c15ace0bec73b1"
    $a2="95f5013b88e0c0e71f9741e05a0973e852ca28770c3ed813f7edd7f8583add711442ffa2451cb90a468aeef0502a77828417225a758a3f4701e6502c8d450a58"
    $a3="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="REJB"
    $a1="U1FM"
    $a2="c2E="
    $a3="c2FzYXNh"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

