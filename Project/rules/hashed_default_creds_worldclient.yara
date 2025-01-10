/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_worldclient
{
    meta:
        id = "7DeyGaGr9eWrZGvpFRk0cJ"
        fingerprint = "05d0f2008f3997cef0c9dd7202c5b06e580d05d6c4e2991ed7389550a0846d7e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a25b2710ba9de114396adc7dfb0a7235"
    $a1="af62387d97bc187df65ba77fa0d55881"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4077eb0b03ddce3b"
    $a1="663a338900aece54"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*D89A99106002D77C1D327FC41E005919505638B0"
    $a1="*AC2EDF6AE3017AA35C7234A7402FEB37E7AFB161"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a1="{MD5}ioNRW/u5RT7cEUiHAd6YZg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a1="{SHA}MYOkLzFSlSJkGyKW4j6oVyOvqLo="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e3afed0047b08059d0fada10f400c1e5"
    $a1="8a83515bfbb9453edc11488701de9866"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a1="3183a42f31529522641b2296e23ea85723afa8ba"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a1="a62b2dab63428f6f0a7afb10c6c313b1b60efcd904128e4e57e90d142dafef00187676b61d93436975f7d3897e5b1548"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a1="e22929f28f6ce70e23d311460c058c08b89e4a365a44ecb5d82cb384"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a1="401ea91dcbd27df1131a68e94457b637be81684d124798b89af3fc36bfb06651d051c970bc28f66abe58045f92c7b4301d52306c47914a646eb71c04a2a3438a"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a1="fa51b6b0d572174d84022a102cc04d0ffd92843b624564f583dea799199dada1"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a1="4ad550e8678f077e4b1e428b78898797f8170e8c08d5bbc7b56c96418ffbc127b3dadff9a96eaaaa3bdad17979a007f32880c9132118570edc2832853cd3f1a3"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a1="fc7efdc12ef525ef72e85353bd9724a32c2cd23c170e6dbf78d1c2ea61f05cbf"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a1="46f7e0b16158bd520e253f7bd4025d79c1b3b8108fcc5d4293995d95"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a1="765c936570c3b52588a1bb55b66384f51a938825183c15b21a3323581f301771"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a1="ffdac43a0d42b96c9c21cdc7d3305f26ff0d397e29ee6c88cb4f4531ed7c6809cf5ddfdb01b0a334dd0360db73242564"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a1="9a6da13771937cc2a8c3d3cec5b5829c6b063404c12735805d5ea48d2ae818ca61d665b0cac0083e928de62eb5059709b03240c5cefc49222f5483c3c7ba3f1f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_worldclient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="V2ViQWRtaW4="
    $a1="QWRtaW4="
condition:
    ($a0 and $a1)
}

