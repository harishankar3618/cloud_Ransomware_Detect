/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_zabbix_llc
{
    meta:
        id = "BxxVifSTgf2K0fIdC6IAK"
        fingerprint = "c5de8de0d5e5347de48278aa9a5b94b710f5fd37189ae55f0d56298e56805ee8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89f364b0727502060fd9c3aa86b32b43"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68ffc1ca109d5019"
    $a1="4077eb0b03ddce3b"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*DEEF4D7D88CD046ECA02A80393B7780A63E7E789"
    $a1="*D89A99106002D77C1D327FC41E005919505638B0"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X84bPjS1IK/v+zfOCMfNZg=="
    $a1="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}GRMsP4DDPTi75MUYKPBbCB6fZs0="
    $a1="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fce1b3e34b520afeffb37ce08c7cd66"
    $a1="e3afed0047b08059d0fada10f400c1e5"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19132c3f80c33d38bbe4c51828f05b081e9f66cd"
    $a1="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0f26dd89a8befc676e680bcd908ba35082dc24a5ea7f0f764058eb6d74d7a788ae8706fe8531c9bc82c3145b15f4df34"
    $a1="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3bb821d6fdc22ef6936af5a08fefce00d0c14f9d8b5e9d48ea9a2788"
    $a1="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f2904a714e52c731bea081c2ee28d5ada378567b564e4a5b0e70c56f2973dcfc7fca5e51d21969a0bade21b619ced0b5ed33fb326b682f70993e025be33e49f"
    $a1="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="caf1c06dcf802728c4cfc24d645e1e7386ba0289e03ea93be21e2ad625b5a3d0"
    $a1="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2006e391b48c3ee39becc6b719f471aaeb9fbce7ffe774ac1ec09f7d97c77b66cb6fe379127e216264e8eb95ea9a27ff34ba1ba7331e57a2de804e8e1261be38"
    $a1="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3fd76f407b26f706b7a6e8d4b65d746d7838ed2497ac8e0c6bdce1c7988536e0"
    $a1="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f37e42b112e9e8ea10bd9a6aca387c323f71167d97da8a7dc07e3758"
    $a1="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4b266b50cb00ff320c59d3569e9ed76d79ea87d415e43bded63ac9ad152319c0"
    $a1="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84f49f5641d8637c8686ec1c01c38dc4d0a016d5b96ce57b60767dd1501d3c0f59fd139e5af172f8c0e99f605317db6b"
    $a1="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4c298f03807d0abdb21722b81d48311de3f1bf4039ccb54bcf9b8c820571480bb6d74ccee89ee492721071a0d7cd3c6e7caba6f325208f6be6bbd578a77b382"
    $a1="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_zabbix_llc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zabbix_llc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW4="
    $a1="emFiYml4"
condition:
    ($a0 and $a1)
}

