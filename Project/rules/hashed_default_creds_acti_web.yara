/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_acti_web
{
    meta:
        id = "sfXhUXY6oK3l93WJ6GaYq"
        fingerprint = "7cb7cdbcfe2a077c59dd3e208d328738f1c1f3ec244631a22389324112beb5f8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a21990fcd3d759941e45c490f143d5f"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7a21990fcd3d759941e45c490f143d5f"
    $a3="a25b2710ba9de114396adc7dfb0a7235"
    $a4="32ed87bdb5fdc5e9cba88547376818d4"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="32ed87bdb5fdc5e9cba88547376818d4"
    $a7="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e782c85379a326e"
    $a1="43e9a4ab75570f5b"
    $a2="2e782c85379a326e"
    $a3="4077eb0b03ddce3b"
    $a4="565491d704013245"
    $a5="43e9a4ab75570f5b"
    $a6="565491d704013245"
    $a7="4077eb0b03ddce3b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a3="*D89A99106002D77C1D327FC41E005919505638B0"
    $a4="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a7="*D89A99106002D77C1D327FC41E005919505638B0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a3="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a4="{MD5}4QrcOUm6Wau+VuBX8g+IPg=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}4QrcOUm6Wau+VuBX8g+IPg=="
    $a7="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a3="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a4="{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs="
    $a7="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="827ccb0eea8a706c4c34a16891f84e7b"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="827ccb0eea8a706c4c34a16891f84e7b"
    $a3="e3afed0047b08059d0fada10f400c1e5"
    $a4="e10adc3949ba59abbe56e057f20f883e"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="e10adc3949ba59abbe56e057f20f883e"
    $a7="e3afed0047b08059d0fada10f400c1e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cb2237d0679ca88db6464eac60da96345513964"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="8cb2237d0679ca88db6464eac60da96345513964"
    $a3="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a4="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a7="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a3="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a4="0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454"
    $a7="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a3="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a4="f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
    $a7="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a3="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a4="ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"
    $a7="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a3="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a4="8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
    $a7="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a3="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a4="b3910b0f4b6f1aede44da90bb7705a868b265861b36e6f7f29dba7223f6f1ce7b10e0dd25e47deb70bd7f3b24f7da653409cd9014f8715e4013c15fee38ab418"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="b3910b0f4b6f1aede44da90bb7705a868b265861b36e6f7f29dba7223f6f1ce7b10e0dd25e47deb70bd7f3b24f7da653409cd9014f8715e4013c15fee38ab418"
    $a7="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a3="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a4="ba2649757ec72ed0b9bd8b3063687767946145f13abcb38e2718fdaad6c771e0"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="ba2649757ec72ed0b9bd8b3063687767946145f13abcb38e2718fdaad6c771e0"
    $a7="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a3="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a4="6be790258b73da9441099c4cb6aeec1f0c883152dd74e7581b70a648"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="6be790258b73da9441099c4cb6aeec1f0c883152dd74e7581b70a648"
    $a7="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a3="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a4="d7190eb194ff9494625514b6d178c87f99c5973e28c398969d2233f2960a573e"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="d7190eb194ff9494625514b6d178c87f99c5973e28c398969d2233f2960a573e"
    $a7="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a3="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a4="1fb0da774034ba308fbe02f3e90dc004191df7aec3758b6be8451d09f1ff7ec18765f96e71faff637925c6be1d65f1cd"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="1fb0da774034ba308fbe02f3e90dc004191df7aec3758b6be8451d09f1ff7ec18765f96e71faff637925c6be1d65f1cd"
    $a7="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a3="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a4="64d09d9930c8ecf79e513167a588cb75439b762ce8f9b22ea59765f32aa74ca19d2f1e97dc922a3d4954594a05062917fb24d1f8e72f2ed02a58ed7534f94d27"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="64d09d9930c8ecf79e513167a588cb75439b762ce8f9b22ea59765f32aa74ca19d2f1e97dc922a3d4954594a05062917fb24d1f8e72f2ed02a58ed7534f94d27"
    $a7="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="MTIzNDU="
    $a2="QWRtaW4="
    $a3="MTIzNDU="
    $a4="YWRtaW4="
    $a5="MTIzNDU2"
    $a6="QWRtaW4="
    $a7="MTIzNDU2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

