/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_xampp_web
{
    meta:
        id = "430HFeVdCBjYmmlW3yg2a7"
        fingerprint = "6e34b0c1b032725cd5abf2cf47a04f9206b66264eba943c10eda0ac01acd79ad"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a470dfa4825d16736c4e8d24a32e1982"
    $a1="8a932e577302c7eec164aa380ccec204"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1029efa771e05385"
    $a1="57f008c30f04ceb6"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E61D216A7B396CAF162B823393877381BE64A650"
    $a1="*B4333ED22F8FFFD460D02C0CA1C8C0AD0C8B4538"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}kuuIeaglJGhqzdAFjhzU9Q=="
    $a1="{MD5}A1TYnCjsOZwA08stCUzwkw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}C3tUyHX0g75IkzAblLKnXCvgnaE="
    $a1="{SHA}zRv+VcuysLmJyshjkeUQDJM//n4="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="92eb8879a82524686acdd0058e1cd4f5"
    $a1="0354d89c28ec399c00d3cb2d094cf093"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0b7b54c875f483be4893301b94b2a75c2be09da1"
    $a1="cd1bfe55cbb2b0b989cac86391e5100c933ffe7e"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2483236e15afac35920898385ba3e2ec3b55f0fe886460efebc9af582cccce387b45db0c2752ed30dfd9b659230dde8e"
    $a1="db8d4dde8910796663a37f48af49cc9b5d3d68bc7adece1ec267ade0a21bef7a0c40ce8e14d09d2b28e37d7b9a047811"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6e58d0f0858cc84231c22d5abd694d533870e72e69e182cf90da11e"
    $a1="d75b483573d8c841c5eae105e6938eae6d73de6fcbf408b7ac0cf986"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="739d862fc58236987199ea91e7c0d615444d4a84db7b76885dd58232ec8aae29b44cf79a0c17941cd729f967a92324f9ba3d388c651608dff19c5793aa5ce247"
    $a1="b42fa1ce2b65fd6f4a8501b64deef38fa3e87059c6f015eb5848c50aaa538dc812c8d36dba61f4c505d54516707a3997d555ff08dd447617d9cd3180df95204c"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c1aaeeab26f30bd0de1ecd863850247067c475a6c5aeb707cedb8ba9db04ae8"
    $a1="9c9064c59f1ffa2e174ee754d2979be80dd30db552ec03e7e327e9b1a4bd594e"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69a1b472931fb74a59e12d09749c215a2ae8435c0d058c01f457e9396b9f11caeb99e9fba6fdceccef69e513cd403c65c4aeaeb60730043fd3767679b95f2529"
    $a1="597ae74fb139d976f0e28dfda3b6ed18b8a764b8a889d6ba849314677f73ea0b8a732c47730ee1cc7b8eb4fcebb68bc2133fb9ad9e77d5aab3cb2f9782c40eef"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e15bc140719497af97c6ef3a6f55ef46e47a033c357b9d65a90c77718ad938b2"
    $a1="f3e282aa4314fc5badd98ebddeb6b1fd50d0eed8f4220a528e0ab3203cb8470c"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1bbb9ea5ac4b0b8c102e781161d390759da92e703831994bea7a3712"
    $a1="aac83e77887d2403c910147f28c143b4ca55ca9b309106e2ddb43b0b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10b239de54ba80fdd39de02bfe205abd212c403ced42e5d74e72abd43af23e56"
    $a1="4bc235380efd7ef2d94733b9b0003bd488d2eed8dc10c4c348c5fabbd475fdfd"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98e4f2b895ce934e5ed2e2ed8768cca3b8a923183c5b4b75fcdea7381c8ce89bf82170438b096d3e96f443cd4854b7c3"
    $a1="0c8898a49c7b35455d8f743a531d120157275b0efad2352b318fd77cb14e786e38944ce5d17f963588ef33918aca44d5"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6d88af8f648f7d8ff7e013fd2fa5d9a127cb6f544bf596acc278a3ab90072cee3aac533c7a584b0cabcba51a47132c6cec76e4447dfa047e6368469ad42ec31"
    $a1="ab04d145529d509c073f513c04c4593dcf360eb0ad172dfa0613d9c6fcc10e37b5a4f8e9102694c8ea018a5e58e97cea0c7c2731de2fcc268bd2b2c6fe4492b2"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bmV3dXNlcg=="
    $a1="d2FtcHA="
condition:
    ($a0 and $a1)
}

