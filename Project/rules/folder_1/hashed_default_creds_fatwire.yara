/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_fatwire
{
    meta:
        id = "6pYvaoYPOzF8pgPNss0H7o"
        fingerprint = "4216725ab7de12e6277cb066570a4e57ae2870747d2fae6d568922f634972f74"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5998ba1d1a0aab4bfb8d9a313866bbcb"
    $a1="5998ba1d1a0aab4bfb8d9a313866bbcb"
    $a2="fd2a401a070a77951b664727b52f2e3d"
    $a3="24e85f35a4890114b5cc035e16025486"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3dfdd42f0857133a"
    $a1="3dfdd42f0857133a"
    $a2="29627edf6d4d3b41"
    $a3="4f9feb30243601a8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8033F727E9F00F62A80E3C290BE0C77EEFE6C6EE"
    $a1="*8033F727E9F00F62A80E3C290BE0C77EEFE6C6EE"
    $a2="*11290C5A9E85E7E03189737B950F484889DFC7F2"
    $a3="*7534BEE17FDD8CD64FED6684247311255C9C9298"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}0QRY9yJfXh5WIrDivNuOpA=="
    $a1="{MD5}0QRY9yJfXh5WIrDivNuOpA=="
    $a2="{MD5}YkGZfqztIX2TFLsJGVfbSQ=="
    $a3="{MD5}FytQSOjTG7Mjb78fZJ3Xaw=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}O1u0kmpEyJWgU1dl4WGNYMmQHiI="
    $a1="{SHA}O1u0kmpEyJWgU1dl4WGNYMmQHiI="
    $a2="{SHA}CWFGpm928oUNZSfhTfsfrYmFRpo="
    $a3="{SHA}178ingGyHgxSHLgLJr8kvQ8dcts="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d10458f7225f5e1e5622b0e2bcdb8ea4"
    $a1="d10458f7225f5e1e5622b0e2bcdb8ea4"
    $a2="6241997eaced217d9314bb091957db49"
    $a3="172b5048e8d31bb3236fbf1f649dd76b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b5bb4926a44c895a0535765e1618d60c9901e22"
    $a1="3b5bb4926a44c895a0535765e1618d60c9901e22"
    $a2="096146a66f76f2850d6527e14dfb1fad8985469a"
    $a3="d7bf229e01b21e0c521cb80b26bf24bd0f1d72db"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8677fbf1106acb063373e0f49121314986c407b58a4fb512218e262106471c49753fc6577d8cc40f7147f6c16775c21"
    $a1="a8677fbf1106acb063373e0f49121314986c407b58a4fb512218e262106471c49753fc6577d8cc40f7147f6c16775c21"
    $a2="88e8b2edab814eda3871b06823ed4fad1b6d307087517e6d10a916974a9aab7191f070d3ac8e18bbf9fdd0e36fbdd29a"
    $a3="f4ab68cbba51b1c9d19d3924035bd441846ad956b277ff02600a0e1f8601ca01b5b0f2a2c05776c7ec66168de3a808fc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="02b20320af5c03b4bd347db62f53ee30edc4c3d8dc8ac4a7d6328939"
    $a1="02b20320af5c03b4bd347db62f53ee30edc4c3d8dc8ac4a7d6328939"
    $a2="e5ce190ea5c75c2c83fa41502de4b8db1d77000e4442aee512d4c60c"
    $a3="8cf19140cbfe4f207d6d66ff168a91f572ed23e39e9ced1523d8317f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6250924f80ae1be961b1a452d6d47a6ace0b160772a11caddfd8d8154e5974230317c00106f8401f0c4d34d3e0f838ee7cdde63518d508606cf8082db1bcf2db"
    $a1="6250924f80ae1be961b1a452d6d47a6ace0b160772a11caddfd8d8154e5974230317c00106f8401f0c4d34d3e0f838ee7cdde63518d508606cf8082db1bcf2db"
    $a2="7f80ca2b78ea3b1a73bcb33c41def1525197ec3963c92e977eff6da07f4392853897b2fb2466d6258035463f51f6ef638b97c69bcdd6fec316549d279c1622ed"
    $a3="3b3de2a49852b1d480f8011f5dd8eb5576f97045b2e13c0f3a3807d8b9d05837d1e360e18b2c38088dff8809c2dd03cdde2d9ed58abe1eec1fc41d4b20306992"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd0624d77f522eac19f103b7e22f69b46e3d5d37cce09288d7b1dfb130885ed0"
    $a1="cd0624d77f522eac19f103b7e22f69b46e3d5d37cce09288d7b1dfb130885ed0"
    $a2="acdaf6b9d19088c668b4ac71c8f97f28e70c8ce6e7839ca99d49293a12d52756"
    $a3="ba1625a37ecad107990e31208789f5fec017b6e9e6f422778139e8f872aa5518"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7862c897f79175838edadbb5d7d2e84808a9160bbd26e33f96e0fb95b6a9f6e8a453ec25eb5e0315071a0422bc406003bcb678f931c53a91a9732ac4958b01b7"
    $a1="7862c897f79175838edadbb5d7d2e84808a9160bbd26e33f96e0fb95b6a9f6e8a453ec25eb5e0315071a0422bc406003bcb678f931c53a91a9732ac4958b01b7"
    $a2="ceef08f04fee77d263b2a6ecbd96aafdda48016f24e45584ec648be3828795e87185ba2047cdb9460c122156efc40dddf06be8706d53ce47423f868649c3e796"
    $a3="ae615d73902ba18d0d7454ab20deeacf4c6f95d07674a442a307ee932feb8eec3a9c61176ef2a4797951cdb2905bbd851185ab75890f613456516ba946d2c88b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c8bf8ccb7ea986068d8d44dd08afb35b30f7729bdbd9de3a2ac891752a7585f"
    $a1="6c8bf8ccb7ea986068d8d44dd08afb35b30f7729bdbd9de3a2ac891752a7585f"
    $a2="aba602c6cde7862e4ecdb38559be007f9af4ab2d7b5cc0a8d5df4abfb4916582"
    $a3="187dd1868f0c27d2e8397572d328f7b68e9694f023f92e217795b39e524e8774"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23043cdd8a5e13150461e02a1103c3c8b030a16ff727e2656a58251d"
    $a1="23043cdd8a5e13150461e02a1103c3c8b030a16ff727e2656a58251d"
    $a2="301a0bfd98045e96b6bc5a8897808683bb6c5c7e8ca92b65fa75945b"
    $a3="109bee661dbc08cb30bb6dafd648ebce86fd7d00d39594e47b560182"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="098857c2f2f3b2db6eb8fd4b6b8be8f0206a1c75a6e2e777e6a1bd8e7e51dbf3"
    $a1="098857c2f2f3b2db6eb8fd4b6b8be8f0206a1c75a6e2e777e6a1bd8e7e51dbf3"
    $a2="407eb2d8f4d42912977052bf56ba176a2f615f05089a7894a9917657d6a0b3e7"
    $a3="3deaf0f9eca5490e120d9c3a1bde7165ddf9f56a131de22224b184b9a1fe8238"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6db1399f206bdb8d6d8b79dcfaaa508fbf2542ec462a6bfc964231961c5ec5faa92ebdc6fb5218544d26aa1ab97698ef"
    $a1="6db1399f206bdb8d6d8b79dcfaaa508fbf2542ec462a6bfc964231961c5ec5faa92ebdc6fb5218544d26aa1ab97698ef"
    $a2="5b750f48155c69d47ad10b987c2729c3723dfa3a68754f0f347c2dd29a87686fad21da1074f7edb6b0ccb519e206d4cf"
    $a3="d543d9ca0ed72c28f83c84fabe022a766d39e364e7c753c49473fc5aeb4c24daa190eec76f06ecb019b22b697f033eb5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac02398209b4a3469f8fdc150274d063550ad00ccab171e672f08794cce906920727fe75b9515d632d089cf7e3aeea4fd9a9dcb9ec9f869085296d147dc5a4cc"
    $a1="ac02398209b4a3469f8fdc150274d063550ad00ccab171e672f08794cce906920727fe75b9515d632d089cf7e3aeea4fd9a9dcb9ec9f869085296d147dc5a4cc"
    $a2="5821cddef17fb944885892b421963507af4ab9bc8edb77b29252002a04b44f3a74a90b0786fbbf23b9a18c80972ff549a6ec372998c26388075481f2d53dfd26"
    $a3="7a4827493d45a64c6a2f0bbb4713cce02f0abb1a0429d021c3ae6c53798fdeeb91245cdf51f37da0635f615fad9ff6401649c180afd908ef1751101fc13a66f3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Zmlyc3RzaXRl"
    $a1="Zmlyc3RzaXRl"
    $a2="ZndhZG1pbg=="
    $a3="eGNlbGFkbWlu"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

