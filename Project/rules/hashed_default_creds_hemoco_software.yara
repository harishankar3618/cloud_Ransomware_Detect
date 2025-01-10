/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_hemoco_software
{
    meta:
        id = "3YUJ3DjqehuRUtLpJnvjQw"
        fingerprint = "733719f594a81d07965a8680ff56fa713c0b51decd942145005a67b22e47bb13"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ec8c90a4816d4986cf457393071dda14"
    $a1="1c6abf437c36b1047a8b81993f775102"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="02ba6a4366afd952"
    $a1="5a61143f456cbf6a"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FDD17A7B22D8DF8E91E4826C7877FC5A73599458"
    $a1="*B8864F0CBE60EF45604E11C30AC7EEFF0F7D55A3"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}u2Vf7UN1riHTRwNeid8Caw=="
    $a1="{MD5}xVxz+Df/WI4xbK4W2hWnHw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}EeZiet3fVrQ8kYnvsrJaPuL43YA="
    $a1="{SHA}HEHB+q0XQNcTdVo5NjRS8ll3KW8="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bb655fed4375ae21d347035e89df026b"
    $a1="c55c73f837ff588e316cae16da15a71f"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11e6627adddf56b43c9189efb2b25a3ee2f8dd80"
    $a1="1c41c1faad1740d713755a39363452f25977296f"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd0667519792aa42268834c586fc30d292cc5fab088ac3ae4812e08698d74745dfb3996c53d30e4214fcbc5bc2678888"
    $a1="77c8662a4cd2fad81e5acbfb7365c6f9aae1e3810d067d112436754841517415d39aaa4bc1b02e573783b0d38767d853"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="039423a95cc545f6c858985de406ccb0eed1868140605ea013d4909c"
    $a1="409f259ced3ec3f6346403ce9dc31c70c07466ee94ff5fe11b331a15"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2c1b52dfb944b670a3c9fbb748bbf981700f06e6dbc935d407783fd44fefec23abb9114030ab40a3121135863b99ccdd2e1db858c3ad5c8d9830d231f8645095"
    $a1="772803acbf87e50abf9d8048151cfac152bb61bd05ce50cb3ff4a5c5e0cf3d256915984afdbbbfb42b69b8762a6fd55fff864484c212534aa8e694eb90c4c631"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="771aec19d40d31c656f84a9d6b96e4806be0154f2567267312dd11e5b6c889e6"
    $a1="e8c3aeca358d39546816b0b38427bd30edacc0c723fd593beb9a72e6d82702fe"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e3e4e79d5bfca6188153083b35c08113ab54f8e7ff5ddc5efa08c5a99a45a3ed4148bfa5100567abcaf06c628b7734af6813365305bd382ede48044d26f4632"
    $a1="ccfbcb2378da873484c950e554a17c117a6183167522958064980485720d09648d8c07caf60f4727f6922f6595538cf03721746142ba353161d1256693ccae2c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18832fc6b3fdb392884335ce578e5ad38997a02c02a09c71793d475ce2b977d4"
    $a1="b02138e0cdb702f22331d44016eb4a43dee11eb43fc2471396a1b125fd8dff88"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="72a77bfd8fd21160833f3481c1b061d5d89a3e1731cca10d16e50c7f"
    $a1="c8c550837cb1bd484ec54177f469d9ecb71bdb10fd5023c4c7e16a6b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54d696d198af7a1d4899c40c44951be950659e02a17abbe39c97b344fcd57704"
    $a1="52a1fda43437f042d063482147627a0340b16aacd965b8beaabf2510e14ddcb8"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ec95885e45b56e07b00a3635c5ce9b0196915779b64c25dd1dd743cb5c8e7f21cd05c97d0ca826d885815455b890558"
    $a1="d09a109d78344b0b94f5face9b082bec0cc1623e33cbec988ff01601fa34ba3d3bdd2886b773a11e55a88877b44c95a5"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb93b0c8257846e988aefae549f07d7f0df48c7629f9d478864914f8dba6b166d35a67e2b68f1ce5c22c2df82d8dd38f1aa946857e4d7e601ffd1ddc2ee01326"
    $a1="0a3988e33920104805988d3219d41605e9153038f81b75ff02818b74aa21642bcf7a1eae1f1125c031a11f40a55c2577e5c48feb1c135514d6345912aa7b30c2"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bGFuc3dlZXBlcnVzZXI="
    $a1="bXlzZWNyZXRwYXNzd29yZDAq"
condition:
    ($a0 and $a1)
}

