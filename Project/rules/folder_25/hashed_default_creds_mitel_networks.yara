/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_mitel_networks
{
    meta:
        id = "6PIp5pXmP9rS1st6wTdVp4"
        fingerprint = "f51348d922872b44f8f8320681955dbb86a2314529c4d0a43406b9c9c2c6df6f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e52caf2cd5f6c0058af92938b853cca"
    $a1="97090730e7e25e0cf351ef7b99f7b56f"
    $a2="789050b591b971e873741eb1ee7559b3"
    $a3="a37c2cd2c0a5415745e9d1fe1a0d6367"
    $a4="789050b591b971e873741eb1ee7559b3"
    $a5="6b57d6553205fa3ac14cfddf9ae1c9ec"
    $a6="789050b591b971e873741eb1ee7559b3"
    $a7="b59db4ed6513e7d35fc18e744036bd8d"
    $a8="2e52caf2cd5f6c0058af92938b853cca"
    $a9="29ed6043f57810b5f405916c1c5ac2e4"
    $a10="789050b591b971e873741eb1ee7559b3"
    $a11="f441f41aa59214cccc3d4ba5ed1550cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68cec90b77f54ab7"
    $a1="1e2ea1d81d71b53a"
    $a2="48d4a6bf11b81e77"
    $a3="109be9900d0cfff2"
    $a4="48d4a6bf11b81e77"
    $a5="29c83f1057f1d935"
    $a6="48d4a6bf11b81e77"
    $a7="29c83cc557f1d8ea"
    $a8="68cec90b77f54ab7"
    $a9="1363c56f0de30277"
    $a10="48d4a6bf11b81e77"
    $a11="6a77f1277b51f67f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*700059826CC0D4CA300205D7A323A3D3BE33C840"
    $a1="*5C6FD33285EC724AC66AB0E4B5C6AFB79868C24B"
    $a2="*BC2DDFC5FBC0F9FF8A710D57E1FF4FCCF6D6901C"
    $a3="*432DADB80863E758A32913E510F74D01A605B00B"
    $a4="*BC2DDFC5FBC0F9FF8A710D57E1FF4FCCF6D6901C"
    $a5="*07277821E7C889F93B4FEF93A42209A4E53023D9"
    $a6="*BC2DDFC5FBC0F9FF8A710D57E1FF4FCCF6D6901C"
    $a7="*A3990B70C8593C66B534B148BABBA5DD680D3AE1"
    $a8="*700059826CC0D4CA300205D7A323A3D3BE33C840"
    $a9="*170AFEC341719E6A5EFEBE910A89A3DF26CF5352"
    $a10="*BC2DDFC5FBC0F9FF8A710D57E1FF4FCCF6D6901C"
    $a11="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}zkmkUTqvAhWx7ci+3jmMbw=="
    $a1="{MD5}EJ11tl2oQAwvNGWh9f7tHQ=="
    $a2="{MD5}7NesoseWc9JEGHNcm1ZwLg=="
    $a3="{MD5}lzhCYbi7+WbfFuWtUJki2w=="
    $a4="{MD5}7NesoseWc9JEGHNcm1ZwLg=="
    $a5="{MD5}Osi4xLaFVuUhkiBS+LBJtA=="
    $a6="{MD5}7NesoseWc9JEGHNcm1ZwLg=="
    $a7="{MD5}Eohrp3H/Jn1PIbCPquD+aQ=="
    $a8="{MD5}zkmkUTqvAhWx7ci+3jmMbw=="
    $a9="{MD5}rbB0zzkZHW8LIh4iGM4vSw=="
    $a10="{MD5}7NesoseWc9JEGHNcm1ZwLg=="
    $a11="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nwsT/WBHTBtR1YMVXobR7QYN0G8="
    $a1="{SHA}7mZ+GHu+y4W0mF2+85Ak2zoQ160="
    $a2="{SHA}6IjcrDKsBH3TYip1bEweLJspOFg="
    $a3="{SHA}L8QtN/7iyB12fgn7KYtwx0iUD4Y="
    $a4="{SHA}6IjcrDKsBH3TYip1bEweLJspOFg="
    $a5="{SHA}NDuwVyc6CGdOGfgvvo67brhxHwA="
    $a6="{SHA}6IjcrDKsBH3TYip1bEweLJspOFg="
    $a7="{SHA}njchZDeX5NE3PP7A0N9P11d7GVs="
    $a8="{SHA}nwsT/WBHTBtR1YMVXobR7QYN0G8="
    $a9="{SHA}nnMN0CJS+VFX+cpVmlqRODLT9Zg="
    $a10="{SHA}6IjcrDKsBH3TYip1bEweLJspOFg="
    $a11="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce49a4513aaf0215b1edc8bede398c6f"
    $a1="109d75b65da8400c2f3465a1f5feed1d"
    $a2="ecd7aca2c79673d24418735c9b56702e"
    $a3="97384261b8bbf966df16e5ad509922db"
    $a4="ecd7aca2c79673d24418735c9b56702e"
    $a5="3ac8b8c4b68556e521922052f8b049b4"
    $a6="ecd7aca2c79673d24418735c9b56702e"
    $a7="12886ba771ff267d4f21b08faae0fe69"
    $a8="ce49a4513aaf0215b1edc8bede398c6f"
    $a9="adb074cf39191d6f0b221e2218ce2f4b"
    $a10="ecd7aca2c79673d24418735c9b56702e"
    $a11="54b53072540eeeb8f8e9343e71f28176"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f0b13fd60474c1b51d583155e86d1ed060dd06f"
    $a1="ee667e187bbecb85b4985dbef39024db3a10d7ad"
    $a2="e888dcac32ac047dd3622a756c4c1e2c9b293858"
    $a3="2fc42d37fee2c81d767e09fb298b70c748940f86"
    $a4="e888dcac32ac047dd3622a756c4c1e2c9b293858"
    $a5="343bb057273a08674e19f82fbe8ebb6eb8711f00"
    $a6="e888dcac32ac047dd3622a756c4c1e2c9b293858"
    $a7="9e3721643797e4d1373cfec0d0df4fd7577b195b"
    $a8="9f0b13fd60474c1b51d583155e86d1ed060dd06f"
    $a9="9e730dd02252f95157f9ca559a5a913832d3f598"
    $a10="e888dcac32ac047dd3622a756c4c1e2c9b293858"
    $a11="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e79a2eaf7547512cfab23475185d7fa079191815ada7a2cca619f65c0e5ac472a44bab5ce5395b092b3da1d552595f1"
    $a1="09663513fe0f7bb0ee410fabf7b8d38390cd49a909a88c203277f5a50e44f18280de30e1a0eecb2e0eb2a09c88d65ac9"
    $a2="7e1e4eae3bdc56266bbfa9963b36b493bd5dfc8eca72a4365b44c4749f1a265346710509e07bec8f70a0c2459b542646"
    $a3="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
    $a4="7e1e4eae3bdc56266bbfa9963b36b493bd5dfc8eca72a4365b44c4749f1a265346710509e07bec8f70a0c2459b542646"
    $a5="b358f8f9b56b2a537db92b12d136a64b781b8807ca64a4bba5d0f929ad0a950817d481b880de2cc71c78b84f596da977"
    $a6="7e1e4eae3bdc56266bbfa9963b36b493bd5dfc8eca72a4365b44c4749f1a265346710509e07bec8f70a0c2459b542646"
    $a7="d6a4fc7e74ddcd5854f0e1c8a1f5e9b29390ab0bdc7be6b71eb376697d59b3bb463ed3666d098d9b122c84f34aef8494"
    $a8="7e79a2eaf7547512cfab23475185d7fa079191815ada7a2cca619f65c0e5ac472a44bab5ce5395b092b3da1d552595f1"
    $a9="435ead18f85466e7c16e41caf2d9db2d7fbb1e62e870dad777562002cd7e989d374eef70456662d0f0bdaeb23325a032"
    $a10="7e1e4eae3bdc56266bbfa9963b36b493bd5dfc8eca72a4365b44c4749f1a265346710509e07bec8f70a0c2459b542646"
    $a11="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="93c44a79a10e9e4472c6a49d95472fc7e40f2d67f38369510cd5ec52"
    $a1="611e895d6028d7dd1236dd419c2886e66abd9ba0086220fe8a586bc5"
    $a2="7d4edbe25b56f378a3090837ed7849225810d0a8cc1d0935b7982144"
    $a3="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
    $a4="7d4edbe25b56f378a3090837ed7849225810d0a8cc1d0935b7982144"
    $a5="c99a6d7630d8c28a5c9b865d58bb9ca780d5749f240162eeec39b1f0"
    $a6="7d4edbe25b56f378a3090837ed7849225810d0a8cc1d0935b7982144"
    $a7="83bb3fc47ac1f7a55e18a113dc40c4a5222aa313e4a017fa4c61cf37"
    $a8="93c44a79a10e9e4472c6a49d95472fc7e40f2d67f38369510cd5ec52"
    $a9="d2f794a490b54343929f420853c953465b95990d631664ce37d4e543"
    $a10="7d4edbe25b56f378a3090837ed7849225810d0a8cc1d0935b7982144"
    $a11="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e6d06f0f0f0474e5c1e035b32fa569afcdd11fe76240ef2e4ee04cf8dc694b7f2a716f513e2c351feed667633901c8cf6e66ec24e75f270f6b8a6e3c903dd8b"
    $a1="e81ed1691a06474a55642a2fd13ed615db96e349586bd2809f9156ff44c4935bf7fe00b4f113184fcbdf73e3da7fe49f970e62f38ea9524f05addad05a1705e6"
    $a2="b54d41342bdd4bae48b2c596315046e55a7d774701f98c8a7ba93edb8cc48ebea557d4d6eff0af7b594161dce9ed99d96d760a73bf4db54e81d63b30880b56b6"
    $a3="b77fe2d86fbc5bd116d6a073eb447e76a74add3fa0d0b801f97535963241be3cdce1dbcaed603b78f020d0845b2d4bfc892ceb2a7d1c8f1d98abc4812ef5af21"
    $a4="b54d41342bdd4bae48b2c596315046e55a7d774701f98c8a7ba93edb8cc48ebea557d4d6eff0af7b594161dce9ed99d96d760a73bf4db54e81d63b30880b56b6"
    $a5="b398d0ea5ece18bdb119da542f71abfbe1eb1472f577f9d684cc169da4ac7724e96cc19ba11f70817f25eb33e5d920da194bca51b4c996253159c03bc92ca50d"
    $a6="b54d41342bdd4bae48b2c596315046e55a7d774701f98c8a7ba93edb8cc48ebea557d4d6eff0af7b594161dce9ed99d96d760a73bf4db54e81d63b30880b56b6"
    $a7="8cffcc26d16dff5fd03e89b5eaca435998535a3730f8187b6341b44162590330119f5812316523dfad29cbff26a1ab1f5475509b95f05a61b737dd663866317e"
    $a8="1e6d06f0f0f0474e5c1e035b32fa569afcdd11fe76240ef2e4ee04cf8dc694b7f2a716f513e2c351feed667633901c8cf6e66ec24e75f270f6b8a6e3c903dd8b"
    $a9="2cc595c5b93f860d70a9a6706d24ffc28954fb5b5ac98a5a1fb996e212375db4080315ba73850e7ffdc0c8d181b8a3a04ebe9383d8f7ed41f57014628e315ee8"
    $a10="b54d41342bdd4bae48b2c596315046e55a7d774701f98c8a7ba93edb8cc48ebea557d4d6eff0af7b594161dce9ed99d96d760a73bf4db54e81d63b30880b56b6"
    $a11="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a6840a79e2e1ce78aa167cb20f5849746987527ed0b19bf8720c4961c329c48"
    $a1="bc4069fb4edf3abf8c5ed5d5b5b15f7b14c2aecdddda4d736930596713932a03"
    $a2="9b6a228004f5e21622157867c1155f9b843c7fc1aacf893809fa2b5289a24a4a"
    $a3="9c0d294c05fc1d88d698034609bb81c0c69196327594e4c69d2915c80fd9850c"
    $a4="9b6a228004f5e21622157867c1155f9b843c7fc1aacf893809fa2b5289a24a4a"
    $a5="f4c97d0f07ca354527997e9865f1e197d3917fbfff92a143bb0dab4470deea15"
    $a6="9b6a228004f5e21622157867c1155f9b843c7fc1aacf893809fa2b5289a24a4a"
    $a7="55da0b2d75f7448a787fca84e3b7052252a69f9c4850a824aa8f0ef475fd610b"
    $a8="4a6840a79e2e1ce78aa167cb20f5849746987527ed0b19bf8720c4961c329c48"
    $a9="b65e5ed8628b3eda27e1cf9aed3ab6ba13a85db081a4f96ecff1f379c240d1e0"
    $a10="9b6a228004f5e21622157867c1155f9b843c7fc1aacf893809fa2b5289a24a4a"
    $a11="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa3f95a275a470327cd92c994e7559f5a914267407b70a3d6208e02735a9bbcd16b39f1cbc1b4be5ba697c1d27c605c69839ee6eac78bc02e9411af6f9bef763"
    $a1="3ad21c6f9def1be68a1795b8eb806e89674f92fda21bcac464a6b9e2fbb58547f097465fb0ceed6f6073dfb3783d06dd9938c55ee4ce6c6aa01e008d4bd27df7"
    $a2="b9e5a4b81102c413380132162c60d18799a0b6d0b9be318a19fec2fb58a784133aa29ddb07a8a37def8475c3eda324937632c26528ec7fa9dc0b419f7d5672b1"
    $a3="78029416f2a036f9bbee2b4519a452479916558edd66a43816bcce88d4b0269a8bb63062747ee448b35fdd05b00abeaf5003014087011ff134b7a00487caaccd"
    $a4="b9e5a4b81102c413380132162c60d18799a0b6d0b9be318a19fec2fb58a784133aa29ddb07a8a37def8475c3eda324937632c26528ec7fa9dc0b419f7d5672b1"
    $a5="0ac166e3f28df968b3fad02990833565556d765edd407bef1485057dcd212b7037a2aa983b3531acb5676f8863f1920b2e438bae55f3b69bb1800d63b9d2b8db"
    $a6="b9e5a4b81102c413380132162c60d18799a0b6d0b9be318a19fec2fb58a784133aa29ddb07a8a37def8475c3eda324937632c26528ec7fa9dc0b419f7d5672b1"
    $a7="fc21b2a2719697e3ea82b1ce2adad3d78185bfc8d6167419456d087402ecb6df7b24804440ee086e25eadadd5ea318b5dc789d187face78765f27daaf9ced286"
    $a8="aa3f95a275a470327cd92c994e7559f5a914267407b70a3d6208e02735a9bbcd16b39f1cbc1b4be5ba697c1d27c605c69839ee6eac78bc02e9411af6f9bef763"
    $a9="e48f30c4dd242f51b2256ce3b67b26058e1de9986ec812d87a2452e7803a63d9924ae7c0193e8f75b03f4651bd113b00245804652cd865a36c0b8d29dc5eb3dc"
    $a10="b9e5a4b81102c413380132162c60d18799a0b6d0b9be318a19fec2fb58a784133aa29ddb07a8a37def8475c3eda324937632c26528ec7fa9dc0b419f7d5672b1"
    $a11="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="85a117a9aa25d3093b352a4dfb4174b3eb20f1584f354bc8a57e5fd6018dfcf1"
    $a1="9dc72c7553c0507fcbb12e494008fedcc00d1ac06f7c66eaa1eea7dc9c05cd77"
    $a2="59a659c677698d083a9fc19bf369f25b52528b4e60d6201cbc83956332c576c2"
    $a3="293eea3b1d83925a4c5794c9d2a7a049b796ba4831e66bbfff5ea318a264cb3f"
    $a4="59a659c677698d083a9fc19bf369f25b52528b4e60d6201cbc83956332c576c2"
    $a5="e169e8d9a85cd7094d485f8394897dcdd633a9118193f7a6504f2d7119773665"
    $a6="59a659c677698d083a9fc19bf369f25b52528b4e60d6201cbc83956332c576c2"
    $a7="2613de2aa850fddc284e58de1f4cf033b814efe2f240c700102a4b2960cd096d"
    $a8="85a117a9aa25d3093b352a4dfb4174b3eb20f1584f354bc8a57e5fd6018dfcf1"
    $a9="6a01eca427f483c42d4679763c91a80d6609dd6bdc62c10d5ace5243d6532925"
    $a10="59a659c677698d083a9fc19bf369f25b52528b4e60d6201cbc83956332c576c2"
    $a11="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd99b0e06b6dc65557ced2cab067dc7c3879098114a3b83b68fa9578"
    $a1="c410bb8cb8770a4413e05d56502f282646c429ecc5eaffc9710ba01d"
    $a2="d2b80068a8b1764ebb2a9d64dd17dfb45c4b5cc7558de0c267f30b2e"
    $a3="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
    $a4="d2b80068a8b1764ebb2a9d64dd17dfb45c4b5cc7558de0c267f30b2e"
    $a5="9fa45a79ebf853060beee450f43d4f3f1195e4f1486faeb5663429a9"
    $a6="d2b80068a8b1764ebb2a9d64dd17dfb45c4b5cc7558de0c267f30b2e"
    $a7="59f85285d63a00b5419b044a90248160322894be6e0f66da9543db02"
    $a8="dd99b0e06b6dc65557ced2cab067dc7c3879098114a3b83b68fa9578"
    $a9="4ce20e6bf8b909f3f1da84fa8b6fa0f73b956f68c1df8e3fe96e4b66"
    $a10="d2b80068a8b1764ebb2a9d64dd17dfb45c4b5cc7558de0c267f30b2e"
    $a11="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c9bd6c4b84a74b52a293499a8fbd2bfd40187e80420f3faa9bd2e1ead156d243"
    $a1="5fcf376109a06d70ba53ebe0e363b17148f276c36697aab04536499243014af3"
    $a2="8b4f3f4111c5687d046a8e998d25660dfff6e217034f2a42e19cc7f9e24fb5b8"
    $a3="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
    $a4="8b4f3f4111c5687d046a8e998d25660dfff6e217034f2a42e19cc7f9e24fb5b8"
    $a5="9cfc8ef98f2e43fe014b9c50965c7d63182ccf14fe156135cefba847a0393051"
    $a6="8b4f3f4111c5687d046a8e998d25660dfff6e217034f2a42e19cc7f9e24fb5b8"
    $a7="338907d05f4e53a01641ebd736036e4e07ea5cee1ba5bcc058b7e89ce132e3df"
    $a8="c9bd6c4b84a74b52a293499a8fbd2bfd40187e80420f3faa9bd2e1ead156d243"
    $a9="38af59e1a1498ad9894d11fb12a04ddc77dc4837f872d8b0b970ee0448ac8dc9"
    $a10="8b4f3f4111c5687d046a8e998d25660dfff6e217034f2a42e19cc7f9e24fb5b8"
    $a11="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be4e5ac1fa95b582138a63f719c4dc273285062ec176c782d1389fcecb927ae23f84d3b9c1a2f97147586f4a14e6fb82"
    $a1="f103f060a02ed478413a913832032639cb053f49004e7748f86209dec765590eb18b8283615c5b327acad1e890cb4dbf"
    $a2="08cee9949c412eb0d7cc99e85ce5ca6aa75ba22d3be7ce50b47bcac8c598a52b6a921e6d0effa594509f104858e2e34c"
    $a3="18b54a8de3ef7af582050541d99e85e583708db04970f30d1fbbbe5bd22a3926c2147939e2be80a83b4f325ad72cd7fe"
    $a4="08cee9949c412eb0d7cc99e85ce5ca6aa75ba22d3be7ce50b47bcac8c598a52b6a921e6d0effa594509f104858e2e34c"
    $a5="d842720f00c37bb0633fcacd07e3b4ea340537055c403bc7f8f44a8b58c3c7f237c172f190ee43251fa476393b7f7fef"
    $a6="08cee9949c412eb0d7cc99e85ce5ca6aa75ba22d3be7ce50b47bcac8c598a52b6a921e6d0effa594509f104858e2e34c"
    $a7="fe8b92c719a13f843f723df016f92e0a43f05be1a338709ec27e0e414043ebe0027de858a133a7a1091af7fb110264d9"
    $a8="be4e5ac1fa95b582138a63f719c4dc273285062ec176c782d1389fcecb927ae23f84d3b9c1a2f97147586f4a14e6fb82"
    $a9="9ca8d93e37eab663a9ae822e4022b903813271ee59051bd6cff6efbf0aeee1ae8c280197b29a52991e64a0630501360f"
    $a10="08cee9949c412eb0d7cc99e85ce5ca6aa75ba22d3be7ce50b47bcac8c598a52b6a921e6d0effa594509f104858e2e34c"
    $a11="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3275a7674bbaa865b849aebe272e3319470e61ffd7f7b2763c3cb027650a63e4d6a4c23abe7d42a7e65059d9400180041870e5b05815ef4fb8d445448a6a501"
    $a1="95943f0f284edb0cba8061ae51e2eaec0d8b7000d2dde0d43a99b91dfde6dcaa96d34792f38ae4eef41e9e31c52ccf48b718c9e66c2bf6a0c4224d81ac6d139a"
    $a2="64bcc739ba5a7eb47d0b9539fd8d36a6a2b86100f91b430e938bf53ef6a4805b5bb99febd6efc818d0132a3b57505106f707478f377e0220689e8eac3d3a51d6"
    $a3="1e60cc099bc0ab00cbffb311120b7ca623df6058beb22ac37f5101883128bd5777e26c52c0efd7e2c2319aeefac74440c653b0af588cc5002850a6d75ad277d7"
    $a4="64bcc739ba5a7eb47d0b9539fd8d36a6a2b86100f91b430e938bf53ef6a4805b5bb99febd6efc818d0132a3b57505106f707478f377e0220689e8eac3d3a51d6"
    $a5="0391a30a541b439912bcd9e8ce336224a538c74d3cc61265eb04ada3e8a1fe88c26f02792f56034deb488a8543570be0f5cfd928c0fe3f6a09b5996e3da926b0"
    $a6="64bcc739ba5a7eb47d0b9539fd8d36a6a2b86100f91b430e938bf53ef6a4805b5bb99febd6efc818d0132a3b57505106f707478f377e0220689e8eac3d3a51d6"
    $a7="bfbf96e4630b0533b4eb0f54fd32ee4ba4084ef74a7b9c476c12c1e17b3f943dff4b7e8ad15f01278678506d0c33913dcf63919af1b55fdf640b4213ef2b339e"
    $a8="b3275a7674bbaa865b849aebe272e3319470e61ffd7f7b2763c3cb027650a63e4d6a4c23abe7d42a7e65059d9400180041870e5b05815ef4fb8d445448a6a501"
    $a9="32451d9f7852e53f251179963b200457b3f5348e2e44b326b398a957dad44b67eb1b75547647cc02c98d928c4e6944882c30567b69089001e152e25145edfbc5"
    $a10="64bcc739ba5a7eb47d0b9539fd8d36a6a2b86100f91b430e938bf53ef6a4805b5bb99febd6efc818d0132a3b57505106f707478f377e0220689e8eac3d3a51d6"
    $a11="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="MW5zdGFsbGVy"
    $a1="NVgyMDAw"
    $a2="aW5zdGFsbGVy"
    $a3="c3gyMDAw"
    $a4="bWFpbnQx"
    $a5="c3gyMDAw"
    $a6="bWFpbnQy"
    $a7="c3gyMDAw"
    $a8="czFzdGVt"
    $a9="NVgyMDAw"
    $a10="c3lzdGVt"
    $a11="c3gyMDAw"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

