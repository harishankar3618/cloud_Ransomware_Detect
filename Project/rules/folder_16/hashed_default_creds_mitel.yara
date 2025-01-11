/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_mitel
{
    meta:
        id = "4SN57x8oEhW9KVjrDlyAzx"
        fingerprint = "1ae9caf12a7094d53978bb9fea50d91ac5e314a7edf14bd4122dc97f9f529b87"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="f441f41aa59214cccc3d4ba5ed1550cc"
    $a2="fb2c93d6b3efd4457eda5d20946874e4"
    $a3="a37c2cd2c0a5415745e9d1fe1a0d6367"
    $a4="9ac57542fcc0f81340609112c9027171"
    $a5="f441f41aa59214cccc3d4ba5ed1550cc"
    $a6="926a8cfd663015507720a7c1d476aa55"
    $a7="a37c2cd2c0a5415745e9d1fe1a0d6367"
    $a8="1ebdada6bd574848235b783ff6578fe6"
    $a9="f441f41aa59214cccc3d4ba5ed1550cc"
    $a10="76178e956fc1907df6d1eb623675f1d5"
    $a11="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2e19393cc5ef67"
    $a1="6a77f1277b51f67f"
    $a2="45e7b2790e3769f5"
    $a3="109be9900d0cfff2"
    $a4="1c26b9ae492e1421"
    $a5="6a77f1277b51f67f"
    $a6="45e7b2790e3769f5"
    $a7="109be9900d0cfff2"
    $a8="5d2e19393cc5ef67"
    $a9="6a77f1277b51f67f"
    $a10="465ff47d58c823ca"
    $a11="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a2="*635E70FC0BC3484295E6605F5AF0490732538A98"
    $a3="*432DADB80863E758A32913E510F74D01A605B00B"
    $a4="*37094A8E8BF520400ACE0F0679DEBE38C7143714"
    $a5="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a6="*24223885F235CAFE7FD4E78C2A79F4BD81EB3AC9"
    $a7="*432DADB80863E758A32913E510F74D01A605B00B"
    $a8="*9326E8C9853E62554E9C233FB1C9431E29540BCF"
    $a9="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a10="*45F2C3B4476FFF9AE3E6335C54339C17B96DB83B"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a1="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a2="{MD5}qbe6cHg7YX6ZmNxN2C6zxQ=="
    $a3="{MD5}lzhCYbi7+WbfFuWtUJki2w=="
    $a4="{MD5}KzUbvAahUGqHd8yMZlGFQA=="
    $a5="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a6="{MD5}rHtN/lGdp5YOsnuY+HgKnw=="
    $a7="{MD5}lzhCYbi7+WbfFuWtUJki2w=="
    $a8="{MD5}YhgdG/cvbery+mETDHK7Dg=="
    $a9="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a10="{MD5}PSFyQYzjBcfRbUsFWXxqWQ=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a1="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a2="{SHA}48u6iIP+dGxuNXg8lAS0vAx+6es="
    $a3="{SHA}L8QtN/7iyB12fgn7KYtwx0iUD4Y="
    $a4="{SHA}pLVC7Tyc/G/QyetxOiwP30b1grY="
    $a5="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a6="{SHA}S6+vlh2KeT6+yxWA64SSfP6eNWw="
    $a7="{SHA}L8QtN/7iyB12fgn7KYtwx0iUD4Y="
    $a8="{SHA}W7afddIWw3aOpFVB9H/x/dTC9nc="
    $a9="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a10="{SHA}GpuVCLYAO2jd/gOpyMvEvUOIM5s="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="54b53072540eeeb8f8e9343e71f28176"
    $a2="a9b7ba70783b617e9998dc4dd82eb3c5"
    $a3="97384261b8bbf966df16e5ad509922db"
    $a4="2b351bbc06a1506a8777cc8c66518540"
    $a5="54b53072540eeeb8f8e9343e71f28176"
    $a6="ac7b4dfe519da7960eb27b98f8780a9f"
    $a7="97384261b8bbf966df16e5ad509922db"
    $a8="62181d1bf72f6deaf2fa61130c72bb0e"
    $a9="54b53072540eeeb8f8e9343e71f28176"
    $a10="3d2172418ce305c7d16d4b05597c6a59"
    $a11="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a2="e3cbba8883fe746c6e35783c9404b4bc0c7ee9eb"
    $a3="2fc42d37fee2c81d767e09fb298b70c748940f86"
    $a4="a4b542ed3c9cfc6fd0c9eb713a2c0fdf46f582b6"
    $a5="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a6="4bafaf961d8a793ebecb1580eb84927cfe9e356c"
    $a7="2fc42d37fee2c81d767e09fb298b70c748940f86"
    $a8="5bb69f75d216c3768ea45541f47ff1fdd4c2f677"
    $a9="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a10="1a9b9508b6003b68ddfe03a9c8cbc4bd4388339b"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a2="bfb6d0743bfa948afda25ea95b22a9e5c7a9fe05edda710f449c3a48eafd648dc7280b3614d59454e7ca1dadc9fd193f"
    $a3="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
    $a4="da46068206fe2c7cb44ad48360ff1f4508e083d06beda566189de20b31ae7d6bb3c9fa4221f3c2582791a1c76e76ab1a"
    $a5="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a6="bd7d21d20a3ef1cc135b93a5089c80da734b38e5ba80a9e44fcf63e4268d409cfb9ddde2f05933840a9c430f06a1c2f2"
    $a7="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
    $a8="7aee27d886b37b7215aaca74429b3886f14c9af360d86f9bc8307bb2a0bfb2e14e01766d75dd552efa5d55064df29f7f"
    $a9="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a10="7ffd57cbcd46bc1359d376fd84a4301e2937322afdfd716933db49a5aae2aa59511dc8d3143e2cf55d00ef0135b1a7cb"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a2="7052a6177e32a37a2afe962ae2cbdeb9f66b732dd2728ff4b72b6c70"
    $a3="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
    $a4="b5b30208ae87c74576c6d25caf56b4056c4c231a12e4e7efd3f23d9b"
    $a5="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a6="f372f6497e53dbadc744424593881d57e2536173ceac4a7542b1d476"
    $a7="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
    $a8="9de5a8a043c194ded5357311049061a33092ea93db18013be8ce06f1"
    $a9="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a10="2cfcbdc839cf550004a0115a366cd5260becb7269f038e2a1911f44d"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a2="1227de669e122a546edf39f0ded50cd2b6332793dc55d835b21be05bd529511655877292748c25f8fc2b5f1d5c987d9aaed2fc92c7e59a448e51cdf1dc5351a3"
    $a3="b77fe2d86fbc5bd116d6a073eb447e76a74add3fa0d0b801f97535963241be3cdce1dbcaed603b78f020d0845b2d4bfc892ceb2a7d1c8f1d98abc4812ef5af21"
    $a4="f33cbc9e2655d55772043dcaa15d9a5fb813d80af5fa4a5ea606d48cb847f23d73e8cb90b88a0781d3e9fc84ed4aca57267c07ec94f053bf5553c05ebbc01e88"
    $a5="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a6="7786d75d8aab53ddcb1a6e4ce1355f77f6014457d200f39b1770d2b6df5aa5780cf94897bcf645a39324feb9bc7e4093e3bced058b2e180eb4794d5192d7f07b"
    $a7="b77fe2d86fbc5bd116d6a073eb447e76a74add3fa0d0b801f97535963241be3cdce1dbcaed603b78f020d0845b2d4bfc892ceb2a7d1c8f1d98abc4812ef5af21"
    $a8="9ebaed300bc94f411d9ca29a1978854c4d3e756cac711984feab247c471244d48d87352a7a1d0759040a02134a5673eb34294279c32078042838ec1170dcbb7c"
    $a9="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a10="4cf5a5be41f417cb2087f1f17e44734ae9b1677dc6b0ed3b80de422cc8e5607980ed08334540c15966485db039927bade22d3dedd5fd3b3f7d9743c20310882c"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a1="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a2="40510175845988f13f6162ed8526f0b09f73384467fa855e1e79b44a56562a58"
    $a3="9c0d294c05fc1d88d698034609bb81c0c69196327594e4c69d2915c80fd9850c"
    $a4="6dea2fd9a583c0282664e60a3098927a9c03e657aca81dbce4933918ef8de56c"
    $a5="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a6="ca3ae47d8dd2bb66ff93db17c4bab27e342efcfd005d42500d145e1b90fa21df"
    $a7="9c0d294c05fc1d88d698034609bb81c0c69196327594e4c69d2915c80fd9850c"
    $a8="be9f5523427b09f89f3c488e56d2b75abc4383ca598eb5f106923286bed1dc02"
    $a9="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a10="cc399d73903f06ee694032ab0538f05634ff7e1ce5e8e50ac330a871484f34cf"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a2="7ddc031d248afaa667adbbf62b2ac3c51adfe92e03e096ad5bf18744fa42c4d1a0b5b3b77163d297cf6fd6af0f05efca0051babe5f4fa0ec0e7a8fc62a39997b"
    $a3="78029416f2a036f9bbee2b4519a452479916558edd66a43816bcce88d4b0269a8bb63062747ee448b35fdd05b00abeaf5003014087011ff134b7a00487caaccd"
    $a4="3b4b8361cdf7e18781e0219dd1d2fc2afd20c9a4169607aa1f6c7bb993f4e9612edd7ba0db4c837d85a63813a0abc32a3304950d4502960481fff2ae1eb48b4a"
    $a5="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a6="c6c0d57177a4da5c7286ab21cc85f3a9b94855c213d6a74dc49aca11ee54c812288f673086fd33fe1e0a4d6ddd619b7d54c60a01ce2a6b417f4d38b9c5701c44"
    $a7="78029416f2a036f9bbee2b4519a452479916558edd66a43816bcce88d4b0269a8bb63062747ee448b35fdd05b00abeaf5003014087011ff134b7a00487caaccd"
    $a8="a540371e43a8bb9b216fe593f5244244deb9d07c89dc0b2b0ab8f37da9d9d486eda2f2134b0c71d5703f299376868a0980d9774debe94950948e2d7ad731c8ae"
    $a9="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a10="368124278d8ad5057ce1abafac2b9b1f840600db8f7714cdd636017624dec28d3af1dea646c382b638b40c09dc695e9222f864e6b249f7afa5ee51ebdd5e533e"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a2="c75ed8287226f3c168be3cd1376b7985c5bd59569c319e8afc72efb0669a1773"
    $a3="293eea3b1d83925a4c5794c9d2a7a049b796ba4831e66bbfff5ea318a264cb3f"
    $a4="5a376174451d097446a40e96ff7824e8b4830aa1465b73354c78b4fe460426a2"
    $a5="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a6="e137be03919f8353e441fd08f1ba0499bc46b84bf1588d9a3a1557a55d59fa6a"
    $a7="293eea3b1d83925a4c5794c9d2a7a049b796ba4831e66bbfff5ea318a264cb3f"
    $a8="1da0fa7bd09969cb110131264cff16dc52e0a0c48e5d3cb05b1c23fe64cb370c"
    $a9="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a10="255de72527d9901c4324c7af5a920740097360f284a3de8cd907e0bd91c7bd59"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a1="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a2="0be990d7a9d0725d4109145a6454011ba2b98f4df551faa5cff989c7"
    $a3="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
    $a4="8f4ed792f5ecbdef4a7d813a9624f71e924ac4f63eb75408fcd0f897"
    $a5="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a6="8d7a2be72d89dc32f516c2bd0f960f3f0f32fc0733f2e8373cc4d5b5"
    $a7="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
    $a8="38a99f28118b7143051a3d2ab3719a64061501003cfa1b7949648495"
    $a9="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a10="bf5b5c7f32e8b4ae23803af71b0f1c6eab4508378e00ea966d652979"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a2="6e9d54d7ebe3029abf15866b51294ce3defb2bc2c27762570819f0959b250499"
    $a3="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
    $a4="ff5be1154d3a9d628b4c62b2b13d1dae5bfe66d2876b297bced9b6e377219a27"
    $a5="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a6="6e47a3ed3b57b60dc109bbbb43e29626d3f695dee5aee9967f002fdfa44a41ff"
    $a7="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
    $a8="e8b886c9f9d7653d27a953cd2867adfe43db18cb9c4cac21d15086dc294dd450"
    $a9="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a10="37b0edec323a7fc924dec259de1b1c59164e2ede27fd51e830dbd6bde7d00839"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a2="78a64f797e9b1b1b2c93c298872e750df0786e31c30a8d277a01acb8052c6021ffaf004dc8ecc7966491be148aa7d2cf"
    $a3="18b54a8de3ef7af582050541d99e85e583708db04970f30d1fbbbe5bd22a3926c2147939e2be80a83b4f325ad72cd7fe"
    $a4="e00dc50afedcce026b1f7cae071bb78721ebf4f61149ce3b3f968cae250cc08485d03c7d0da28616527d5a8359f842c8"
    $a5="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a6="5397476ada680c1c22bc89e65ec2362c0b2c0ec961241d95613422c8d1890304373908b86b00b6559f87e5ded6cfbd90"
    $a7="18b54a8de3ef7af582050541d99e85e583708db04970f30d1fbbbe5bd22a3926c2147939e2be80a83b4f325ad72cd7fe"
    $a8="429ac44955752ea87f553303d485b159ccf39873bdab5da9acaff9cfe393ad413aca035d907a58d1e860e850fefcbc51"
    $a9="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a10="6bdc1b784f4a65070782b0168fe535716083235d6de618c10a913145b5d78669e7565a1cdaba90a417d4641d95dc02c0"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a2="c198fc70fd688cd9a7c5d67d72c4f8aad8031a72745987dfe4291867a3ae50625a642ec18c5663e9375876a825357a5a7cf2463b9b7809533f2810edb7356331"
    $a3="1e60cc099bc0ab00cbffb311120b7ca623df6058beb22ac37f5101883128bd5777e26c52c0efd7e2c2319aeefac74440c653b0af588cc5002850a6d75ad277d7"
    $a4="cd0701e7cbf73293f245c2fae91b07f4f9492601b9d1a544ca245ac597f9d3be625cf928d05a68802ba9d7f2367805cd5c3a978e3373e1545a309b81316ff4b6"
    $a5="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a6="201a3cdd56890e2d1a57d31721c317b57309cc2b36a8e962c8acf1bb766c3e4dc4b673434629cd9145abc5d678284811a9594562b5d02d8b507975032a37f32d"
    $a7="1e60cc099bc0ab00cbffb311120b7ca623df6058beb22ac37f5101883128bd5777e26c52c0efd7e2c2319aeefac74440c653b0af588cc5002850a6d75ad277d7"
    $a8="67924888eb2964206b2f12c3a6c094614c64700a8c862144432ec4dfd452ed5636767bff113aae6a3c9c8dfe5f5c8d41ee5d0d47555c5d7118093c1cdfdc5713"
    $a9="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a10="cdef0c740bfc6224a650219c6266edcc491f6535c9444f21591423b95cc7d63344b2cf83e2c81f0143141f0659b3aa31996319b932fdcd6c4da531684bd58de9"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3lzdGVt"
    $a1="cGFzc3dvcmQ="
    $a2="aW5zdGFsbGVy"
    $a3="MTAwMA=="
    $a4="c3lzdGVt"
    $a5="bW5ldA=="
    $a6="aW5zdGFsbGVy"
    $a7="MTAwMAk="
    $a8="c3lzdGVt"
    $a9="cGFzc3dvcmQJ"
    $a10="YWRtaW4="
    $a11="MjIyMjI="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

