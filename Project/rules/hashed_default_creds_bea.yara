/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_bea
{
    meta:
        id = "6aJkQFt4xX4I6W00tz1ojX"
        fingerprint = "62206ff33d2b472e8c5411ef4c785b96878065d28d49a58b223f149ccf8d3674"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="58e8c758a4e67f34ef9c40944eb5535b"
    $a2="d5e9e0db50ba46b948853221be26da2b"
    $a3="f441f41aa59214cccc3d4ba5ed1550cc"
    $a4="50838b21bdef4bbe69c770f8ee7169fb"
    $a5="f441f41aa59214cccc3d4ba5ed1550cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2e19393cc5ef67"
    $a1="7b57f28428847751"
    $a2="1bea6e365840ca17"
    $a3="6a77f1277b51f67f"
    $a4="56b6113a2cefc6ea"
    $a5="6a77f1277b51f67f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*60D178145669A4D1569FE820852BB3425CB2D4A7"
    $a2="*1FDB0D828172183735F1ED9E45E6AF3CE04DE9D1"
    $a3="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a4="*89DE4724E0A55726B22671EEBF685D932B6FF9CB"
    $a5="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a1="{MD5}j/MkifkvM0FmlL6P3C1MIg=="
    $a2="{MD5}6R5jSBV4aN6d2LJcga6/uQ=="
    $a3="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a4="{MD5}SpY3Tmzt1eqIw0CaMXowTg=="
    $a5="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a1="{SHA}FqmlTd9CWZUuPBGMdjE46DaT1/0="
    $a2="{SHA}jux7xGGAjguKKHg9C+waOiLrCCE="
    $a3="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a4="{SHA}65szVNxFtj2EVicUi3ePTD1UgxE="
    $a5="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="8ff32489f92f33416694be8fdc2d4c22"
    $a2="e91e6348157868de9dd8b25c81aebfb9"
    $a3="54b53072540eeeb8f8e9343e71f28176"
    $a4="4a96374e6cedd5ea88c3409a317a304e"
    $a5="54b53072540eeeb8f8e9343e71f28176"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="16a9a54ddf4259952e3c118c763138e83693d7fd"
    $a2="8eec7bc461808e0b8a28783d0bec1a3a22eb0821"
    $a3="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a4="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a5="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="5759ba5b71427e5ee5a02b2f71ea7456a0a2094f93d03b38d43613fb600c0a30924a8d2b78a249d7e9ba17840a6e5801"
    $a2="7d376d415ff3adbd0789a49e08380520f5e7822b9a6fa5039943bf2eb12def6321d3899471be27e27f69e2fe8a58e29c"
    $a3="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a4="f0eaf6f35ca40378802883b7cf06790eb1c7a520338c57abe49124b3bacd1ee579ee4675c444a90045c93d621fb49bb0"
    $a5="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="c7e8f969fb2abbbe56a301c5bd65ca0ab772788b274d244a55e5e7f9"
    $a2="36e21f2bf0c4247e491d0fe56b2874f8de7aa584a04e88254cc14bbe"
    $a3="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a4="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a5="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="226c72af6fd3dc3ba3c50d56b43dc79cc93482c57a1359089cd6cbf5a3e5095d0bb435609df2290bf126295dab0d8e1fb45409a348bb223eab5f29622f012b95"
    $a2="f2a46a9101d3b65c419c98a9ffe73c154196bc3e87379491746cf5a70ee0b5e4d308b27b28f77960582d8ff88ab7c3c4930860436bf05d6d5517c8e3f9efb8e5"
    $a3="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a4="5af950b6531642271d1fd9f9c52d40b631cc64917067c599c0387e6b5f4542f99cb9f5fd1d2ab5446c4c309021700d36cb72948fa73615f63eb73354d398b6f7"
    $a5="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a1="78675cc176081372c43abab3ea9fb70c74381eb02dc6e93fb6d44d161da6eeb3"
    $a2="5d2d3ceb7abe552344276d47d36a8175b7aeb250a9bf0bf00e850cd23ecf2e43"
    $a3="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a4="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a5="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="f8f7d4cf34169fba37978f77972a1261ec3731be9d53ce8a4afc684a42226a19f3ee17578b0a838d75d8e5b0bb0dc2782eb0ad8c27971af4ddf06778c06d0dd5"
    $a2="910a5dd56e159138447be1627f041efd4a2d76795420b001460c9088f4e0d9d5e7e32276518544b40ac958491793d557b62fe8c1141794bf94ee98ffe681283f"
    $a3="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a4="4da10ad39159033a05182ec267c0b6bd8b5cb5953dc1a26a501a57343ff4412108c3dc266fa51453c720fe3634267d31614f4dc87c954f78e66b996472e466fe"
    $a5="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="f4ccb9a16537e226102b6f5b85c2ace40d5140d0cda8c0ef07a08b8cca87bfc9"
    $a2="5ef65cc2ca9c5aea4bd3a676ebe0d4d0830ef86d040b6612912cfa92a177e919"
    $a3="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a4="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a5="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a1="c19957d1594ed5e0474847c416fb91e9dc8ad3668e25fcc3971a3537"
    $a2="64a5f4e4de37bf608e98ea275502ca5a18e4438280cab8467e59b98f"
    $a3="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a4="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a5="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="c7c348cf88383c25ae5c394ba71c2e92e7698df98c7f523cf8aab6bf9965ff36"
    $a2="10414145323772df86d67f55a07a80e989ba7d893f8fa9a79031b2d7000ecdb9"
    $a3="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a4="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a5="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="85329d087922707acda4d9039e6e2fb6fa648aa587412db830d10e861754f6212ba96fa16cadcc19e038629409ee90a1"
    $a2="e93d6fd44e5a6e57fc6083328ed79695f48fec43cab2e5b2d797084fba8ab17ddcceba629dbbf75c6fef680193fb4c40"
    $a3="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a4="c54f0043b456e5b813e530055fc8e47745146b511db337338eabb6be7863f31f1142e389d853f8d476eef73703ba1209"
    $a5="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="085294bc9669dc8d9591758b9caeccdd8127c9d6aac8d81bb55cddbf6fc01005f38332128ea682e92983cb7c3f033705a32295afa868a3cf989b4494aabc8fc2"
    $a2="9590db8c6413f2ef63a7c9c616a73be75b4c1a95fa38a802858077a9e2d4ad8b644be584e0457ed6248426dedecc970259ca575adaf1f0a171c9e0085617387f"
    $a3="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a4="68aca6a399ef9122b29eaf0843ee168d5116c02844c49c2067efd3f6db9b298f6a558bac77e9a99a40fb386c31cc74cebb2220b3be9df685ccab1118403db033"
    $a5="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="am9l"
    $a1="cGFzc3dvcmQ="
    $a2="c3lzdGVt"
    $a3="c2VjdXJpdHk="
    $a4="c3lzdGVt"
    $a5="d2VibG9naWM="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

