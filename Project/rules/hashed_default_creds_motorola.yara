/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_motorola
{
    meta:
        id = "U83ite2u63qdpfqA39o9P"
        fingerprint = "2b6ee599c15cd4c1f4ac953b7600b27b95f930ddc07feba5dd9fc420e0108a97"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd2351189d57d6cfde9e8f9cb96da06a"
    $a1="8d9be21fb0084317457f66e8ad649ba8"
    $a2="99aff69ed25ca5f45572c5503a10d28f"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="4ba57c94d500dd36627fde8fc037393b"
    $a7="f07206c3869bda5acd38a3d923a95d2a"
    $a8="b9caade7bf386df6ff023c57fb5e74fb"
    $a9="12150a212f41ef5a9cc0a17db93ea4c4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql323_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74c9ca336412b401"
    $a1="4047f2fc067ea544"
    $a2="1d8545b70205dda1"
    $a3="43e9a4ab75570f5b"
    $a4="5d2e19393cc5ef67"
    $a5="43e9a4ab75570f5b"
    $a6="1db9c3684a0efd22"
    $a7="75f8469b7e1d76be"
    $a8="71c7b0550d2c0344"
    $a9="05b61030502fee27"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql41_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*63DA4EA8D1848C115BC12C4956B7ED85510A216B"
    $a1="*6EBBEE79F2314B26A7D8BA22E2B652D43A997EB0"
    $a2="*0F6DB8D764AB9D89DBB30DAA5B682B889569D4BC"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*B4FB95D86DCFC3F33A3852714DC742C77504479D"
    $a7="*C80A94EF37B4CA1599BA47CC95530C43CACD7DA5"
    $a8="*C426DB257270F4338CFEC8DDD210CB33C738FDDE"
    $a9="*89454C1CCBF535F73F185D2994A97B8F83A63EAC"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_md5_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}8zlc1Uz4V9348gVnaP9Jrg=="
    $a1="{MD5}j7BHGaSUqwbTLWbeqzwKVg=="
    $a2="{MD5}dQN5tZJun3KKpsJT0343kg=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}Pdrrgvu6lk+zRh1OTxNC6w=="
    $a7="{MD5}qqvw05lR8+bD6KeRHfUkwg=="
    $a8="{MD5}mcwvX4TVIAV8UKDrTaFb6w=="
    $a9="{MD5}65GRduusIJndAm7EFSS3Bw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_sha1_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}d+sdtsuBs8sIjTareq6PIw3Pqig="
    $a1="{SHA}rVlPF9ZX7yHVnyAS9DiNi2U1LV4="
    $a2="{SHA}UegixQzGLNvbhQpDnqdbbUWsSHs="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}JvWArg78aQee2aa+6g4wKIrZARk="
    $a7="{SHA}TPW8Wb7p4cRMYlS1+E5/BmvY5f4="
    $a8="{SHA}cpRKF8Bu7b3YPWv9jZmZ6KIjZjc="
    $a9="{SHA}VdJYAPuCuimiZ8kyMAqqihl2e3U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule md5_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f3395cd54cf857ddf8f2056768ff49ae"
    $a1="8fb04719a494ab06d32d66deab3c0a56"
    $a2="750379b5926e9f728aa6c253d37e3792"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="3ddaeb82fbba964fb3461d4e4f1342eb"
    $a7="aaabf0d39951f3e6c3e8a7911df524c2"
    $a8="99cc2f5f84d520057c50a0eb4da15beb"
    $a9="eb919176ebac2099dd026ec41524b707"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="77eb1db6cb81b3cb088d36ab7aae8f230dcfaa28"
    $a1="ad594f17d657ef21d59f2012f4388d8b65352d5e"
    $a2="51e822c50cc62cdbdb850a439ea75b6d45ac487b"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="26f580ae0efc69079ed9a6beea0e30288ad90119"
    $a7="4cf5bc59bee9e1c44c6254b5f84e7f066bd8e5fe"
    $a8="72944a17c06eedbdd83d6bfd8d9999e8a2236637"
    $a9="55d25800fb82ba29a267c932300aaa8a19767b75"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a055b36f9947efb7fbe1817e20e14d5f4c4815a0d51b089f1fafa2e7cc8909b840b8e455dd740ce6313fa56419ad86f"
    $a1="0b0920075996b936192ff5550f153b2c845184834abf13fb67ba8dc07ff728d7c1a809919d044de3974d14a18c1d6e67"
    $a2="f90af180966a30a4bb42c9a2e5390e12279336d0355d26c5746219a2d5d2cc60793fecdd3ee224cc0041678d2238159f"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="683efc8fb8cdedb8e52255891bdfb91afad01b7d31b746a0ecdb8760d9e334365338ab5943f35e22c424ec3c65fa4404"
    $a7="66e17cee68b63148b492c1e60cc3b9c85161eac639df6ccc878f251b056eb1a1994c6e81f1f6971a3ada23434c9c5ef2"
    $a8="0d2542695647320ec0bedbd6a467fa94320835293536b8d12903950e6d0df65c6861f98eedb45f48fcc71496fb2f9a80"
    $a9="f507f1638f8d1ed7fd34b4f6ebac79309f2ed1bfa785ae3d6558a701c8af466af6ef1a9ae260bb0196039ce2c7d6b514"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7902f17d6164ee01ca4f8ca79c3e39618b64e93160311f2e8e9d402c"
    $a1="b6ebf0805e8f23a423ccdb6824195fff219f53040e41870933a03b57"
    $a2="e7c6add1676a3f5508b4f9833c5a6deb83848b18d0f82b425365ab1c"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="fb22dbd3dcf0b2ad8e74079e7db330b08b16a9cdca3a446bcc402a7c"
    $a7="3496179ea8bd6210252a6aeda9b8b598f0d4ef126328dca4a817d5f1"
    $a8="98e6eae7336c91abb2949ddfb5f1c0499cd36d9c3c7b83997703ec53"
    $a9="60a3e7db49689e427d323d69d8a9ef86af02a3b4668bbd9d17e22e50"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8391976da1e82092fa39893979d25f9714e39ef9367ecd90b15eefb8b7b80540e7efc91ad74abe135d0e7eaaeebdec1e126e840471b2ba692e04447ee85366da"
    $a1="baaa60c571adfc75b00432283b6fc4293dbd366f4b1f031e85f32251b4298b25fc49c74791014b158193b3c2f5de52077d5fe94e5a0820165b2330e63cd9ce15"
    $a2="2aa271963bb68c9bf0b44736814a288bfccc0a5d1802e1ee2c2b653158faef9e6d66e9f805c8fca303d4d82d97e2b5d613f792410b2ed50c044a0768398b991f"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="8309dd7c52675caaf669868c10bb5616d28daec1e47001277118e7832a22fa7e624a497edcae4a8eb0c74b9f2f64882ce7978492b99cc4975fccece756c4712c"
    $a7="b719607226d34094f53b043491697d98875096ff36bab4aab89da12850ac56195b183a0170976efbe29a6a4ddcc1f114b8f00154933ba6f766d82e5a63624eb4"
    $a8="be460ecd19614bd7d5a1e127a0d9e717128c5472b4555017f8f053a9c1856d5c1816d69b3e061e25d7045e7c00b2473b75418cfdd4e919253d3c7a37721f6984"
    $a9="1008aee4cee1463834b3eaf369b8e6788f456bf39d1cebf505697ec8701b685e95b37d2e05d8ee2742bef77debc7af52111b339f926871ff33bd3ec2c314d9bc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74c95604043427f0bee1d0e16bfa53afd537f736ad0073c4cc4e1ccb3a82b5dc"
    $a1="5fd27b27dd78566133180b3e86d5ac88439099188593a375302bcef9f846eb3b"
    $a2="0c44be9f7948957db073a1f24c266b07508b127ec030b328269ad052d7213aa7"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="fa1eadc4c6995667412681c69ce33adfc9302a2965f521c40908549e670e2e4e"
    $a7="9df6b026a8c6c26e3c3acd2370a16e93fffdc0015ff5bd879218788025db0280"
    $a8="24319cb915275f937eefa4e8fad430ac0a971177756850b7f0e49426b69c744b"
    $a9="29ba9d9cef5a66461116a24938bb9307e005c35aa1bb909f16aa5e85bd767480"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04134ddd131165ad52bcbe11800875556c75245a7dde83d127a2e83bba0fc9cd5097b1c04c743a75b224c28d9326471da47991869f2e05686e9c1da69eab192c"
    $a1="8da5525d49c047c516f2d19e05247aae07dc54e5d94ce1af5f4c099846113fca3f34950635d4d08aa057126009bcdd67a3a21a79186d4c7c5f50ea6738018aba"
    $a2="f1e49137c65993da285d960add379c5b1f63d9fbcee77026e3e191a5da7db10d5eedca3b4a5df348aa95bb75b5b914d3b0c3fdb10a3a9b99de8f118269c66ae0"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="b75c8c42a1c9216da01ffe3d1f1854706c5dc40a306a6bb76916e8bb93983d469542180373ca305ad5bbf8abc70bce61776f147eb2e041fd8e5367103d674e08"
    $a7="9c0204c6a050d1a92ee3e332261796068dce670fd22f28ddc6e153e708948b30bf9d735ba1efd51e61b6876a2969ae32c3e3cb8fa1076a62c22165022d735d1d"
    $a8="7465b053b832bcb98d162be89dbc054eb945b3e2ca42f99b2c20189b9e3dffaaf872a4b077d46026a4451305221fa6c94dc934d7a544f9295ce7bcc23aec31a8"
    $a9="5860893bfed0ceb5b3f4f874bc3e6256eabd1b3091f0cec26132ff8591b290a2647dcf236c153ac3895291cf2074dfa5ca1a5e0ea159cede8d84857cba17b5b5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f45b3f0eb0c77db94cd9e089c91e4af34cebbf60034df9a3bf0642239af32f8b"
    $a1="4305c8368fb76b838cb16a4334a34499323bef73919dc970d8f13ccdfb42ef9e"
    $a2="e922f7b90d222ccd09d1114614152e9b533f300da2c3c9eb6124af77dff2a528"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="cef0603e0ff8eb1842c0822f0fc3974b996589f8c15d8b82e95561054c29d159"
    $a7="b07dad53a0d27d81641f20c700df09617c238f16d36bfda78b5a57d71414f486"
    $a8="06b07472610e2f84d641236081940a65d124e8f814c54fe4536b834d70d411f7"
    $a9="27621d65151802229728aad129e062d4b30a3bd77a960bb67d412dfb9d818522"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="283b91b42fe837604b6c486310061312bc2887abdc821416b858521c"
    $a1="3d485d081fd9f8aeab0a900813700d2ffffad79267748f753b6438c1"
    $a2="0f0a9fef8fcc761fcfee0e6757bfbe09741361f7b7df68ca20eea036"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="fd9dc48ed52245c81385c2a50f69254ef2318efd51650adb441113cc"
    $a7="eca023569110ac72502e1e99d327f1ded5bf0e556747a883074b26bf"
    $a8="fda7b94b1afd7d51ea37c37632bb79b0f19499cd05cb47d58b7bab2c"
    $a9="3ee9a89c78349023a55c7e7b2f67e2c8de518495961090c74b91356f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae48964325684403f4239ebf3de09bea8dce035f40ffc0c03959300538f476bd"
    $a1="edac5c28b92c7d127bd2b5557d6ee6a2491cc147103ee5fb16bd39100ff30c58"
    $a2="34f06ccb589e19284e83e1669bae6358d6a4c6b23698dc3114b94adfd53faac9"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="ed9e36fa06a282d0572283f9332e1008e159ec1d234e55fc4316c7fa0f3f30d2"
    $a7="63e5b5a4137cfa77cb9d10adae081d0df082a826d8441721460d5933f5800056"
    $a8="a7797efa8ce0417f3f0242d74182c431c6a6b5c739348afb3b01d8c11cce36b2"
    $a9="92a2396ac62ab41d712a66589901cb680160f38cfe0359b0f0d35f6b5d35251a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09115bb74c0f96f7e0afc093d1343c10e8f97a5ade755b5e3add1dd2ea4c5c11f6c0d8040aedc090e86ff68eee98da1f"
    $a1="d1ef2e826150dddff72c5b643142f61c25b0e529961693fdea0c2f3f7e9fe3d422bf5713d43d632acbc44dc7c7724495"
    $a2="9e67fc27dc82a040f4d69afb4f21404ddc2939a6596f898eb849afdff339bf4021424076a0c9abedde240ec9c9f743c1"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="f3e35699f5b5c65615b9b77e56cf9a027927da2779f7e249a2971408801ee28c739c2de9b95a8bfc94647e1033239a71"
    $a7="c81d6422d13cc3fb2ced709500d1acaed5dacc81f52c9adbcc20a6a8cbeaa38fa04aca067480c67e6ed909e5f56e618c"
    $a8="31b5e246ef3f10c8f47695ae15579dfbafded3cd41cdc02a2610c519e9adfa34352a60db6e6caaab5cb6430c52e2e478"
    $a9="9f2d4fa5d014018b928656b25ba1bb19c8c30c99608f41f03ce47d63ae09cd9a87efaf5fb4b93fa21db220ef57c412c2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3fd49aaf123262c9488283fe59596fd271b6e9da0978e5d9cee0168c078996d9705fb03528f2a49a2136b81bb9008092265fe7fc2d082279296f83f37bec538f"
    $a1="b494d71e9282ce0e4abd722aea47bb98179de1bb997655da07a9e3d4e29eaa169dec383ebe573b59c36741f70a517d513dbec037fe13b451c01d88a9eb3023a5"
    $a2="afa4f4598504512a701d121a0102edbaef2723e764399535d30b7f1976d204de734a67d495cb36c4707c042b4b7b90ab8dd0c8ee2120f42a21df06777fa9992a"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="aa0f96477a753c367edb9be48f0f5561d5ba9136c6cdcd9b59415966301d6c88b3df8eb446fafe1979321d7b81677c22bec39485bb2056a0e76de73d5f32286a"
    $a7="cbab59d74fea767f62a9cac3851b832e01570b54280cbffa7bfe6f0f57352199adff8fe9530a129101047560f0992cc6990116bf8d38bcfb44f8ebd2bdf517fa"
    $a8="0c757889a9243541ad16cae83b4d1aaa03b4206691d9999de0846c21839677b5c56bf79ffe3ebff27b2fd914b95167053c1f2fed76468a79af1e1fc78021b579"
    $a9="09aeb34e3c243c9d5365b896bd62588df6bde484db7c7dae0c6f3a828bff09c1a1b853eaf2c422349101a7301efeb2e23a80c8bc91f747f661c7af54697ea125"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y2FibGVjb20="
    $a1="cm91dGVy"
    $a2="YWRtaW4="
    $a3="bW90b3JvbGE="
    $a4="YWRtaW4="
    $a5="cGFzc3dvcmQ="
    $a6="c2VydmljZQ=="
    $a7="c21pbGU="
    $a8="dGVjaG5pY2lhbg=="
    $a9="eVpnTzhCdmo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

