/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_schneider
{
    meta:
        id = "62hIKMWc4dTSN7oEbweX2j"
        fingerprint = "a2ee489329a8579b3c72c2286b31cf96a863c3d08c2cd92a706cf3a09b4ac855"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="96388f27c95e6f7b15180198c1226aa4"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="4cc0bb6640549818648ede0d9747696f"
    $a3="67f6c767ad13d1986980a9bc2ba55b6d"
    $a4="d5cf1723c208af23eb6222aec2bf415d"
    $a5="0a6f495948c7df2bdfbab10949b590f7"
    $a6="f71c06917bd3033942e82649ac7f98b3"
    $a7="6d5fd8fe631f0f71625e078548e5d7c5"
    $a8="e768fd2ff41b87534f7aef3e4516adf3"
    $a9="9fc6f8f7b33dab7f3cba2fac269cc3a6"
    $a10="467799ec546cddb461f187080eebb40b"
    $a11="467799ec546cddb461f187080eebb40b"
    $a12="4c845126bfa610c7839dbedc76a8bc1b"
    $a13="467799ec546cddb461f187080eebb40b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule mysql323_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c481f213f3c4308"
    $a1="43e9a4ab75570f5b"
    $a2="5c1f1c181dedb604"
    $a3="35df6f8057f4142b"
    $a4="1f28e3d35c481b0f"
    $a5="61d0d847500347c8"
    $a6="5e15094634fac7df"
    $a7="38914f9560d4d960"
    $a8="32a05c464b1cc97a"
    $a9="4c5d7bda61187bf5"
    $a10="660b73791094ff88"
    $a11="660b73791094ff88"
    $a12="433b9dd07a62d629"
    $a13="660b73791094ff88"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule mysql41_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*50D8F90CF73E583752F255BC8EF69271A86622EA"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*3667E195CEE710DAD1664BB67EC54BD231116A0F"
    $a3="*0F2ECC6C323671315316386889E116408B996D0F"
    $a4="*FEC7882CC5CED39B7D422835A959FFCC4EA205C0"
    $a5="*CE64E548B5368C3DB66764B2C744B9BB4E15B6DA"
    $a6="*C40D504517AF441DF5F7620932541A322D64387E"
    $a7="*E518C52F0A3A97843278BC14F962395227E52B73"
    $a8="*05B92B9BC77519D2B5D2492FE32792382C5A3D6D"
    $a9="*D7B6822013515EE400D953231633990E9E6B21F4"
    $a10="*197A0CC528020173082687322D7D75EB62270AF7"
    $a11="*197A0CC528020173082687322D7D75EB62270AF7"
    $a12="*F8D6C7DD65A3DCC6330E2D9308CC8602B166E63D"
    $a13="*197A0CC528020173082687322D7D75EB62270AF7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule ldap_md5_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}T/rz+20AyDIDozHGNVzvBg=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}BQavRjTfi+VsrX16JkrgrA=="
    $a3="{MD5}b3t7t2kdwgNZ47lsspLKXA=="
    $a4="{MD5}glN58JvyKhmNdiThG5VKBA=="
    $a5="{MD5}zqvaXX6PyI/K3VWgTY80Ig=="
    $a6="{MD5}i+ICN75uEN0iYTQQapOQ/w=="
    $a7="{MD5}5kz6P9WeMt9XADx0AfSMmQ=="
    $a8="{MD5}kfnWyiwWlb8ioisstqVEiQ=="
    $a9="{MD5}TIzjoeAkg4aUlev5SAL6Qg=="
    $a10="{MD5}LkCth56VUgHfTe2/jUeaEg=="
    $a11="{MD5}LkCth56VUgHfTe2/jUeaEg=="
    $a12="{MD5}41X/OkpZYLhVq9viZm5eHQ=="
    $a13="{MD5}LkCth56VUgHfTe2/jUeaEg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule ldap_sha1_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}vrxyqX81S2qynmYSHHxgGyhgAhE="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}cPbUj5TOPnY2u/R0SsB0UJ1nDm8="
    $a3="{SHA}KnF4KBCvOPJWKovcZVslQ1jUFFY="
    $a4="{SHA}dIpiulMTH3+Nu/3i2lYWOmYBO4U="
    $a5="{SHA}P48AD+2QDEoYmpPOSFgoG/s3Dwk="
    $a6="{SHA}O6a+6GU+SKmUWmZ6tzV76wwO9MU="
    $a7="{SHA}pbI/M4ZIy28h4swShOTRt7kwrJc="
    $a8="{SHA}PD5RWQo2ePBuhnvEqNqyIfxF8ug="
    $a9="{SHA}rZqXj+wp/IpWakrKMbGX9snywco="
    $a10="{SHA}brDGEgGpavyZy/GA8cjZPAqf2Mg="
    $a11="{SHA}brDGEgGpavyZy/GA8cjZPAqf2Mg="
    $a12="{SHA}Z+oYFx7ixRzoZy/lGaLp1+0JkWs="
    $a13="{SHA}brDGEgGpavyZy/GA8cjZPAqf2Mg="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule md5_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ffaf3fb6d00c83203a331c6355cef06"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="0506af4634df8be56cad7d7a264ae0ac"
    $a3="6f7b7bb7691dc20359e3b96cb292ca5c"
    $a4="825379f09bf22a198d7624e11b954a04"
    $a5="ceabda5d7e8fc88fcadd55a04d8f3422"
    $a6="8be20237be6e10dd226134106a9390ff"
    $a7="e64cfa3fd59e32df57003c7401f48c99"
    $a8="91f9d6ca2c1695bf22a22b2cb6a54489"
    $a9="4c8ce3a1e02483869495ebf94802fa42"
    $a10="2e40ad879e955201df4dedbf8d479a12"
    $a11="2e40ad879e955201df4dedbf8d479a12"
    $a12="e355ff3a4a5960b855abdbe2666e5e1d"
    $a13="2e40ad879e955201df4dedbf8d479a12"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha1_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bebc72a97f354b6ab29e66121c7c601b28600211"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="70f6d48f94ce3e7636bbf4744ac074509d670e6f"
    $a3="2a71782810af38f2562a8bdc655b254358d41456"
    $a4="748a62ba53131f7f8dbbfde2da56163a66013b85"
    $a5="3f8f000fed900c4a189a93ce4858281bfb370f09"
    $a6="3ba6bee8653e48a9945a667ab7357beb0c0ef4c5"
    $a7="a5b23f338648cb6f21e2cc1284e4d1b7b930ac97"
    $a8="3c3e51590a3678f06e867bc4a8dab221fc45f2e8"
    $a9="ad9a978fec29fc8a566a4aca31b197f6c9f2c1ca"
    $a10="6eb0c61201a96afc99cbf180f1c8d93c0a9fd8c8"
    $a11="6eb0c61201a96afc99cbf180f1c8d93c0a9fd8c8"
    $a12="67ea18171ee2c51ce8672fe519a2e9d7ed09916b"
    $a13="6eb0c61201a96afc99cbf180f1c8d93c0a9fd8c8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha384_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b31bf3fa900da5ae5423ffcfb8523a3a3bf353550336b9d2a3f790795bafa7db09a950cc1ce43b58b6186a4e71f161f"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="962e1b5102806c8a8169f55e210ad3b517e73367f296fa1391a4dda4f2e9fe4d1a2d80e5764b47f031a6b65bc38b6b59"
    $a3="200ce4a0cd99ffbb8dbc1d2414b7c0c216c4d042e7a86d035a8da2fef8eeadd05da0285ac8bbcba2bfc600567f43a7a6"
    $a4="83b33d3fa09c9d68c064d9d8250a8d022cff899a3e5ce77f07c4c6f361e37be2b8bbdb6ded6b20037af9af4398d00fa9"
    $a5="9c0d10f1bbbc84a59f1611cdba9e33db66f00e157f4d254cd295bc3f71a0a849431a7499e23aa6a18a7e605a68363a14"
    $a6="60d668d39888448e9556498bddbc8978969099933afb927e05283f029b91bac415beaf7d70f59fa9ed27af320815c6ef"
    $a7="a3124031782d96ed3c9409bd1872de96be2981a97fc8852b8da482780150cb7b59ce00a12de5fd0b5adcc3fb51839788"
    $a8="4c31fa9f2233521784230faef6e76e1ad97eebd300ef2675ab55ef8dda8b0564ad3a562939020d4ed678ac5201d75845"
    $a9="0e69d9669ab0fe4989553c463d738a416237eed0e502bbd4411a7d55f1284b21d407e087e837042ac27cae5e3651840f"
    $a10="8b7d7cc6f927b7040e35cb0a33d70e264c7317e4e2079517a1c636e588121efec3ba9be57c92a929957e7fa5e8e33f78"
    $a11="8b7d7cc6f927b7040e35cb0a33d70e264c7317e4e2079517a1c636e588121efec3ba9be57c92a929957e7fa5e8e33f78"
    $a12="235defe79fd4391c111c606037e4681de40173d7a41db51c74b4f6d91902dd5dab02f4413b5b780ff8001bac989d310c"
    $a13="8b7d7cc6f927b7040e35cb0a33d70e264c7317e4e2079517a1c636e588121efec3ba9be57c92a929957e7fa5e8e33f78"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha224_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="42fff29a5bfb53e23cd7dfaafd8ac06275514134502ad9d97388e007"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="2a42c5e4eb439512051c7702fe77d5916513550dbf5920d5be088407"
    $a3="42be550a0145ea419da61f3513873d7c976d6d91b53fd85981f496b6"
    $a4="ea0c1ff3ae657c2c79ddebaa6cd411f95394764525c7a3499bea4987"
    $a5="46347396d27b772fad50923e492acb4b8662e03e2cc4affb5e4ef153"
    $a6="335a4dae69567718bdd291d9d684fcda52ef8bf5fe8a8541e0b733df"
    $a7="5a2fbee33fd775ad37848488ad1c332b73f432c907e21095f48a89e6"
    $a8="ee2d93e39d51298022af4b5d1df8a3be22a455beb4bb3e18c539d0bb"
    $a9="f308d01316af4e6b9b0a766f5b328f00723fdc1b97c2859f07bb1114"
    $a10="da79ee73928d0b41045809fe692e468aea0f869f025365e6438ad159"
    $a11="da79ee73928d0b41045809fe692e468aea0f869f025365e6438ad159"
    $a12="5b55af7c2e964e5db7057da6f10e907aa4befe6d6cf5b19f4b672071"
    $a13="da79ee73928d0b41045809fe692e468aea0f869f025365e6438ad159"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha512_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcf346a597f65e994600a502e782283b7c2e9eb52b8f3fbe8f820d1db2ea75747d7d2ef308385241c6d9baefb61a4d60e596b80927759ebcb33893574969de5f"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="d6be2b194648b678e52086653488cd0278a21625307436e90cc00ec7e682464107b7c5447b1df3b981558c1d8a4dec11797c884d1c45500d25194ef64f45b46a"
    $a3="a3ac8332a9d99477413bfbd339c551305b4a5eb89ba7d3268c6be38ca1c0792e90f73503570149bc2ce5c7e7227bdd0bd599db0caaa623a046d2df671d0df74f"
    $a4="09fea83718f1b4114f27a68c07bd10063a163a124b048ef0cb318bf94a61c42076b8caa8475c045de1c42feacc3352ab824c907491e1ad3dee476fe1406006ac"
    $a5="c7b3b5b9a223a4f06084976070d22bd7d1fe67e524594c5014632c106ffa65e1cc496e2dc89d4fd831e416adbf5e3cfd685ffcb3dc15274523e34a4cbb63d6c0"
    $a6="666739b339fe6627cf41757e1ba7617680836e0de9c5ea8e64ab5ef334efeaf53c65c387a275c8154946efb769617df43eeb7f25472d78172e08bedff6e87272"
    $a7="d181a4fc59dca216a22f993bf18b902aec9beff0d70be72cbaad69a1fcd53d4831433e9d7d52c57d8f61b660122f0603c5e42db5e16b8c7d4ed5428e1b4ab077"
    $a8="e36ac69210f52ff081cf7e811a791f766e6d56a960ef58ad08447ff60fe9c6ee58bccea8dedb04f4bb30c2d4c26dea2a43908970d1d5968aa1555626d0c66c1e"
    $a9="6162eb4b9377a7c411410c77e310652d31da64a51df77d3b5713f4b9291923fac30c67b26e9f544643957c7ebc5424edbf44a9b563e05ef74917d39ce3d4529a"
    $a10="1c50ab60c2cebb875c56a2dab7accd17de4c8940deb0d158d628dc103fca18af78dd0fe95129123fb1408989a282544c6b22843c3dc443d835f6886802a9a9fa"
    $a11="1c50ab60c2cebb875c56a2dab7accd17de4c8940deb0d158d628dc103fca18af78dd0fe95129123fb1408989a282544c6b22843c3dc443d835f6886802a9a9fa"
    $a12="eb4deacd551f08b2efcace8249486b5e33a470825a2dccd91da3659bae6558025169e9f4fa126b5195e6ff0addfb8a72439d5903dbb466a85f290c152d464b78"
    $a13="1c50ab60c2cebb875c56a2dab7accd17de4c8940deb0d158d628dc103fca18af78dd0fe95129123fb1408989a282544c6b22843c3dc443d835f6886802a9a9fa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha256_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f8f7a8c040ef2e8fdd133102b65cc526fca99ca84d4c7b67da5951c99977eba"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="5b5f460bcbcda97b60137d28a0d1d089df2ab48a3ffb08d75adad462ce3c9683"
    $a3="e0717cee504531e21a049f6e1f72775c7273ab987e5d2cd4f2ae9a2d59694721"
    $a4="97e991732e1f2034217a50a30031f86a2b3eebc9b33ccae169ffaa2090458a08"
    $a5="fefa82ceb88363173b2f76d214b5b66848087cee1d0b41716d8a53054e48d884"
    $a6="585d081bd4f54e084722ac6c5cd416b1f431ccf5a5fd5deba5e80555f68d0796"
    $a7="982945308d3682d16636fd628c314e293499e99c00120acd9b693f5ab16e1648"
    $a8="7ab18fd7a14d6d731de6eb91fb5bdb2123e705af7fe2442139198f06b7948feb"
    $a9="23a1d40404715c2a6970c6350b01920ec417bdb3f1f6f399ecb3f073542b58eb"
    $a10="92b7b421992ef490f3b75898ec0e511f1a5c02422819d89719b20362b023ee4f"
    $a11="92b7b421992ef490f3b75898ec0e511f1a5c02422819d89719b20362b023ee4f"
    $a12="16ab94f97bde08b9b51910985f9599a63e9514b4e4d29c652d20621de3b8540d"
    $a13="92b7b421992ef490f3b75898ec0e511f1a5c02422819d89719b20362b023ee4f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2b_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fc453313c9f389f8121626d76498cbe6585bcbd077500c309cee6902ee1bc765c2c8472329ca16cc4c973599677a68de93fabf4f2831dcf245177f0e950c720"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="2ab8959cd324808fe15e7ee1b27a752a10a5ccf33dbabaee4ed1a3789a474d82942b6fc735605eea40a864310629a8997c94d6e71fb2f9351beee8fc4575a813"
    $a3="413df10a2188383f99931bbbe5d37d8211dc0f972bea9347b1ff7d1351cc57a541541317080ba298fc94e0df68588ae789fc45e8277e88f97c49938005e89432"
    $a4="3408a118fbd016d158e863484224429aacbad25adff8f2b88ef321ca78ead49b57809d7740ba4156037315119c559533982b1057ba0c89fc65549087a9bb2b81"
    $a5="037353dc33994142e36d08f363b05279a50faf390f719b54f7ff4d0a42193c257596446f0c826ce3eb54eca9095e864dc93568ac8b388437e66f181b4b3a0a1a"
    $a6="69b451e1e89a11444b8cbdade33cd94c1b519f2a7fdf08e64f062a023878b46b3a306e0c5f4ab91c1167b3a4806f1f83eddf2897879730dd0f6c13db92b4040c"
    $a7="33729a49dc84a798f8afdea91c57c4c886b6e5bff3747bf00a50b15a58748aeb08c8c53613f169546e6e75a4ff7d9954420bf505a71d712241965466815127ac"
    $a8="1eb32b2f1ce876fac529b7928657c1b8f885d75663eb082bd07d212ccfd7ea5dc890beacc5d26f47fe2ade13b45cbbc6be0f3b0614e83dd5ec8daf0b8b6bc29a"
    $a9="4548f269ecb8d41644522baed22de8734e3499897742b59ac51cd442e8fbfbc3d19866cdbd7a917e85fa99440e3c5dae7633a78433ecc39b97510fc21ee1c522"
    $a10="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
    $a11="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
    $a12="00b9b7ad478a8e6e71d31b03d7a1d77c6ff921280456c8cb34695b3bb6e7c4ba139c3a70e9f51ab2f3e95837e5d5dbf06560917e1f83a67d615b94f6f3e6c9c3"
    $a13="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2s_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13e7518f1bd3ca9fe63138b9b8dd5a42d0254f772abc22cd0cebae0670cd7528"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="ab4d1214cf24bfc4a4e4d2dd8b7f73ad8ba236fd3686130ffd23db17020ac7a9"
    $a3="f98599d8d902756dd66aaa949cb254986f7f361a1574e21ad5534fa19b18e455"
    $a4="36a8b72e8bc83524f1be81e514a709566fa2c7c11c86739937a38a977ce6ccf3"
    $a5="cd08df4577ca595cc717711c5ca24b6808ce578f8be67c75f0a13c8fe8523e18"
    $a6="e8af4daaa2fe1a5ddfd91792a2275a4dc692cc0db6244c9db2050ca17d4350b8"
    $a7="8795e415ea47e3387cf49a3a45de28958220085abcd097c980521d1b7599e6ac"
    $a8="4c7d8db1c3f3fcd06f80159186f42455496cfc4a9335429199ff41a0902d5e24"
    $a9="f901bf102a696e8e217c3d7c3ff8943208fa34cedba1edb459d56000bc67083f"
    $a10="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
    $a11="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
    $a12="82df5d0f14d06c6397cfbe0a928db4611f2837ca96ac0d60838d4b16d0d35dc8"
    $a13="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_224_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="83db1a30cd194d12e60aea7fd71db341a095f9d4913c34984e142321"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="beb04b428690c3735bb761ee08024d40cada273b6f4cb64c060e99c3"
    $a3="e2fff94df9706d65ab404f1fbf975ae3c9d64deee05b5afc03304759"
    $a4="f7cf7bae5b773cc93e56511ae9d199268b6f9e1a7731ac94a6d646e3"
    $a5="60c9e61cb8512ff3a1f1dc545c3118708f6dc434f6f8342f40eb9c63"
    $a6="5d3537c42ad566601c47c18b803411d9bd0dcc875a98d2126f62b067"
    $a7="cf07e9c1fa80f75a13fc1f921179556d1a519e844123d5e7c7cc4327"
    $a8="eca1b37497244881579be9058e9b7211159de6f1df36b55d22cef8d3"
    $a9="a4d6b17f5d20ce6223a308d938b07a9f3ec093233757eb9e387c963a"
    $a10="2692bab49e220cb6c4de347c55e2b22779a55080f5dff79c1ccf41b0"
    $a11="2692bab49e220cb6c4de347c55e2b22779a55080f5dff79c1ccf41b0"
    $a12="6eb902718cd28d136036a5b48efc93f098c8ca9db78bdfe5eec117f0"
    $a13="2692bab49e220cb6c4de347c55e2b22779a55080f5dff79c1ccf41b0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_256_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc3e3e7aae8ce30b86a5da56d6460f90d605bef2e2068ee7c50f8000e8b56192"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="f524b7833a9d4b3e4cc158d1be005c1a18cfadc03bae6af38a0bdaeac9c29f31"
    $a3="06ef834cd3b080074a694d172db0bb0ebfd2f3bac5d943a1e8f97ef17b847853"
    $a4="017383d51ba86830b8bc9864b8531bac6449ef36a0dea9b9d8bf471bb4366c8b"
    $a5="ac2247a99c3e17aac292908eb9f36780b469c57c5fbb916c6b91ec0d13888346"
    $a6="e2025ff4d76d05c3f8fbdb1bba8e93ec67e7a726e86fe4783f3dc2eada17d3b7"
    $a7="a91b5c25b6af4afe0d19dde9bb501bc4d099b09f34d035b51fc4c2d7733bfb51"
    $a8="fec3572a226527ba9a636836222a7231362a9f348b1a4caf2cbfef230a703aea"
    $a9="ee372019b48bff763cdab6b666d63d413b6bab26429d03f66406dbef07b978d8"
    $a10="fc7f082eca25ffe62016dba0193786e8134d3a0a428adf3308c8db2a0abbae4d"
    $a11="fc7f082eca25ffe62016dba0193786e8134d3a0a428adf3308c8db2a0abbae4d"
    $a12="79c2d64847da284b332e5fccd1282acac0290528ee4d63f398c15e64d031e478"
    $a13="fc7f082eca25ffe62016dba0193786e8134d3a0a428adf3308c8db2a0abbae4d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_384_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4edb2be26a95dd2a52b2a7445cfbfc952a6b5fda84c264675a762a194af78b28d58fcc87f2edab6732589a8daa22684b"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="0723ac2e44eff4e98485856446f8d3be0c882ae75d96590bd5f0eea00e1c3880ee0886b203466a4d6ca31ef912ca5d10"
    $a3="3ddeb8b95dd2315b7936faac32bc6de74912185774399efaad2664e1c51468feec3fb41f11be45fea2a3d3f936d24590"
    $a4="150706009491b4d06ae288d433d9c44447986c822b13953dad1ac43a8c5bba91d0d676b9049bb1c2f118a910def71113"
    $a5="5431a842fbe7eb8e68f25ee6193aedc5a7ed098cc5087a760f578bffa4e9130c5d58a71cb47c526062eb1e73f5563c11"
    $a6="709e2079fbc4c09162c2751ed9c769319893ea72a7a57a28ea69b061df3729172c2f5cace165043002db069f7a87d552"
    $a7="0cb2b82d10f9706e6bf686dd25610eb3c35c3f8a02fc6908be29483d0204f19fc8d802cc4b296f86f3e5a8c3fe5627ed"
    $a8="1982f42589842b2044a81748873969acbc6ab0b28305259651b29c6a3dbe9e17515dd60ea81dd506ad0a6df96e048726"
    $a9="46d4665406a2b67de50adfa819779a33d776eb80884c016b31f2d9d12bc3f584f8d1ad18f9da4efd4618b6f18dd6ebdd"
    $a10="87a06473be4a29ab2c863ea66d53a06fa9d6883ee4fe301567bef102479fa7749cdcee7933ac0f8e61f3d1326a68e07c"
    $a11="87a06473be4a29ab2c863ea66d53a06fa9d6883ee4fe301567bef102479fa7749cdcee7933ac0f8e61f3d1326a68e07c"
    $a12="b45644a05028971ab803d1c69a1d8b6f567c63312ec45d172d35ea5e0ae530f800d17a7e84dd737add8ef93e794fff9f"
    $a13="87a06473be4a29ab2c863ea66d53a06fa9d6883ee4fe301567bef102479fa7749cdcee7933ac0f8e61f3d1326a68e07c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_512_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f20eff79db19db192a4f49b8e6a4105903cf28a204a4195625a1875eefff4163b3902dd35ececf2ba52f9a9a2e43f8dd575b393fae0792499744172ef450d28"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="62208c35c26c71b4729b39815db5e63e23afadab876bd011cba8c2cb5de61bda14d2460dffc70a9f57248ac1a5630f1039ff3d0e28b1164423eac09186104783"
    $a3="8341d8275dc4d8280ada002618edfce79b33ac25b74394c918168ede320423cfbc8f42f581aedcde002cea5d4f14dce3d19d593edf2c9811c905d5647ab6a230"
    $a4="591cfba5427daacd099b5c300497333c7e518b603d78e27dded50c9077eb1e500dfd62735b57cb580b46c3bbdc9b5c62f2f7378b0322faa43a89dcd2748ddde3"
    $a5="eae47ae73e3ef92a86147c5a643381f9143d360d22d83b6f8983e86a1adf7ea3ef4c0cd5136627e10593b590e5068ada1e6d11d43097182310611a001c842aa5"
    $a6="d1edd3baf4879cd6da2ec415064a357aaa93eb6e5272cac36d4e3686a2e4e7809640b9fc57c17dcc10cf645b5c05d6d1be0fac4c13c443608e1b68d2f5ca2310"
    $a7="a46eed8f55b756dcfa477cb621209ecc170bfa1c4fa1b3cbe4437003ab0b883cc93f2265ef79b952e30058671477a862a37228759e3259de1119bcc44a19b74c"
    $a8="6fc99f5ae5ba7605fd6ae2d3d2b5c56821ffb0a9e1f257ed31eaee5bc374919bd8aa81fdb7ab9cfae9d0a7de7cd98f2ec45c5fa9998eb04ddfdc01e754f6411a"
    $a9="cb3b953d592297d5ca7659f59e3c0dc1c7a273b851446855dd90854e14606e96b355d9b419766493a56cd06e28d6bf49849bf33951787d00af188f2663e18df8"
    $a10="f8059e95f875706acbbbd37924172b947f399d5ff4adae42babb986e4589b456b3f1e69517496db9276a559b7ee106ee54a367a28518e6bafa696736927b0c92"
    $a11="f8059e95f875706acbbbd37924172b947f399d5ff4adae42babb986e4589b456b3f1e69517496db9276a559b7ee106ee54a367a28518e6bafa696736927b0c92"
    $a12="973a19d88dc29aecbaec2f40535e3b6ab3d22354453a554cb3c58089830e23cdd803497c8c21519e4f53a35a3f3bd7fd162983586e9f5fcc55124ef31aa437dc"
    $a13="f8059e95f875706acbbbd37924172b947f399d5ff4adae42babb986e4589b456b3f1e69517496db9276a559b7ee106ee54a367a28518e6bafa696736927b0c92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule base64_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="ZmFjdG9yeWNhc3Q="
    $a2="ZmRydXNlcnM="
    $a3="c3Jlc3VyZGY="
    $a4="Znd1cGdyYWRl"
    $a5="RmFBbVU1cDJGfg=="
    $a6="bG9raQ=="
    $a7="WmZUbGp1YmxzeA=="
    $a8="c3lzZGlhZw=="
    $a9="ZmFjdG9yeWNhc3RAc2NobmVpZGVy"
    $a10="VVNFUg=="
    $a11="VVNFUg=="
    $a12="VVNFUg=="
    $a13="VVNFUlVTRVI="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

