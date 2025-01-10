/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_syabas_technology
{
    meta:
        id = "1iIIwjL5QxO1KPYdSS6aPF"
        fingerprint = "eb4178374ca339b867d8888e623f3debd6a11125383ff773f9957f3269a8193f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="9e427414009e765b30af480fcbb532fa"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="4a6e758d82a49ae433f2317927ae7bb6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="446a12100c856ce9"
    $a1="40ca4f0b09893903"
    $a2="446a12100c856ce9"
    $a3="7a2ce76326fa4108"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a1="*8272D64B4DB9D7DF622DF834A91F9BEA74C6CE6C"
    $a2="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a3="*3D6EC56BEEA1447C617285798BE126D9F52D1032"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a1="{MD5}25oQC9nk+q2KBVipQyXT3g=="
    $a2="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a3="{MD5}8CtyyrSCVVfX0pfu1GxylA=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a1="{SHA}xvHhvhInaSCSJkhOx4CsQVkiVWI="
    $a2="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a3="{SHA}JQu30mhj9ED6bNzOk6XNoUzHGf0="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81dc9bdb52d04dc20036dbd8313ed055"
    $a1="db9a100bd9e4faad8a0558a94325d3de"
    $a2="81dc9bdb52d04dc20036dbd8313ed055"
    $a3="f02b72cab4825557d7d297eed46c7294"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a1="c6f1e1be122769209226484ec780ac4159225562"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="250bb7d26863f440fa6cdcce93a5cda14cc719fd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a1="bebeb64d3ec88f578e17860f4272976d8114f1842fae54b0a9709935abdc5f0ee396b45dbdce97fd2908f051f6992feb"
    $a2="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a3="6b3db39955fc90188a615a818e182c6933899d869689479099ee6311636261cc7ae953a4d88484d3b98ce77776343541"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a1="147ba488d7a0b535742c3a505da5b40d1345eca29ac96049b98265cb"
    $a2="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a3="bdbb98cc5007a1855b7af9e1b52b6572c1730a680501afbac120504e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a1="10f296fd46a886571820201a5ec6790b7ea0eb72d518ee4a3bea0256be1ac5023a5baf2ae990dc948b8de2dab1fe92f1b63cd4d2256e4fcdfc85c01c68ade427"
    $a2="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a3="99d45477c102b8c50db133f2bc2397e01e3e769eb58bacb3fe219c4b73390bde6843807217124f5a2bee6e05504daf859f5bc060bf71576506f23392aab44b6e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a1="dfd15faadb7acd0ab6329aa9941c33e977d82028fa0b3193857eef8c2fc077c0"
    $a2="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a3="fc74de5b79d22c90b0741fe91f7859e72884a70bc920c7ca2687f030a221f0a5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a1="ff1d879655fdb53a4290b756b5c3c12cffc056992be06705fc6983782102a88c3bb1f1ac797792a7133ccb03610816d350a15a2c1cccc7d4d477560c2226e3f0"
    $a2="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a3="9dafd721a28b9b2bcc2fcd3a9218a9522e69260dc216e4f036cebd2513e2e08309b5560cbd01c33792de736ec97d777bfec9479a625f0e59256c7e9e92b49950"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
    $a1="01a2378e6ec2862772c75c5f8ca91c7b896f630bf8010b2ec24345034bf26545"
    $a2="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
    $a3="6e9c5dac19e04819091446377074b2059377998e8e8770d46089a613f67ecc3f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a1="3a58f48df3e341e6c1507a8b6b2e927948add4da2bf7c875456fb444"
    $a2="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a3="d3724ff5cd56ea39b965633a1faf8ceb7a4189c4a9b87e7c04e409c2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a1="94ab5cc5a0390b03245941af98a984deb74be0197ac2e2b2632cb36b0d00501c"
    $a2="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a3="dba9712eb44793c81f3ff87f62019858f0a475666cbb8c6058b59dfce2cc7665"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a1="2b5a8cdde0892d613f1998fcaaec083a66cb1575225b552332002d8d63d27cf85ef3f66b607e2c032274138cf5857530"
    $a2="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a3="4b2967bb6a74d0b77df623a1bf01390706479ba123b5c8eccfd843487c28c1916576416e2a41290d3f40983b91c39b87"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a1="0efdfc2bf8076425b343850f2d27409d73e75a87a043fb5753bf5b776552d3a9b215ef69a1bc687fa994cf6e0fbd4430b4eede565ec85ade35536a070423a5ec"
    $a2="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a3="06a28f02fe8424affd9ee20612a1e59eabdb853908d6ee67f6bc41ffdf696946f675ea1f40a4ee904fc92a6124b0faad30a83295c726008e8858970309cb4501"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZnRwdXNlcg=="
    $a1="MTIzNA=="
    $a2="bm10"
    $a3="MTIzNA=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

