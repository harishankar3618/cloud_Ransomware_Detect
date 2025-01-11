/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_osicom
{
    meta:
        id = "3WAjyaYh3hhSuwJBfCijYA"
        fingerprint = "459e807489737b589a822ed934162bff46a4b36c4ebe59f5c46ba5811481624d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94aa68f72ab39cfec7ffcb58dca3358c"
    $a1="94aa68f72ab39cfec7ffcb58dca3358c"
    $a2="ec16b699514c70c7f3e12ece7c30232c"
    $a3="d47ce0c3e3f78529db2f266d5e7afe8d"
    $a4="823893adfad2cda6e1a414f3ebdf58f7"
    $a5="823893adfad2cda6e1a414f3ebdf58f7"
    $a6="a25b2710ba9de114396adc7dfb0a7235"
    $a7="2e810dd7bf85d71280f588266c1e2ee7"
    $a8="0280777f37d4f4e7c478d21cec701463"
    $a9="ec16b699514c70c7f3e12ece7c30232c"
    $a10="0280777f37d4f4e7c478d21cec701463"
    $a11="0f646870e4bfaadbf772e378b0e69777"
    $a12="0280777f37d4f4e7c478d21cec701463"
    $a13="823893adfad2cda6e1a414f3ebdf58f7"
    $a14="a25b2710ba9de114396adc7dfb0a7235"
    $a15="94aa68f72ab39cfec7ffcb58dca3358c"
    $a16="2e810dd7bf85d71280f588266c1e2ee7"
    $a17="2e810dd7bf85d71280f588266c1e2ee7"
    $a18="0f646870e4bfaadbf772e378b0e69777"
    $a19="0f646870e4bfaadbf772e378b0e69777"
    $a20="6c692ee01b2fc655b6cd60195a4a3be9"
    $a21="43b4c4b0d87e82b0bdc9c8f6a110fe1c"
    $a22="532a71d1afa4930012f3048d25f98148"
    $a23="a444a17d659890b5a712d16b50fb9a08"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule mysql323_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4701175b460f3f84"
    $a1="4701175b460f3f84"
    $a2="4660c1d55c384af6"
    $a3="4829c53d6f9319a1"
    $a4="57510426775c5b0f"
    $a5="57510426775c5b0f"
    $a6="4077eb0b03ddce3b"
    $a7="2ac90b9577c33931"
    $a8="15f73cd91718b388"
    $a9="4660c1d55c384af6"
    $a10="15f73cd91718b388"
    $a11="5f1c284521aa2d43"
    $a12="15f73cd91718b388"
    $a13="57510426775c5b0f"
    $a14="4077eb0b03ddce3b"
    $a15="4701175b460f3f84"
    $a16="2ac90b9577c33931"
    $a17="2ac90b9577c33931"
    $a18="5f1c284521aa2d43"
    $a19="5f1c284521aa2d43"
    $a20="29d7619622ecb839"
    $a21="462bb13c0e48d7be"
    $a22="558bb3e11f999dd8"
    $a23="04964711571d0a96"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule mysql41_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*887D4ADD2175BF34AFC0BABD2A4AF6FD2BA29A0A"
    $a1="*887D4ADD2175BF34AFC0BABD2A4AF6FD2BA29A0A"
    $a2="*532E60766AEB459BBB251F646FD39747B0A2D232"
    $a3="*34E8D02C361F409EFA12A0DC2D59029648DCF5D5"
    $a4="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a5="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a6="*D89A99106002D77C1D327FC41E005919505638B0"
    $a7="*6695524259F1EEA28BDD985FC5235873DBF015E4"
    $a8="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
    $a9="*532E60766AEB459BBB251F646FD39747B0A2D232"
    $a10="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
    $a11="*EC6751A1D1C261C57C81741CFBC5EBDD6FDFEF27"
    $a12="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
    $a13="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a14="*D89A99106002D77C1D327FC41E005919505638B0"
    $a15="*887D4ADD2175BF34AFC0BABD2A4AF6FD2BA29A0A"
    $a16="*6695524259F1EEA28BDD985FC5235873DBF015E4"
    $a17="*6695524259F1EEA28BDD985FC5235873DBF015E4"
    $a18="*EC6751A1D1C261C57C81741CFBC5EBDD6FDFEF27"
    $a19="*EC6751A1D1C261C57C81741CFBC5EBDD6FDFEF27"
    $a20="*9FF9235F528F8067F595829E2E9DB276FF0D1E57"
    $a21="*115DCB04CFDE0DE73C4C21430E287FC7660F0B26"
    $a22="*85BB02300F877EB061967510E83F68B1A7325252"
    $a23="*FB8DB8211973E65BD674FFF4EC590B46901EF64C"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule ldap_md5_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}4Mvw5i0DeW8x2kcJloK3Kw=="
    $a1="{MD5}4Mvw5i0DeW8x2kcJloK3Kw=="
    $a2="{MD5}KSl/eG9K0VOEx0gMhKnSUw=="
    $a3="{MD5}rUL2aXsDW3WA5P75O+ILTQ=="
    $a4="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a5="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a6="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a7="{MD5}rpS+PNUyzkoCWISBnrCMmA=="
    $a8="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a9="{MD5}KSl/eG9K0VOEx0gMhKnSUw=="
    $a10="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a11="{MD5}y7Ee2H3IqV2BQAx/M8fBcQ=="
    $a12="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a13="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a14="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a15="{MD5}4Mvw5i0DeW8x2kcJloK3Kw=="
    $a16="{MD5}rpS+PNUyzkoCWISBnrCMmA=="
    $a17="{MD5}rpS+PNUyzkoCWISBnrCMmA=="
    $a18="{MD5}y7Ee2H3IqV2BQAx/M8fBcQ=="
    $a19="{MD5}y7Ee2H3IqV2BQAx/M8fBcQ=="
    $a20="{MD5}9gqTJj+6PuI7USYPbDnD4Q=="
    $a21="{MD5}z6UwE1i5/L56pFsc7qCIxg=="
    $a22="{MD5}LBfGOTdx7jBIrjTWs4DF7A=="
    $a23="{MD5}77KmhOSvt9VeYUf75aMy7g=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule ldap_sha1_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}/GeDs8q9TAmsen2oRSn3g8DhHrI="
    $a1="{SHA}/GeDs8q9TAmsen2oRSn3g8DhHrI="
    $a2="{SHA}VQiTNN2ceANTf3NR6muaEad0Mvk="
    $a3="{SHA}MvquysdCEA93U/DB0KoK3QG0BGs="
    $a4="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a5="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a6="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a7="{SHA}ur4wUOLoHf2HqM5nJk1RjLNK73I="
    $a8="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a9="{SHA}VQiTNN2ceANTf3NR6muaEad0Mvk="
    $a10="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a11="{SHA}stIedx2fhoZcXv8ZNmNXTdF5bI8="
    $a12="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a13="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a14="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a15="{SHA}/GeDs8q9TAmsen2oRSn3g8DhHrI="
    $a16="{SHA}ur4wUOLoHf2HqM5nJk1RjLNK73I="
    $a17="{SHA}ur4wUOLoHf2HqM5nJk1RjLNK73I="
    $a18="{SHA}stIedx2fhoZcXv8ZNmNXTdF5bI8="
    $a19="{SHA}stIedx2fhoZcXv8ZNmNXTdF5bI8="
    $a20="{SHA}w5nmWwCqiwr946izWsyUfYKEYFc="
    $a21="{SHA}eEH7H5K5kZTKgY1BDLCUMHMbYoU="
    $a22="{SHA}6AcheTwkrhTt/KmyatQGqYFc0/8="
    $a23="{SHA}4dDGwcKeatUWQHKlshNA3Kf8sFI="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule md5_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e0cbf0e62d03796f31da47099682b72b"
    $a1="e0cbf0e62d03796f31da47099682b72b"
    $a2="29297f786f4ad15384c7480c84a9d253"
    $a3="ad42f6697b035b7580e4fef93be20b4d"
    $a4="084e0343a0486ff05530df6c705c8bb4"
    $a5="084e0343a0486ff05530df6c705c8bb4"
    $a6="e3afed0047b08059d0fada10f400c1e5"
    $a7="ae94be3cd532ce4a025884819eb08c98"
    $a8="8f9bfe9d1345237cb3b2b205864da075"
    $a9="29297f786f4ad15384c7480c84a9d253"
    $a10="8f9bfe9d1345237cb3b2b205864da075"
    $a11="cbb11ed87dc8a95d81400c7f33c7c171"
    $a12="8f9bfe9d1345237cb3b2b205864da075"
    $a13="084e0343a0486ff05530df6c705c8bb4"
    $a14="e3afed0047b08059d0fada10f400c1e5"
    $a15="e0cbf0e62d03796f31da47099682b72b"
    $a16="ae94be3cd532ce4a025884819eb08c98"
    $a17="ae94be3cd532ce4a025884819eb08c98"
    $a18="cbb11ed87dc8a95d81400c7f33c7c171"
    $a19="cbb11ed87dc8a95d81400c7f33c7c171"
    $a20="f60a93263fba3ee23b51260f6c39c3e1"
    $a21="cfa5301358b9fcbe7aa45b1ceea088c6"
    $a22="2c17c6393771ee3048ae34d6b380c5ec"
    $a23="efb2a684e4afb7d55e6147fbe5a332ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha1_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a1="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a2="55089334dd9c7803537f7351ea6b9a11a77432f9"
    $a3="32faaecac742100f7753f0c1d0aa0add01b4046b"
    $a4="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a5="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a6="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a7="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a8="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a9="55089334dd9c7803537f7351ea6b9a11a77432f9"
    $a10="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a11="b2d21e771d9f86865c5eff193663574dd1796c8f"
    $a12="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a13="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a14="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a15="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a16="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a17="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a18="b2d21e771d9f86865c5eff193663574dd1796c8f"
    $a19="b2d21e771d9f86865c5eff193663574dd1796c8f"
    $a20="c399e65b00aa8b0afde3a8b35acc947d82846057"
    $a21="7841fb1f92b99194ca818d410cb09430731b6285"
    $a22="e80721793c24ae14edfca9b26ad406a9815cd3ff"
    $a23="e1d0c6c1c29e6ad5164072a5b21340dca7fcb052"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha384_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6697f95267a06541d307b844b985b47804c52ddf4fcf66b0009168cecd6448d5540e23c1c5bc3e16f86f58f96122d08e"
    $a1="6697f95267a06541d307b844b985b47804c52ddf4fcf66b0009168cecd6448d5540e23c1c5bc3e16f86f58f96122d08e"
    $a2="bc660922e6db670bc9a6d33208b387da80fc60ef4f56d65754579ae8a787635178da7fe849ae3c55cdb730855ff366d5"
    $a3="b345909bba936cdc8ea81ae3ffe6c668481d351df7c46efd502f7f7f94dff566d40a9ecaa6621609419ad1903f74a799"
    $a4="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a5="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a6="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a7="9f926adb99d65307adc43260aaab27c71af4f8b1c112b8f3b45139eab7ccb9a4afc0569c47fef0c4ba69af737533271b"
    $a8="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a9="bc660922e6db670bc9a6d33208b387da80fc60ef4f56d65754579ae8a787635178da7fe849ae3c55cdb730855ff366d5"
    $a10="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a11="87859ccf51716260936c266b4a3ac697a0695ed043abac013cc69eb04f5829fb4eea5b15b51adb334f150161d3fe1dbd"
    $a12="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a13="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a14="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a15="6697f95267a06541d307b844b985b47804c52ddf4fcf66b0009168cecd6448d5540e23c1c5bc3e16f86f58f96122d08e"
    $a16="9f926adb99d65307adc43260aaab27c71af4f8b1c112b8f3b45139eab7ccb9a4afc0569c47fef0c4ba69af737533271b"
    $a17="9f926adb99d65307adc43260aaab27c71af4f8b1c112b8f3b45139eab7ccb9a4afc0569c47fef0c4ba69af737533271b"
    $a18="87859ccf51716260936c266b4a3ac697a0695ed043abac013cc69eb04f5829fb4eea5b15b51adb334f150161d3fe1dbd"
    $a19="87859ccf51716260936c266b4a3ac697a0695ed043abac013cc69eb04f5829fb4eea5b15b51adb334f150161d3fe1dbd"
    $a20="72f4604cd40be9d2f56ae188e94752c128496ddc1a6afb9ce1641cd460251f5f7950625e2ae895b34dfde04ff9ab704d"
    $a21="a265795b837d1aee9a8ec087c2417af2883da54031b3b5160cc63f4a41b897b92ed51e489bed7522ef5354f2de1c9b73"
    $a22="40fe2d4072282a91177bd8d13977c0ed68c7dfccf6e7eca10d481238487e4e318ca87263da20ded9138ca7725aa10263"
    $a23="49f042f1390c116a42a26a42bf1ce4f3904d9004cced0b9ef09824a7b2d494d82dcf892f48ae9136501d2ba326832e16"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha224_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a1="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a2="88796e3e59767d3ff43367b26f6bf9ebc13168d3ef032b7a674de5f6"
    $a3="5cd7fd4c793de52376f74a016cf373db2426deac143682521f0d7779"
    $a4="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a5="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a6="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a7="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a8="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a9="88796e3e59767d3ff43367b26f6bf9ebc13168d3ef032b7a674de5f6"
    $a10="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a11="7c3c192db3e2318612c10cc63392760a6ad4b0e7ddf757858e96790f"
    $a12="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a13="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a14="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a15="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a16="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a17="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a18="7c3c192db3e2318612c10cc63392760a6ad4b0e7ddf757858e96790f"
    $a19="7c3c192db3e2318612c10cc63392760a6ad4b0e7ddf757858e96790f"
    $a20="b08b1001678f48f23d2cd765b8e5b804033053f5468b85558317d49b"
    $a21="06b6ac2318e181873e4283a77412e1592da0db2c108eab9c3baf670b"
    $a22="2a12e8d906468d24de4552c04fac544c36a2775d6a4d206bbf20bb43"
    $a23="d951a81aca79223a7f557f032ea0d8f773f9867b74004a4f3125c23b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha512_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="349a41e67bd69bcb66aba203c61d4c58e9912b1e46aff23bcb6ea6fab11cc9cb8bf25c5187a1b73f53d31be856fdf58b0ffe662e6df96ababaf2ae6a9c838cd5"
    $a1="349a41e67bd69bcb66aba203c61d4c58e9912b1e46aff23bcb6ea6fab11cc9cb8bf25c5187a1b73f53d31be856fdf58b0ffe662e6df96ababaf2ae6a9c838cd5"
    $a2="2ff7c8b30e2d8a2e5775b1055e91e94a81e6bf6570adf528547e13fabc4942a5935edc73a059ae882b837bbc1cd58e0f4331c82523023dbe918279995f4f3a3a"
    $a3="225d05b918519458a8fcc1e6493a4e854c004da76f6250b8f52197f47094f71ee984725c31446a1967f0d55f4dc74793dd44d932f2bdf50d77d4288d663bf1ab"
    $a4="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a5="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a6="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a7="290cdcaab07595d41dda81be97b19b9dd2f0ccd7594268d075a9eac22121c2fb033469f384c988ed20749aa4ce0f46f5c592a9468c8609c8de1b6a5bad56b596"
    $a8="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
    $a9="2ff7c8b30e2d8a2e5775b1055e91e94a81e6bf6570adf528547e13fabc4942a5935edc73a059ae882b837bbc1cd58e0f4331c82523023dbe918279995f4f3a3a"
    $a10="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
    $a11="1e1e70b7fcb2621d95b9ce261cd5d03b30dfaf01f1bbc68af639e44f50fa5c31a4adee8ffc9517ae62db3b1ba7f06a8d9bb427106ef77c5a4cccdd7490f87721"
    $a12="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
    $a13="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a14="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a15="349a41e67bd69bcb66aba203c61d4c58e9912b1e46aff23bcb6ea6fab11cc9cb8bf25c5187a1b73f53d31be856fdf58b0ffe662e6df96ababaf2ae6a9c838cd5"
    $a16="290cdcaab07595d41dda81be97b19b9dd2f0ccd7594268d075a9eac22121c2fb033469f384c988ed20749aa4ce0f46f5c592a9468c8609c8de1b6a5bad56b596"
    $a17="290cdcaab07595d41dda81be97b19b9dd2f0ccd7594268d075a9eac22121c2fb033469f384c988ed20749aa4ce0f46f5c592a9468c8609c8de1b6a5bad56b596"
    $a18="1e1e70b7fcb2621d95b9ce261cd5d03b30dfaf01f1bbc68af639e44f50fa5c31a4adee8ffc9517ae62db3b1ba7f06a8d9bb427106ef77c5a4cccdd7490f87721"
    $a19="1e1e70b7fcb2621d95b9ce261cd5d03b30dfaf01f1bbc68af639e44f50fa5c31a4adee8ffc9517ae62db3b1ba7f06a8d9bb427106ef77c5a4cccdd7490f87721"
    $a20="c9c90184e3e38a836cba2b371205acaac0ac640f523289222494d052a0bc807563fcefbc28a0671faf83510e192729c9cb3140ee00d880b30d20b44ac9df76ca"
    $a21="9408218f3f1ff887751d736008a5ae64bf36558a70bd7f8011b57ddc5efe28b24bcbeea306c09dea24bcf6bca185c5ea37422d90e9393b27228e8888a019130d"
    $a22="9d9f1d99d6a2e8488d0c330269f0a15d1f56bd4b309c840ff678fc6a32f15e2cf6efaf76e4d5471e7af9f88a12014a7ae6f91fa2e08fc622493920a555290c93"
    $a23="8039e274249e5df52a780f1c3d913cb1769d8edb30707ed14fa453f701c8177fbc4e72c423fda59dbd95b5ccd951b2a73c73307ea4eea72fd0383cb49d1274a6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha256_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a1="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a2="2aa10c7e1ba8d76746634bdb832005103645e62913f9f5cfe621e8f088915abf"
    $a3="0b8e9e995d8d77f1e4770f0f79665aee6f3f70247b3735422daba73df4c3096f"
    $a4="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a5="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a6="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a7="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a8="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a9="2aa10c7e1ba8d76746634bdb832005103645e62913f9f5cfe621e8f088915abf"
    $a10="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a11="092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d"
    $a12="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a13="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a14="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a15="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a16="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a17="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a18="092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d"
    $a19="092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d"
    $a20="2d084342694e7d6b7ad38afc89264915449338d3092356ebf9e5482c4a52213d"
    $a21="9f69998560dcfd8016442e0a32e959191df095817a164ce844c64ec5a8b0cc1b"
    $a22="715dc8493c36579a5b116995100f635e3572fdf8703e708ef1a08d943b36774e"
    $a23="10fd874b68dad080ed706762c8e163dabb20514bddae38fb159c56f714a3b143"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2b_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99ebd811fbcd8b1bb1625fa439438c96e9649f68fdb04954348d4d4bee19d1682f1d1853077f903c0a82928f0f1a8d905fbc764f26b0dcb178fddd09ce123922"
    $a1="99ebd811fbcd8b1bb1625fa439438c96e9649f68fdb04954348d4d4bee19d1682f1d1853077f903c0a82928f0f1a8d905fbc764f26b0dcb178fddd09ce123922"
    $a2="1bcfffa65462818f01cc1026e1fe370c4dded6aaf1c5a43dfee71005c90d942f95f9a8172d72fc7833fd6e5971325518f0904ffeb334f5219e9ea1b262d124d0"
    $a3="1261c79e61aae75b7c20e76f0e04c29647a6effdc2d41a7a17582402fd6858060bf834cfa56771a1afa7b5da1ac3bf9eaae3d96fea8873b3eb17b48e9b733081"
    $a4="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a5="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a6="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a7="d4ee695d84d47ff4cbb16c47fa7364edd5b8c0acaf21ba78a32cfa403dbb6dfe597547cefc004638dd1f8a8e6cbfbe90f7f10afd6412e912077d370bb4a4c39d"
    $a8="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
    $a9="1bcfffa65462818f01cc1026e1fe370c4dded6aaf1c5a43dfee71005c90d942f95f9a8172d72fc7833fd6e5971325518f0904ffeb334f5219e9ea1b262d124d0"
    $a10="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
    $a11="425c9b0a3c4272f4d9df0d0abbab3e1a178f3d21045c34053910511af2d0a42bf1cf4c8a628e8f5e95fdd4cfff75ecf2e72cd87904650952be87cd7094519d6b"
    $a12="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
    $a13="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a14="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a15="99ebd811fbcd8b1bb1625fa439438c96e9649f68fdb04954348d4d4bee19d1682f1d1853077f903c0a82928f0f1a8d905fbc764f26b0dcb178fddd09ce123922"
    $a16="d4ee695d84d47ff4cbb16c47fa7364edd5b8c0acaf21ba78a32cfa403dbb6dfe597547cefc004638dd1f8a8e6cbfbe90f7f10afd6412e912077d370bb4a4c39d"
    $a17="d4ee695d84d47ff4cbb16c47fa7364edd5b8c0acaf21ba78a32cfa403dbb6dfe597547cefc004638dd1f8a8e6cbfbe90f7f10afd6412e912077d370bb4a4c39d"
    $a18="425c9b0a3c4272f4d9df0d0abbab3e1a178f3d21045c34053910511af2d0a42bf1cf4c8a628e8f5e95fdd4cfff75ecf2e72cd87904650952be87cd7094519d6b"
    $a19="425c9b0a3c4272f4d9df0d0abbab3e1a178f3d21045c34053910511af2d0a42bf1cf4c8a628e8f5e95fdd4cfff75ecf2e72cd87904650952be87cd7094519d6b"
    $a20="e2040482bc5838ab0605e0b626b378bcbd6c00fca59d3a5129986a20ca8dc0b6b604b87d6f40f1ebd00b7798693a39d92dc666eac455dcbb17de721cb5773f82"
    $a21="a659a77f71dda72729dfe062f8d11a65dd361409a7eb28080da10ba65ce2b2b66eb50101a4ebad62775b333b6de5f1517101e0bd1b130227077f221911f386d7"
    $a22="dfa0fc6b62c5255b0612dcabb84e7ba987f7ed7d704ad64bd63cd955614a648bebe267e528e1523d9d860a5eb4e7cabe04b16fd7c1023960586211d3bdfcb228"
    $a23="214c0939a3c1d53d80461c608520dac05495180d6da60bbcbc27809b6ba9874271ac318934b8cd4650f9e0d9f9c47c018f12c081050334595e5f4870e1543176"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2s_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a1="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a2="95c4b7287769151aa0fab9550000b24a35c29a962b1b83796f6436320331552e"
    $a3="61b83c12ccabd0333a492ba2d826cbeae8d9b2febdc369da09614c29342a2bd1"
    $a4="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a5="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a6="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a7="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a8="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a9="95c4b7287769151aa0fab9550000b24a35c29a962b1b83796f6436320331552e"
    $a10="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a11="21853332c749d7bce769b738faab633854cd5f380edbbed56a7baa958e637125"
    $a12="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a13="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a14="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a15="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a16="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a17="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a18="21853332c749d7bce769b738faab633854cd5f380edbbed56a7baa958e637125"
    $a19="21853332c749d7bce769b738faab633854cd5f380edbbed56a7baa958e637125"
    $a20="fe705ddd07bd5b4759ed9582a793e69b923f0cebd6653d4bb639fd9bcb400783"
    $a21="070a3aacfe77889883b651df90e9ed8e88a8d93d9cf91391ab321f60a8706862"
    $a22="934804255c453972da99bcdec2e4d99aad2c277bc7469bb335d4a835cd32e529"
    $a23="fac3810507075ee8b15f29b738065feb912e349f9826411cb5507e00073c6cd6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_224_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a1="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a2="0ead148441198813f78304269fe89dd5dbca5d603121029b54b118c0"
    $a3="5122338bd461aecad5e9cd8266c965d6068c3a17e6283d041e4d4627"
    $a4="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a5="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a6="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a7="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a8="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a9="0ead148441198813f78304269fe89dd5dbca5d603121029b54b118c0"
    $a10="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a11="806a92f9d22571e07f91514b82e6cdd119bcbb2ec4b8def3c5717044"
    $a12="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a13="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a14="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a15="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a16="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a17="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a18="806a92f9d22571e07f91514b82e6cdd119bcbb2ec4b8def3c5717044"
    $a19="806a92f9d22571e07f91514b82e6cdd119bcbb2ec4b8def3c5717044"
    $a20="c4ac0665fbc37a1b5e7028ce9352ac05e972e1e115d5bced500f0de2"
    $a21="96eefd676a924762c32e5a05ce00ac80105c9c362c9dc0af613573d5"
    $a22="5f5c82ceba48805254828ca4c8e61e236fd9d04d948e5f05169d35a4"
    $a23="061f8e291064d95e8c1dbd1a6f90bfd2ebf5a90150f9e36cd8529eb9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_256_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a1="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a2="9691993c31365ae98b83d8273129aebd97d23140f0a028b24b057ee402596b8a"
    $a3="789cf532419e99b67093f10b9059465900d073c466c25efd00771189d38f7e66"
    $a4="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a5="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a6="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a7="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a8="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a9="9691993c31365ae98b83d8273129aebd97d23140f0a028b24b057ee402596b8a"
    $a10="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a11="2c99ba746fe048c72ac15b2875c70554fc8373980f3ed859bdda41ea8daebeba"
    $a12="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a13="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a14="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a15="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a16="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a17="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a18="2c99ba746fe048c72ac15b2875c70554fc8373980f3ed859bdda41ea8daebeba"
    $a19="2c99ba746fe048c72ac15b2875c70554fc8373980f3ed859bdda41ea8daebeba"
    $a20="512c0356914d6110d78285c82734e26b6831e37f5ad61db272affe01d4d954ae"
    $a21="f85ff244f49dfb741e6b8837298a000a30bda080f52bb86bad7d27a029dbe8a6"
    $a22="2032a7663effc6b47d3d2476625c0f085d89cdb9d1df44904fe558b65a703cb8"
    $a23="91aa470491a98aca115499d2d65096e90c14e286414587df08ff7304851afb95"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_384_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
    $a1="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
    $a2="cb34fadf4c364254dfac2e0a24a93cd814c2032942ee4b75d7aa85cc4cee782ce7dea4f0732bcafe88f96588e174d6be"
    $a3="4e5a6f0fba604547745375eb56ccc6f7cecb54dfcbb0b3b65813667ed0ad417ab61e9be79f05ad44e85b29dde2b3fbe1"
    $a4="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a5="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a6="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a7="9fde29cb657614f4dd02c1329dea73d4e409ce50a8275fd34c9fa00ab6a590211814bf8b5254581e99383bad238d4174"
    $a8="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a9="cb34fadf4c364254dfac2e0a24a93cd814c2032942ee4b75d7aa85cc4cee782ce7dea4f0732bcafe88f96588e174d6be"
    $a10="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a11="8cadab5ae059ddb24a20fbb97b212cbd04f553ce8a121b424ad443f965877c53847dbca33629fcb6b079b2fe8a02876a"
    $a12="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a13="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a14="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a15="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
    $a16="9fde29cb657614f4dd02c1329dea73d4e409ce50a8275fd34c9fa00ab6a590211814bf8b5254581e99383bad238d4174"
    $a17="9fde29cb657614f4dd02c1329dea73d4e409ce50a8275fd34c9fa00ab6a590211814bf8b5254581e99383bad238d4174"
    $a18="8cadab5ae059ddb24a20fbb97b212cbd04f553ce8a121b424ad443f965877c53847dbca33629fcb6b079b2fe8a02876a"
    $a19="8cadab5ae059ddb24a20fbb97b212cbd04f553ce8a121b424ad443f965877c53847dbca33629fcb6b079b2fe8a02876a"
    $a20="f19a41936463108d294cb1019b1f071e71f593a06648ecd908c40204459c895a44a661bdb8c4df40c89d7b1505ed5af3"
    $a21="e9613ff2a157609ec6d58bb2cb758af7129b30a78ebab385b4e3f605aada9c341d6334157741c49d83f354ca7e9c3ce7"
    $a22="92f70453f8557e5a5b78148358f4f313a8ca005c910c5d47966413a6d7b9424fcd7b769ae05980ddb1e8fb09c5946a21"
    $a23="b500e159254cce19c7b53b0c83bd56be1e2c991f8f24590e4e84d81cc036c323d4e36e2f8ef335c167565b9ddd89b945"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_512_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2df4dab3baf0ff7e54bd1cc0ab00640d39ea47dd5458502795169cf472b4f7c466f0fdd0078785050ab781ec412cf0114c897f3876e1d8f458aba1dbb4eaefc2"
    $a1="2df4dab3baf0ff7e54bd1cc0ab00640d39ea47dd5458502795169cf472b4f7c466f0fdd0078785050ab781ec412cf0114c897f3876e1d8f458aba1dbb4eaefc2"
    $a2="c6f52a0727c73e544bfc529d3f2bb864d8efe4aa532f96a6aea23236020b604187310dbe251293a91fd948a626be432081371fbe11c45fd6ce791b74cacfeb29"
    $a3="1b553e6e2f919758eaceb4c940055d95507e3a6f2bc82252dac4ba0e72bfd3cb1faff77f8d2d727c309ecc92f3571f92dc5cd1c77ab1d62c91e3187da543026b"
    $a4="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a5="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a6="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a7="23da8a9053fc47ed8afb004dd1559061050ddc8ddf1d38f0b02566b9a2f6962345e22bd807f576775b07cd8a63aafc583fe7747bd73f0633e7eb83791d3967e9"
    $a8="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a9="c6f52a0727c73e544bfc529d3f2bb864d8efe4aa532f96a6aea23236020b604187310dbe251293a91fd948a626be432081371fbe11c45fd6ce791b74cacfeb29"
    $a10="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a11="4ca3b7215d659c39d1c53722ca55e6ef297ea06e2ec4a66a6c5268a4951bc5129b4e0fa6f150ebe06d2dfa29d78c92dd855a274525386b0296caf6b952507870"
    $a12="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a13="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a14="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a15="2df4dab3baf0ff7e54bd1cc0ab00640d39ea47dd5458502795169cf472b4f7c466f0fdd0078785050ab781ec412cf0114c897f3876e1d8f458aba1dbb4eaefc2"
    $a16="23da8a9053fc47ed8afb004dd1559061050ddc8ddf1d38f0b02566b9a2f6962345e22bd807f576775b07cd8a63aafc583fe7747bd73f0633e7eb83791d3967e9"
    $a17="23da8a9053fc47ed8afb004dd1559061050ddc8ddf1d38f0b02566b9a2f6962345e22bd807f576775b07cd8a63aafc583fe7747bd73f0633e7eb83791d3967e9"
    $a18="4ca3b7215d659c39d1c53722ca55e6ef297ea06e2ec4a66a6c5268a4951bc5129b4e0fa6f150ebe06d2dfa29d78c92dd855a274525386b0296caf6b952507870"
    $a19="4ca3b7215d659c39d1c53722ca55e6ef297ea06e2ec4a66a6c5268a4951bc5129b4e0fa6f150ebe06d2dfa29d78c92dd855a274525386b0296caf6b952507870"
    $a20="9951bafa91855ce83e99eb1fcf55c151ed36600bff9176f3af462fe29b06e09b27ff1484704bb62dc818b48f63e06a7210c0affbe36e96ee56c159cc3e996683"
    $a21="12736c0a6464eae8bb256e578fa74680456c90e1d23c67a57194b6ce28cdd1f0d0498394ff2692a7475c27c08e4334c82b22d29d1441ae4b2702acd9d5e43c39"
    $a22="c10a176fd1741b90f0ffc3b57ca22bc2c96abce4623491897a40278ca9c9e1a47b13f443efa8deb64589a65342fbe37cae86eba972561b910a620555e721d03d"
    $a23="adb933810d393a945f733e97757f50d71cae5957d879ad8d2713a30991b79e2685edc1f826f65ac4d1e9d063ed8148767d564d4617e7d68dd06b9274de83e2a9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule base64_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3lzYWRt"
    $a1="c3lzYWRt"
    $a2="ZGVidWc="
    $a3="ZC5lLmIudS5n"
    $a4="Z3Vlc3Q="
    $a5="Z3Vlc3Q="
    $a6="TWFuYWdlcg=="
    $a7="QWRtaW4="
    $a8="ZC5lLmIudS5n"
    $a9="VXNlcg=="
    $a10="ZWNobw=="
    $a11="VXNlcg=="
    $a12="Z3Vlc3Q="
    $a13="VXNlcg=="
    $a14="c3lzYWRt"
    $a15="QWRtaW4="
    $a16="TWFuYWdlcg=="
    $a17="TWFuYWdlcg=="
    $a18="ZWNobw=="
    $a19="ZWNobw=="
    $a20="MTUwMA=="
    $a21="YW5kIDIwMDAgU2VyaWVz"
    $a22="d3JpdGU="
    $a23="cHJpdmF0ZQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

