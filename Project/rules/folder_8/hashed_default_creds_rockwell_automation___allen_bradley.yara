/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        id = "dOA9I3fR6OmvBVQ8BzmwM"
        fingerprint = "65eeee4dcf53097a78ac5b725d7d43c7ee256a0459bfa637a505f0b8a69e4506"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="a7ff3f3dfe4c1faf2d06c3f83105a5a9"
    $a5="7276ff2f82204f4161a2df026da20099"
    $a6="a7ff3f3dfe4c1faf2d06c3f83105a5a9"
    $a7="442f3bcbd926b51d5a84acdc82b4a4b4"
    $a8="823893adfad2cda6e1a414f3ebdf58f7"
    $a9="823893adfad2cda6e1a414f3ebdf58f7"
    $a10="9a3b1b48311950e7d2ed9c7308d5f563"
    $a11="a4141712f19e9dd5adf16919bb38a95c"
    $a12="c9d793a5059786e1a424a20827d73ca4"
    $a13="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule mysql323_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="58f7ee435f925abe"
    $a2="5d2e19393cc5ef67"
    $a3="43e9a4ab75570f5b"
    $a4="14cc52d0761ecf63"
    $a5="41bf12fa0c1dc5a2"
    $a6="14cc52d0761ecf63"
    $a7="3e643a40542063b2"
    $a8="57510426775c5b0f"
    $a9="57510426775c5b0f"
    $a10="3d6a18240601ebdb"
    $a11="7a7eeba37575fe5e"
    $a12="30f0cbc11bc9b6d2"
    $a13="7a7eeba37575fe5e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule mysql41_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*99ACC2D9A89606546A8AB1684F1EC3E89884DEFC"
    $a5="*A9340D88657188FF49AC10DFC0BF6FC8E8902638"
    $a6="*99ACC2D9A89606546A8AB1684F1EC3E89884DEFC"
    $a7="*FC726AED4F0E0A9196111E4958015337B9A44E7B"
    $a8="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a9="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a10="*F84CA0C34B072060E7FB01D9E00406D8269295A8"
    $a11="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a12="*14A3BF3DE2947AB353903EBDD15E283E13D8D8B3"
    $a13="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule ldap_md5_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}eJRv+w4/1+9OD+zpQvZXWQ=="
    $a5="{MD5}dk3p8Ck9OyLcgK/mdnn7sw=="
    $a6="{MD5}eJRv+w4/1+9OD+zpQvZXWQ=="
    $a7="{MD5}jexwDac+AsQEpISxbUyq0g=="
    $a8="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a9="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a10="{MD5}3Ph/M7pPh2zvdoHBdwW0kA=="
    $a11="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a12="{MD5}Epri2wsP8Fi50Y6qR/M7qg=="
    $a13="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule ldap_sha1_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}0B2LPOuZ1huGuUuGkTp67WvNeZo="
    $a5="{SHA}Qa6M9/Hsft+MfMH3foAFk+FKomU="
    $a6="{SHA}0B2LPOuZ1huGuUuGkTp67WvNeZo="
    $a7="{SHA}5N0/xUmpktk0ua7MDTfAmMVMzrc="
    $a8="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a9="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a10="{SHA}o6IojozCfOqPcC8srrGVdo5SjAo="
    $a11="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a12="{SHA}BfCwdGmrGvkqNmB66UdSSeKIs7Q="
    $a13="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule md5_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="78946ffb0e3fd7ef4e0fece942f65759"
    $a5="764de9f0293d3b22dc80afe67679fbb3"
    $a6="78946ffb0e3fd7ef4e0fece942f65759"
    $a7="8dec700da73e02c404a484b16d4caad2"
    $a8="084e0343a0486ff05530df6c705c8bb4"
    $a9="084e0343a0486ff05530df6c705c8bb4"
    $a10="dcf87f33ba4f876cef7681c17705b490"
    $a11="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a12="129ae2db0b0ff058b9d18eaa47f33baa"
    $a13="200ceb26807d6bf99fd6f4f0d1ca54d4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha1_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="d01d8b3ceb99d61b86b94b86913a7aed6bcd799a"
    $a5="41ae8cf7f1ec7edf8c7cc1f77e800593e14aa265"
    $a6="d01d8b3ceb99d61b86b94b86913a7aed6bcd799a"
    $a7="e4dd3fc549a992d934b9aecc0d37c098c54cceb7"
    $a8="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a9="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a10="a3a2288e8cc27cea8f702f2caeb195768e528c0a"
    $a11="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a12="05f0b07469ab1af92a36607ae9475249e288b3b4"
    $a13="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha384_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a2="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="59f42752047c2f96534afc66eaeabfcab757a5d037d9ece8b140c1dece1b1e8905ad886f3e5f6a601242f69956057b27"
    $a5="bc103de599c019dc3731bf079680d3b4a47f2d5230cf5152a1804658f00a6f9f0942bae24bc4da93b3140bf351b247c0"
    $a6="59f42752047c2f96534afc66eaeabfcab757a5d037d9ece8b140c1dece1b1e8905ad886f3e5f6a601242f69956057b27"
    $a7="59574b4173ec4533369d13cb3b1c4496cc8fdb5a10d22298e26e1952547e91bb624102df5ccbea276a169e2d8c2e3b0f"
    $a8="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a9="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a10="92c6a814f27de333d7883d1a4fda98a1a9042d498c57c4597791f6ddf6d7448cb4371061da793a52c71f2bd88eb98524"
    $a11="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a12="762325d2e67ae3257b112a4130c54b5ba33d409a884c48ab6b0895cebbf39812a367466e2a8a7bf431cdc58dede41acb"
    $a13="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha224_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="ac1474b06b6662446155ce2845692a9b1a156139b1d5464955b4f483"
    $a5="32ee436e5d71971e37541945be338f5d792aa9aa3a95a99eb7f38bad"
    $a6="ac1474b06b6662446155ce2845692a9b1a156139b1d5464955b4f483"
    $a7="5e42b4b573660aaa6783cb49625c6a2ca3fd2ceb0db836d2f55b3452"
    $a8="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a9="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a10="687cb1ae396b49a4344c96d8da99ee7dae292b03eeeba4a127ae1876"
    $a11="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a12="d39148f4d651d07e5598a70830cb4af98f5e64ebd151342e5139b828"
    $a13="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha512_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a2="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="15e11ab0562ee203c7b73c10f792f1364623de4d2a18663c53e9e20cc11b001f3990ab2f81fdd0a8ce2c6a8b81733e61a32a89bbf55d2299369409bb0b8ce66e"
    $a5="acd79785b2922bfb3ce1068241c2106b5617ae10a6ce81cc2708ee6efd864cab04f86c54ea2f5345a45eb1dd1009b64addd9df4a083423de3c96df22f0b9ef0f"
    $a6="15e11ab0562ee203c7b73c10f792f1364623de4d2a18663c53e9e20cc11b001f3990ab2f81fdd0a8ce2c6a8b81733e61a32a89bbf55d2299369409bb0b8ce66e"
    $a7="6c94dc42777c943ce60d56c6fd851c51dfb96e177484706afbc50106b10bd297592f6d91701ec6f35da94636e6504e4aa889a796919b2dad10d987167f55a48f"
    $a8="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a9="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a10="da3f1c38b3ce6f87c35eb5b1e48e81e0781d5c286d1cb8c84601fcbc7fbd7c117979162f62d33eead86a1d6bb7f46459cc0c97b1e67acba8afb8fccef650ba02"
    $a11="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a12="d740d2d96e374cda55b6b1d055fb7047204aa2844615665e6764d28e6dcb79eaa71aa1a5a46a29d7ee3fd96c25bd1463df17ba64f6322d12e9baa77e0cf65c8d"
    $a13="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha256_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a2="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="a973366c1b5ce1634adf74428079d86c28773ae64dd2c96750b00871737c8d33"
    $a5="cfdc129e475d7bb885854f7c3a86d34a35b662a1706e7585d7b88647b9535447"
    $a6="a973366c1b5ce1634adf74428079d86c28773ae64dd2c96750b00871737c8d33"
    $a7="db12a8751aa38c950fe087780945215c97c2a57eb89be9eb0530bc88e24c0680"
    $a8="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a9="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a10="f50c63b028e99997d393aa21e3bae1de16c2e43c9f0cc3e52dd1b5132c97bbdc"
    $a11="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a12="3d004e622af5937de069260e2fefbd92fbd341770e549fdecfb3f1a7019fad77"
    $a13="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2b_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a2="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="cc85e4608cc830bb25b6ef9d83cc7ba88bffa4218e344ba1d2e450a6ac2feba0a58727c67fd6c397549d0b6075592c6c2bdbc668a51a49cdd8aad758df53c66a"
    $a5="02dff1d4a359ef1a1b72f27938f55fc3f5c4ae5448e695955cf41d37bd3cbba8a85b84ba31eef2d84438ffe7e2285659abd9d098075ad6e71b8978213fae31db"
    $a6="cc85e4608cc830bb25b6ef9d83cc7ba88bffa4218e344ba1d2e450a6ac2feba0a58727c67fd6c397549d0b6075592c6c2bdbc668a51a49cdd8aad758df53c66a"
    $a7="9ee8242fdce3b8c0f2c4ce8a37a1e38b25e2218344496f4cbe3ad00ff419e37a13f098e189ef518a879dbdcbb0dab05a02463a6cc71e66e0cad684fe299001cd"
    $a8="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a9="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a10="9c2adba6cebddd0b577f169c051d027c8fe90d047bbd622fe6911d9620cd132aa6f223e025c73eab3e4ea0a60e83941a390b377b99b6d62d490320f6d1243d2e"
    $a11="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a12="07dd6553d8fe8ae0fa0dfccb05adad8fd136e9b77d26d5c9eef3a48842039ab53a09db8b956c16f3b53af529dc0a5c79ecd9a3cf00fcbb0b6e332c2b287c1a01"
    $a13="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2s_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="894b385d5c8140943a4cb0d77317f4d892ef5b796b09f06e6b6dbd940fdc4cc3"
    $a5="fff9f2722d6603f74cddf024b6a0bbace26b322689919a5289474a9b6b12c22f"
    $a6="894b385d5c8140943a4cb0d77317f4d892ef5b796b09f06e6b6dbd940fdc4cc3"
    $a7="c7c1e70a09034c28aaf217377ad3370439e6a46ed9e249abe4ede6361aba703f"
    $a8="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a9="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a10="b1dc7bc88bfda20471d760fd627a3cd8b1f4df6d7e625ef41b41b8859d5b01c9"
    $a11="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a12="6dbf890cd626cd2f30cded320fee1c2d9aaa5d1932fceac1dd99b8edcfd8477c"
    $a13="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_224_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="841fa703d3d62efe1d04f7a2985425a0d22b9048461cb102c0e45bab"
    $a5="1bdf1b8e182ad1e5031e2c7e1649b5a4ad13a9c16d6b892c0942afd1"
    $a6="841fa703d3d62efe1d04f7a2985425a0d22b9048461cb102c0e45bab"
    $a7="bce7641fee5cb750cc2c9d89eff288973c09e09eb2e18d0037739262"
    $a8="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a9="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a10="3300785c377583971d8241d3dcf8cec718c3daf31392496c969452e7"
    $a11="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a12="baf6f3dfdd1b9d6fa8a5cbdc360de08498674e681f042bb835d9fb96"
    $a13="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_256_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="ea2dd0bafaba2169f517e8f3edc182c67637b89903c69c68c86eb386b8cb7101"
    $a5="4d614f42f26e33094907a4f514089b6fbe39406819596e72cc0a6c9e3a19d853"
    $a6="ea2dd0bafaba2169f517e8f3edc182c67637b89903c69c68c86eb386b8cb7101"
    $a7="9f0b1265514403b23ba0c75f5345a55981601bb2b735eecae81a3fc3bbeae23b"
    $a8="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a9="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a10="a8bb0b0a4db037a2056889667e0672b4d4dbc6fff045408e13efd377cdf034b3"
    $a11="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a12="2f6c7a4002c96b6bfb5b6cf9249ca5caebca87e292d5af0e14f125a1f73d1862"
    $a13="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_384_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="bfbd0f3e3c470c2d3976e44e9558efd84f44cb298851d82c15f3d8864d2d257fdbe17707389550d48f82c9bf30f3cd56"
    $a5="19df6fb1afa3ece8907b0af4c1fb24703e7c2b8202810a2d0ee78f1395d0eaeb729f30f7eef9ca9a93fa6bfa8c65a83c"
    $a6="bfbd0f3e3c470c2d3976e44e9558efd84f44cb298851d82c15f3d8864d2d257fdbe17707389550d48f82c9bf30f3cd56"
    $a7="b2de79279ff8193fdd6b393af4e9f696650cd6a84464ad5489aada4beea3ee46dfda60e8cfec1b9619af35a7870b4ba5"
    $a8="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a9="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a10="cce720412c2ef8bc3d3382ccd9741a66b90f9d88f4c0e92fc774fb896a5760fcac3057896992c955319e2837ea80ec18"
    $a11="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a12="0f8baed846a780b070317ce98573c44d035f2d6779457dbc699fa8794cd582cb596b04f18fa4cf7a16e22ca986ae365d"
    $a13="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_512_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="4019d67cbb61ae99be590560b56687fe53b6cede5b9a91cce74aea517fd8527d47c38a6b44e2fbff97aa7a8f59749d94b6a8545587c651f8892407bd15840b5f"
    $a5="257d6aa9c727c6833062be21aedc3d1f8eb3c58fa7af2db287bfb08c9f404409d23eb833633b7c5681c019c63f54bd556ffbf5b901655b5d7b0878f8353aef88"
    $a6="4019d67cbb61ae99be590560b56687fe53b6cede5b9a91cce74aea517fd8527d47c38a6b44e2fbff97aa7a8f59749d94b6a8545587c651f8892407bd15840b5f"
    $a7="83763184017775169d6e49acbe76a4d2fe548f08aba64bd88e11392ae5c3eaea6555e64942beb5d4ea6915ee97374447d2a561ddbea4608d5b6c4b36135f48b9"
    $a8="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a9="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a10="20b23956753615eadf495bf31ab307e1003e478b4f30d79074165e2402f2fa3f879ab44be88561f372a2b98cb9461afae8871d47636ac640c6d572ac10c333eb"
    $a11="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a12="ccf16db31d1022f26c815beb938efe2b9725b277b4d4ab5fa3461da2d605e730db48d27c0aa67516fd48bc0f5e4eb7c963dd0aa31cfb525a423fc06693205261"
    $a13="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule base64_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW5pc3RyYXRvcg=="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="cGFzc3dvcmQ="
    $a4="dXBsb2FkZXI="
    $a5="WllQQ09N"
    $a6="cHBwX3VzZXI="
    $a7="WllQQ09N"
    $a8="Z3Vlc3Q="
    $a9="Z3Vlc3Q="
    $a10="YWRtaW5pc3RyYXRvcg=="
    $a11="bWwxNDAw"
    $a12="YWRtaW5pc3RyYXRvcg=="
    $a13="bWwxMTAw"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

