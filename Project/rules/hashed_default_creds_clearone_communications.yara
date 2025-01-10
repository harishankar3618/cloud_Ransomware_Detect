/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_clearone_communications
{
    meta:
        id = "4SNniUpm1y2k51jRlcxNIV"
        fingerprint = "054d4931a9c98e44fae0dddc6e34c903deac5cf3adb6743337e1a382ce7d7d5d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fed850acfbd29174add53ba4d4a75818"
    $a1="674ee821426649f2ea50db43b0ae27dd"
    $a2="b4288fb6c01cd4d3d406cc6106207989"
    $a3="7baf939dbe9f1e3adc9fe7ef06e965d1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18b53b936fc19001"
    $a1="0f267553558bc71a"
    $a2="7f4214c526708a2e"
    $a3="1171fa53517afa7a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B50E2145223248E53BE5E471F410CF5E9DA99983"
    $a1="*1FB07FA4B6F61E1EA743444B16F2D4635CD40C2D"
    $a2="*0B304F30352992829154580CE27AC37FE1BBE32D"
    $a3="*2B9A8B2E39799CE3F1C5AC3159444B684625C6BF"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}8Au7d0eSn6+p0a/Qcdunjg=="
    $a1="{MD5}jtQCs/psrKmI/tZkIhEJyw=="
    $a2="{MD5}bEL6d7n0AiXXxfyMv1RlNg=="
    $a3="{MD5}4kf3/1lzOoDSYplfwA+z7A=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}GrMoB5bUJILbmcVWZZc4vQXyrEY="
    $a1="{SHA}8w742vUrtLf6zrqJyTg6agd1ZRw="
    $a2="{SHA}5+TGvhKA0SvJsrdVA38O6IC9Lbw="
    $a3="{SHA}gcna3eeTb31dGHfgKHoETDaVQ5c="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f00bbb7747929fafa9d1afd071dba78e"
    $a1="8ed402b3fa6caca988fed664221109cb"
    $a2="6c42fa77b9f40225d7c5fc8cbf546536"
    $a3="e247f7ff59733a80d262995fc00fb3ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ab3280796d42482db99c556659738bd05f2ac46"
    $a1="f30ef8daf52bb4b7faceba89c9383a6a0775651c"
    $a2="e7e4c6be1280d12bc9b2b755037f0ee880bd2dbc"
    $a3="81c9dadde7936f7d5d1877e0287a044c36954397"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c98f7893a47c432ae28e6024a345dff67233e1b54b2d1c73662c7b3eae567caf3ef5a2d2a204f8aa1290b64f869894de"
    $a1="1e85c366175990ec1eeea3dae48364fcb193f6e48b6fc073d46f001841d5aba3a6f93633ccac01a27ad96b1321e72158"
    $a2="625a921712f28a1567b1140b40f884869e62e23dd312b2984eed227692d44d53c50bbbccf718b9db42e2049b8ca730f0"
    $a3="1341b34f7c8e0fb7deb68b3da30c3cb30dee1809e52ef883536efb5e86d873bbb85a81407ea2f0abb68346644155736d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a3f46b8bdd14b4a819c84c43c2f1aeefba0adcb4839aa354c6a4b10"
    $a1="748b089a11fe5e4d08577d53134155745e791f49f677ac44ed554354"
    $a2="fb18dff476b2148de33fd3122f9589d39236ce4fb8a7956176bd675d"
    $a3="22020dc655d0f086116d2e85bd6c9301f3ea9cbf3a9bcf490e28d3d0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4fe2742c36544a0c483660f3cab4f97f9b03fc2f4b7d96e9a6b0b7537065ce365cf75f9b18b98223adfa01a46bc30991a2fdbad658614b722edd82a9cac8385c"
    $a1="e7876299a40d476be39c097fc84dac39c8e745fb41391ca929bbf17d749f564576795535290c1737114dc31d9f71db191b1125c403d9de269e2280183dd566cb"
    $a2="9ffa0289047df18fc8f3a0873a5084b42ea4d21f37dd6b6063dd838b052b2f7d5c9a4f7f4b776d1628a63f39b1b5448d665ce445b200f3b40ec8a69f7556b71b"
    $a3="41efd98e07e0cb762fe8c50af1ac78c31301b6403b5569504b4b24bb695a4834202e3a5c3b59c7da4e3ee1f349b8a9e0dfe1ba656927b0d261a44204f2d21c19"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54caafa49296ec47f1839e46980ed744804fb7b23264bc6801e03af643c5fbf1"
    $a1="d0ea4a011db775ff3782b0e6dee0c25907909716e4b162d2054520615065464a"
    $a2="c563c209d627c4c5585b8bc6fe39521c27b545be63927fa283df66ff03abf315"
    $a3="208e992f2d602142a01d0663211b6c27d62a20a7c3f9aa3c9b476b4e7ad28953"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8b661eccb7755608285d8df90d4b20edce71ccdbe76f9c23cf82fd9e4447202dbc951aadf0b3de93cb3993abc03cc2d0fe183b2c48d568910fb16a28a942ccf"
    $a1="200d1408e8e9aae885b9d686c724d45f1f0df4fb28df147279cbe5865ba0590e770f90cdc0be3ca90fb78825940aa56e00449828fe403ba0562fc0e5f08ce3d8"
    $a2="92df82a884b3edbc9f73f48d7558a88f83670bc43faa86f4e7258fbeb3c6e04f4a55023709542c39278a2a2e24827d155cc6a8f3ec7d19ec56eaae85fcad35a9"
    $a3="d4a6a8df325d4f527cc09e3aafa10a97e9017b197ed6fd21a884f6166c0975990d2ecd694ffbc5e7c5d4198a7f76dd972f2eeade71536e1a94a86c73bd067d33"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f00f0e3472200fe1005639680b0b8d1a42eff76cd201b0f35acca2ad3d5a193"
    $a1="f40cbef85f9f77e707d6dbdc17357d6131cb28a2394c0199143e0ea7c61b4b2c"
    $a2="622f4e8dc501cd4902852c92315a523b95562fe0dd38d5d2eddf6193c9244e97"
    $a3="e0ba7472698e0f397e79d90df4161c49e98901be880d7bc867e19fced3446487"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2181c1f89f533265b2e0d39a6d50e0b695f0b8edb55319effc618b03"
    $a1="67770354014920888f17f0f59ca504415087d0df75ebd7b0d6517b70"
    $a2="1e2919ffe3f0cb870be18c31bb9f3d3df9dad3983138c72d10ac3237"
    $a3="1b7e2482bc4d1b5828720925e9fc446aaf809d1779efe909343de13c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a32f6c38af28e930ea85aa730dd0c0d87f7885cb3f9db5c7882045c54ef6274f"
    $a1="4ec81bd44262c70330bd50fefa7189352c0c0e95025a15148be39c1484b592b9"
    $a2="1682c530a80b82e27c31b40bc8187e0f727d461d4587bdafe9456ea7d09a073e"
    $a3="d7d6e1b9955c2c48883ffa8763103f517d560769acadc438b15b3ae664cbe899"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f2388e9d87457e92b81f99e9f073ac39bcc5e94039f9f350c909b64e0afbafee050a745ffc0906afc5adda0a3a30dad9"
    $a1="3b7f166f1f53674024eaea0a08486166ab1b9f28f26ba984cf05cd0872ccd3ba5a222fda1bbe4c741d091988594c9cf4"
    $a2="3f1fc78f8999010f75a8506228ecd49beb282bb608d2c6dee87f3254c7ac4896a77e19e76e95157cac7536ce6589fc41"
    $a3="529eee81848c0b9c70ab004466c7565cbf93ebbd22742047c814635ac508b1b8c006075f8681f72b6a558b879f19958c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ecc7b00ffa23befbe039e9ff3fa24459803b76ceee959e764ea5f91ec0ba79ecbbf1885fea69c70be9df66cf7b0a95fc76716a18ec629902c150c36edf2f1ec"
    $a1="4b8192c5ec7975664d009ee684cebdf44c7b33d106699b5d94762f17673e64ae3203441666c418fb16b75317c529b43c4aa3cadea14152864b45cb7c9c5fc76f"
    $a2="08aca657e4b9e6a400041464ca90dd090e4c945645c7995879da851cc75c3dfc188646ac0049a732ab52f39219029ea97a369c6ba3cfaded679e159d5a609d11"
    $a3="2917ab1e249787255701b6c3852cecda12dfebb8bb1160d4dcaf420de2b43c7baaf2c6c91a4507e8f506f5fed262dbe218dadb9d56b136aef439ffb546cbf20f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y2xlYXJvbmU="
    $a1="Y29udmVyZ2U="
    $a2="Q2xlYXJPbmU="
    $a3="UkFW"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

