/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_general_electric_healthcare
{
    meta:
        id = "3G8fcZBgKoB31fo3n0wBAH"
        fingerprint = "1e15459587a2890068e35fe191c0734ab82c0d9180a5dfd033f0915dff13411b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
    $a2="6870185312c803240aa99c3702639da9"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="6870185312c803240aa99c3702639da9"
    $a5="6870185312c803240aa99c3702639da9"
    $a6="769ba068568072b10b2c0d2e0f02ebab"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="8588ebf11ee2219a33e70a21b6bc6866"
    $a9="9b3b43a7ba16b656900d947cb9862e23"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql323_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="4077eb0b03ddce3b"
    $a2="6ae06afe6eea8d23"
    $a3="43e9a4ab75570f5b"
    $a4="6ae06afe6eea8d23"
    $a5="6ae06afe6eea8d23"
    $a6="7026502040899555"
    $a7="67457e226a1a15bd"
    $a8="6d45c652228f2d20"
    $a9="2c46fb58043ef1b0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql41_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*D89A99106002D77C1D327FC41E005919505638B0"
    $a2="*BE0C64F8900D465CB1D23FE352CC2B0F4B7EC302"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*BE0C64F8900D465CB1D23FE352CC2B0F4B7EC302"
    $a5="*BE0C64F8900D465CB1D23FE352CC2B0F4B7EC302"
    $a6="*B7273AB063A1055607237F2DD5A1A519F9362ABD"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a8="*B207EF8923E9760F9773C62828F6451D3CCDA84A"
    $a9="*62BD1A28A2E76669460A4FD27F83937C76E907C4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_md5_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a2="{MD5}F4VBT77XOSo+iU+TCSnL1w=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}F4VBT77XOSo+iU+TCSnL1w=="
    $a5="{MD5}F4VBT77XOSo+iU+TCSnL1w=="
    $a6="{MD5}TrGnrNwDNMsiOegwjtVs/g=="
    $a7="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a8="{MD5}NbPbgFn9ksSYYnBLNkEMzw=="
    $a9="{MD5}pnFeWsgAUaAgX+UKIvdMRA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_sha1_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a2="{SHA}NVm85iZiWcYcDoqkP10gkZj1FuE="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}NVm85iZiWcYcDoqkP10gkZj1FuE="
    $a5="{SHA}NVm85iZiWcYcDoqkP10gkZj1FuE="
    $a6="{SHA}2ODkvBcvRzlPccbEMUdew3uIPE0="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a8="{SHA}GNn2o/pamf7gz5cF99qtQ1YhBx8="
    $a9="{SHA}mhmMnwNrc4OZW/o+MFHs/7UG/ZU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule md5_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="e3afed0047b08059d0fada10f400c1e5"
    $a2="1785414fbed7392a3e894f930929cbd7"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="1785414fbed7392a3e894f930929cbd7"
    $a5="1785414fbed7392a3e894f930929cbd7"
    $a6="4eb1a7acdc0334cb2239e8308ed56cfe"
    $a7="63a9f0ea7bb98050796b649e85481845"
    $a8="35b3db8059fd92c49862704b36410ccf"
    $a9="a6715e5ac80051a0205fe50a22f74c44"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a2="3559bce6266259c61c0e8aa43f5d209198f516e1"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="3559bce6266259c61c0e8aa43f5d209198f516e1"
    $a5="3559bce6266259c61c0e8aa43f5d209198f516e1"
    $a6="d8e0e4bc172f47394f71c6c431475ec37b883c4d"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="18d9f6a3fa5a99fee0cf9705f7daad435621071f"
    $a9="9a198c9f036b7383995bfa3e3051ecffb506fd95"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a2="ca9e49474f5e878cadaaf494ee85038fc6cf1230e9ea9e88fb863343a3ffd8c9e5747de0b6ef599bf32e00f27937b67c"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="ca9e49474f5e878cadaaf494ee85038fc6cf1230e9ea9e88fb863343a3ffd8c9e5747de0b6ef599bf32e00f27937b67c"
    $a5="ca9e49474f5e878cadaaf494ee85038fc6cf1230e9ea9e88fb863343a3ffd8c9e5747de0b6ef599bf32e00f27937b67c"
    $a6="f7e9a7ac5176bdd2e265a156754c78b5f99e5b66d6880a7ad8ad44e198f30d5c3ca61b0bbe5726a8a36bca1b00fd6e68"
    $a7="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a8="42d006cecba897949868c11d26e729a902b4968aa40c786ffc0c279301ab409a4b9219fc63ef3498a99cabfee9ffe58d"
    $a9="ab665571d308b61a9967706fde1299e967779aaab172b73ab8f02ae912d6a93e4d904389e07db532bc9725d4b1333f4c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a2="6b3622227bb6985df16f796f1eda9be9ebab4c08837e1cfb236804b9"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="6b3622227bb6985df16f796f1eda9be9ebab4c08837e1cfb236804b9"
    $a5="6b3622227bb6985df16f796f1eda9be9ebab4c08837e1cfb236804b9"
    $a6="22fad01ae2b72d9abd7321d5c283545bdb79b56cc2a0da5afd42f9c4"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a8="a2f637211b294a257128cfc2c6b8b278d99d6d7c2df09f5933bdcba4"
    $a9="e3d1008edb1c68d858f4fa6871f2abaa168c041058ae276c065fb63f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a2="b293f5f9497a37b0ee2fa78ba297653ceef80af78433b5822438c44dc25d7d5e7c14b63c162eb5dd119f276266119e856328c6fa9d854b974e9483813956ad67"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="b293f5f9497a37b0ee2fa78ba297653ceef80af78433b5822438c44dc25d7d5e7c14b63c162eb5dd119f276266119e856328c6fa9d854b974e9483813956ad67"
    $a5="b293f5f9497a37b0ee2fa78ba297653ceef80af78433b5822438c44dc25d7d5e7c14b63c162eb5dd119f276266119e856328c6fa9d854b974e9483813956ad67"
    $a6="8f08246f7e2ea04f82ae424b086dbc91fa829507ad61f84553c0a533978561b7f9ebe04dae055fe95e9b67351fb89dd224b0127caf1c0149ce46f02677814486"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a8="af10118672e49e03993ffc4d67137e23fced75779299fdd8603cfed03349acc6ddf5cf14644f106c09143792698cfe38cba2fc68f6d8ad7109860b8b225b808d"
    $a9="a81ded4d8247627ff6cf7b9fdfd760efc97eaa055447bdc9c26f3c5e975c2c25ca6dc1a2eea3b331a21529d4416642ff2b8da079a19d1df0664bef1304bad399"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a2="c9bb503300194d3202e27f4590b1a6f3575fa8ff9d8b2155ad8df932bf0f3778"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="c9bb503300194d3202e27f4590b1a6f3575fa8ff9d8b2155ad8df932bf0f3778"
    $a5="c9bb503300194d3202e27f4590b1a6f3575fa8ff9d8b2155ad8df932bf0f3778"
    $a6="d768c1ee678644dce773dd6f7078ddf89ee4ee9ea0d270cc66d196a4b399391b"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a8="a2e0e7ff5cd818186b05ff07c9cb646e90d6b38bd7a583425613871ac4132e6b"
    $a9="48886fa89ff7ec55343263a088bd1ebf0e798b7646d99be34d8c34d1683b5aa0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a2="e3c443dba0236abfb1dee273898cad82def58cd02d4d3d68dc13c27fc1255dda9a569d4c573a117d4cc8fa8525408c6590b79f700a4404ad9b5cd3ea99dd17ff"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="e3c443dba0236abfb1dee273898cad82def58cd02d4d3d68dc13c27fc1255dda9a569d4c573a117d4cc8fa8525408c6590b79f700a4404ad9b5cd3ea99dd17ff"
    $a5="e3c443dba0236abfb1dee273898cad82def58cd02d4d3d68dc13c27fc1255dda9a569d4c573a117d4cc8fa8525408c6590b79f700a4404ad9b5cd3ea99dd17ff"
    $a6="971a2ed24ef1107144f857efd569898d09473788c0760160ec11f9c473e0f755497318746d1195d7c17571604398072e0c41a65fe5e840180646257274d3ea62"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a8="cf5b11040faea433a418c2d37fcaa683e11df7d03fa4a97efab8d5321ee010ef957557d7248be8ed5fc2f67b160fd862bc365a2fe928f5dff8319e4f00f6d387"
    $a9="f73ae1654fd863c460ce69617d08f76573ed60b6b71c82b4726f641854a9ef6f86163cc3d3d194f4263f579b78b22d4b9664d876be4fade88312f19606b9e3ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a2="69c0fc0894d97a0a109c1322cca94287457509a69294996cf15227cf8bc70f40"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="69c0fc0894d97a0a109c1322cca94287457509a69294996cf15227cf8bc70f40"
    $a5="69c0fc0894d97a0a109c1322cca94287457509a69294996cf15227cf8bc70f40"
    $a6="60cbf99cbc066d31fd8f00b2f7a3d62ffe1d94f8d70aac6931d13ff3f208df9c"
    $a7="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a8="fe2348b7887dcb9e65ec9c4200b8f4a8c42a38b43f107691330dde4666e4845b"
    $a9="4e99c76486b8036bc1ef39716afa217b3bd855b78960250619f83d8caf804e8c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a2="341ea0cb47201bc88d3e18913f3f62b37543ff530007bd7bf9c71790"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="341ea0cb47201bc88d3e18913f3f62b37543ff530007bd7bf9c71790"
    $a5="341ea0cb47201bc88d3e18913f3f62b37543ff530007bd7bf9c71790"
    $a6="a01a8a93f5df478a4bf3b40e234a34011a1c02825ac824aef4db3f27"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a8="200410e8dc18f24fc10e3a7e87e74d6e54e3a993a797dd4fecaa6b1a"
    $a9="65ebf58d74d771b108ee706f2bc4cf4eb492b07e0e73b7552cf9e61e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a2="05d618642a430d4cdebb7fddf959075f8f678f4fa9f7acb02896794d26bffe93"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="05d618642a430d4cdebb7fddf959075f8f678f4fa9f7acb02896794d26bffe93"
    $a5="05d618642a430d4cdebb7fddf959075f8f678f4fa9f7acb02896794d26bffe93"
    $a6="cab6da75769c88a833cae2410176b8b9eac006e8a0a75364f8fd8617281249bd"
    $a7="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a8="98095726530397f28bab68905464f9a00275f176d660c3d4b1b5665ac5ab98e8"
    $a9="563744be95bddb62d3575b293d29d7317b6694d17b93a0e418c62e66199bb011"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a2="66f11b3fb9d7052c36ffb01d30d97439e85ec3b0d981b05910e14034caf76a03063eb32f5b67cdbc697b963deb2915a1"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="66f11b3fb9d7052c36ffb01d30d97439e85ec3b0d981b05910e14034caf76a03063eb32f5b67cdbc697b963deb2915a1"
    $a5="66f11b3fb9d7052c36ffb01d30d97439e85ec3b0d981b05910e14034caf76a03063eb32f5b67cdbc697b963deb2915a1"
    $a6="40e12b42de129576b2788a6f0b84019732e616b8eab62b424b2601834c00f597b61cb3ea9e69a40bd9afc3ef0f4cc823"
    $a7="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a8="7d000799e7e657963926f34a56401c5605e4b967ce11ffd0385c4bae2d48bcd86f624f27df61fc9143886429d964859c"
    $a9="bb6c0384ffc50cc63b12cc2ae64c29452204d4b405f91896a48762aaa2a183e2685082a3c97593cc19cf5506f0556472"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a2="dad451059568dccfe73b5e8f8575b0e4e283b9c4559e9fda90a729fa7843fcd242ca725729b9e6cdc0f6d9d3787793a1ea4b05b7d485e224f90e36b56d1364bd"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="dad451059568dccfe73b5e8f8575b0e4e283b9c4559e9fda90a729fa7843fcd242ca725729b9e6cdc0f6d9d3787793a1ea4b05b7d485e224f90e36b56d1364bd"
    $a5="dad451059568dccfe73b5e8f8575b0e4e283b9c4559e9fda90a729fa7843fcd242ca725729b9e6cdc0f6d9d3787793a1ea4b05b7d485e224f90e36b56d1364bd"
    $a6="30c2a0029c6fd4b4c451efc99a2534f60468427cd0167cc6c6d302832c2a3aa399f8fa33952f6f5bb855d2cfb5714226c397514b7bb75fae1763bb97176bc1af"
    $a7="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a8="aee3be29a8f6de2700e34a3dc62554cae59d4b5715749f38757d7a4b8b7579e934e042d2fe2b9695859262cba51cf6bb1fc8ba315b3909179dfe3aeb09648ae7"
    $a9="cbd3b2afcee3515c7dbbfa33108247acca8c00e82f072f536f270eb594a18e3aa60637d1a883205262b96783f9ce3b00c7a70ec8b8c6f78340651de2bfc5d23a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW4="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="dHJhY2VybGFi"
    $a4="dHJhY2VybGFi"
    $a5="dHJhY2VybGFi"
    $a6="cm9vdA=="
    $a7="I2JpZ2d1eQ=="
    $a8="Y3R1c2Vy"
    $a9="NCRhcHBz"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

