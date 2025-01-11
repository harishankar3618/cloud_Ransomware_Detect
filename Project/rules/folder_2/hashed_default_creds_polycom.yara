/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_polycom
{
    meta:
        id = "10IZZUZTpuU0CJMdjjwIo7"
        fingerprint = "f37ed525cc1bbf45eebed6db4ed26b5545a226ee567be70b26912bebcaf9601f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a420e7750b39be09fa29d314fa4b51c"
    $a1="62cd12b827e5a98ffa3b4b2eac84b93c"
    $a2="893a0f7f1a11a5a0a0b6909e10c80f80"
    $a3="62cd12b827e5a98ffa3b4b2eac84b93c"
    $a4="75438937fa990c591097d354a3c056dc"
    $a5="a4141712f19e9dd5adf16919bb38a95c"
    $a6="47871e9502faab0aba6086ae35137fdc"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="778714772c8c129f00b4591f0755bb9f"
    $a9="62cd12b827e5a98ffa3b4b2eac84b93c"
    $a10="5a420e7750b39be09fa29d314fa4b51c"
    $a11="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="767559eb0d8d12a6"
    $a1="643a4d2911b4850c"
    $a2="70b6d1d27ed97af7"
    $a3="643a4d2911b4850c"
    $a4="099b1815176901f4"
    $a5="7a7eeba37575fe5e"
    $a6="43e9a4ab75570f5b"
    $a7="43e9a4ab75570f5b"
    $a8="767559eb0d8d12a6"
    $a9="643a4d2911b4850c"
    $a10="767559eb0d8d12a6"
    $a11="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*531E182E2F72080AB0740FE2F2D689DBE0146E04"
    $a1="*DBF1E5C3BB3C57AD4966C29169B186DD27E8D211"
    $a2="*4CA5EE9EC5AECDC8F8A158FB36427D5D8AD7F6F4"
    $a3="*DBF1E5C3BB3C57AD4966C29169B186DD27E8D211"
    $a4="*C4A4F6754CCF00807FD77192DB87EDBDD55F9C73"
    $a5="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a6="*5F794C1DDCBE3964E79E87A283AC76BDB72D307F"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*1ACC14962BDBE92DEA39DC99EAF51B8312B1D425"
    $a9="*DBF1E5C3BB3C57AD4966C29169B186DD27E8D211"
    $a10="*531E182E2F72080AB0740FE2F2D689DBE0146E04"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}JQz4tRx3Pz+NyLS+hnqaAg=="
    $a1="{MD5}g0YipBPjxCwt2AgMImvuhQ=="
    $a2="{MD5}HRHVw9n3RRlIbSmEVDPSnw=="
    $a3="{MD5}g0YipBPjxCwt2AgMImvuhQ=="
    $a4="{MD5}LSuWRi0CnPuWw70YVjT5bQ=="
    $a5="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a6="{MD5}BC5K99ylzQk90ecXdeRR4A=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}77E8XZK2QaEEI0AcB0UGHw=="
    $a9="{MD5}g0YipBPjxCwt2AgMImvuhQ=="
    $a10="{MD5}JQz4tRx3Pz+NyLS+hnqaAg=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}UerGtHGihNM0HYwMY9DxooYmKhg="
    $a1="{SHA}sMTzZvHR+VDT5KSOZ92E6JOnHlA="
    $a2="{SHA}Jkzb53nCPemPuTJJjSpiIlJKxqg="
    $a3="{SHA}sMTzZvHR+VDT5KSOZ92E6JOnHlA="
    $a4="{SHA}VDa4zWskmN49GYanGwx1kAUliFk="
    $a5="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a6="{SHA}/sSvTZh0J0+ZRQoRAoYT74s6imk="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}9+wzccWClysVR3Dc6dheL8YPpKs="
    $a9="{SHA}sMTzZvHR+VDT5KSOZ92E6JOnHlA="
    $a10="{SHA}UerGtHGihNM0HYwMY9DxooYmKhg="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="250cf8b51c773f3f8dc8b4be867a9a02"
    $a1="834622a413e3c42c2dd8080c226bee85"
    $a2="1d11d5c3d9f74519486d29845433d29f"
    $a3="834622a413e3c42c2dd8080c226bee85"
    $a4="2d2b96462d029cfb96c3bd185634f96d"
    $a5="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a6="042e4af7dca5cd093dd1e71775e451e0"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="efb13c5d92b641a10423401c0745061f"
    $a9="834622a413e3c42c2dd8080c226bee85"
    $a10="250cf8b51c773f3f8dc8b4be867a9a02"
    $a11="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="51eac6b471a284d3341d8c0c63d0f1a286262a18"
    $a1="b0c4f366f1d1f950d3e4a48e67dd84e893a71e50"
    $a2="264cdbe779c23de98fb932498d2a6222524ac6a8"
    $a3="b0c4f366f1d1f950d3e4a48e67dd84e893a71e50"
    $a4="5436b8cd6b2498de3d1986a71b0c759005258859"
    $a5="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a6="fec4af4d9874274f99450a11028613ef8b3a8a69"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="f7ec3371c582972b154770dce9d85e2fc60fa4ab"
    $a9="b0c4f366f1d1f950d3e4a48e67dd84e893a71e50"
    $a10="51eac6b471a284d3341d8c0c63d0f1a286262a18"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="714b7ac92749929c1902ae7a8497bf8da3fb421a3ec4311332053cc43f0994be9b6844f5b34ebd10d6801a1ea2482918"
    $a1="9a96b4515e4cc95ae6158d76532028c8cf6df26138c17dd221bfc45f6c2074e5d7e713e21c6687b0e88887b5256b37bf"
    $a2="1896d30c608e95c321b2cffd60ac2b71b0662b94e55a70b3d0c53f0a62cdb9698969a372311ce51f0d278607261d2e52"
    $a3="9a96b4515e4cc95ae6158d76532028c8cf6df26138c17dd221bfc45f6c2074e5d7e713e21c6687b0e88887b5256b37bf"
    $a4="db0a91119745c6bcdcf60558d29bce5594891bf7da3ebc8b59f02f1cef2a4598adbea5345be0cec7f4934163df2616ed"
    $a5="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a6="f6dbb4d5687a9ea5fe44f4c88ff5e0447805006b48b8ac6c52dad8e24c7617299e4a46551039841132c3e8ffb8862287"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="0d9a6a03211e1f150d971917fc04c1e98343222c245cdf23543983bf5abfc2c8f5e75174a0bfa85606076cea2ceeb4eb"
    $a9="9a96b4515e4cc95ae6158d76532028c8cf6df26138c17dd221bfc45f6c2074e5d7e713e21c6687b0e88887b5256b37bf"
    $a10="714b7ac92749929c1902ae7a8497bf8da3fb421a3ec4311332053cc43f0994be9b6844f5b34ebd10d6801a1ea2482918"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7bedacebad77e3bc61d1e27db602019c6e0fc954d6c856bd2719968"
    $a1="3778689d047eb9e58cfd5240ab3dd8fd84e1cdcdf0dc53ccecf97770"
    $a2="11882960fbd93ad1606c66d9021f6281515a7d3a2c766881c597e33d"
    $a3="3778689d047eb9e58cfd5240ab3dd8fd84e1cdcdf0dc53ccecf97770"
    $a4="664d8f3cb0b98e5ed4204a2490993720a40dd297c859bbabb05ed987"
    $a5="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a6="3cc27ba47fd4d99add33ea2fc6b94b1ddcd92598df48568e70c35ee4"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="09e8afd1a285e7f260f65e8de0e97fc01637360157b411cca9516f73"
    $a9="3778689d047eb9e58cfd5240ab3dd8fd84e1cdcdf0dc53ccecf97770"
    $a10="e7bedacebad77e3bc61d1e27db602019c6e0fc954d6c856bd2719968"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f6b07b6c1340e947b861def5f8b092d8ee710826dc56bd175bdc8f3a16b0b8acf853c64786a710dedf9d1524d61e32504e27d60de159af110bc3941490731578"
    $a1="19c18441d69484b5a944345313844e87ce6462489a096479eac9c6aa4eebce171063e41749a6bf6c303e4fceeb232cf944fd3e606429682e05b74a0c18a6b889"
    $a2="8c10144fb8485e7056365df293ac9bbb2ac01bed7c7656e2e0315b7beaa878f1c394beedcd9baea3f5bc0544e7a4c3bd60bcd2d418f2ae1a12cccc5d1fe976c5"
    $a3="19c18441d69484b5a944345313844e87ce6462489a096479eac9c6aa4eebce171063e41749a6bf6c303e4fceeb232cf944fd3e606429682e05b74a0c18a6b889"
    $a4="46534abbc7b4d4f4a348f43324f861e8e583e9f4c5a4bef73ac7eb9c476df48ef65a8a16fec5031e9eb8f8f5b4e6a8f0ae30f31eec1c6669d5be0d04888605ce"
    $a5="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a6="056a04f5dff1be846d7edeb527d1debd104663e0fddbe1f1d28abda6f4d0869c75284126492617980be9f7aec391937e416833fb8c1e1e7b8a56f2015cd1bd3c"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="c03acaa86255c2ed52831dac7d04546ed150c370f873d624252b81b80ade3b3a85552100cab4771c938217cdb4715655cacfd25628394f54f059fd4669b61196"
    $a9="19c18441d69484b5a944345313844e87ce6462489a096479eac9c6aa4eebce171063e41749a6bf6c303e4fceeb232cf944fd3e606429682e05b74a0c18a6b889"
    $a10="f6b07b6c1340e947b861def5f8b092d8ee710826dc56bd175bdc8f3a16b0b8acf853c64786a710dedf9d1524d61e32504e27d60de159af110bc3941490731578"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"
    $a1="c2b7d0550420583e8d954747bc3fdedfbf9434a621934aef5f577e5eec2ed2a3"
    $a2="84da65567426a771c18b2e2294ffa4485eb209e392174bf6737af060414eb7ea"
    $a3="c2b7d0550420583e8d954747bc3fdedfbf9434a621934aef5f577e5eec2ed2a3"
    $a4="3b2bcbe6081b7deaccbe0b42f2269a0910e8f2c47ee4e61ccfaa13b3a0de0f9c"
    $a5="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a6="8d3c7a78b824e5a1d6b902d0b63c418c358a4194501882810f4e003a775914d6"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="f0c8303d46ebe569e445b6f65ce43e7f8ba14efef67b36bd2cd6fe97c85e08c2"
    $a9="c2b7d0550420583e8d954747bc3fdedfbf9434a621934aef5f577e5eec2ed2a3"
    $a10="b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98186e8212d82bfdcf950da3075d0bf7caaf55e9f52155beb6c9230559d2970a90f11ba4c4b486a2cafbb51f3c8fbe9bd4b386eb13ad03dcc974c22a30bdfd05"
    $a1="6262dce6abf2bb4ec25766c1c025db1d4b714cca01413c3e494d52393baf14de0c0cb19ac191e288e588e4fad9b34383c8caeee8311d085734fb3c230d33304a"
    $a2="e0c680e19cc0d6a3661209a56431c23d0144f1add2d9f815e6065ac1b54ff56822fe2af3b649f1fdcb631977466497abac925deb21b09aca0bdd321f68bd6d41"
    $a3="6262dce6abf2bb4ec25766c1c025db1d4b714cca01413c3e494d52393baf14de0c0cb19ac191e288e588e4fad9b34383c8caeee8311d085734fb3c230d33304a"
    $a4="f1020c2452a3847b7c9a82a054800c7a26e6d79ef9c380d9b3d5f0b2f47aac3a0d2bd7c2ed4d19677de9c25bdf25329078420cf12ae3f1656d76c7c4cf9f5a2c"
    $a5="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a6="87498478322b2dd634b587e2b88688fbbfaa412d26177d0708cd1190101320abc21025baa14aaee3640bc073cca1b83bb0a4bf0c9d6409c31e85a5feb7cc9662"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a8="a20657473838a54d50b5b6ffd6610d84dd8389b988723ffdd516e6f5472cbb4705b90abb5be970bc061f2bb89048de00b1978681967de86a1c7c612c7762362d"
    $a9="6262dce6abf2bb4ec25766c1c025db1d4b714cca01413c3e494d52393baf14de0c0cb19ac191e288e588e4fad9b34383c8caeee8311d085734fb3c230d33304a"
    $a10="98186e8212d82bfdcf950da3075d0bf7caaf55e9f52155beb6c9230559d2970a90f11ba4c4b486a2cafbb51f3c8fbe9bd4b386eb13ad03dcc974c22a30bdfd05"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d9d8b9a458754c6f38ef1659a4b869ffd939dd25474b0c1677b36ace49dd37a"
    $a1="1a0171ec046b5d5f7997e50a84ea78da4f1ce97ba57ec4c0e9983e21ac00941a"
    $a2="0894548f2f7123ad7209d8bcbb1fc4b3bd06b394ad0f1f8285baf4b978d63f30"
    $a3="1a0171ec046b5d5f7997e50a84ea78da4f1ce97ba57ec4c0e9983e21ac00941a"
    $a4="bda6e6fceb2a94ff97a0720b0202b3f1d31a7e241ec767afc18464da14c7edce"
    $a5="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a6="5e328fa3b17ebb32cf0382d3012b005263eb26333ea6fe9c7cbf83e3558df98e"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="3f6be9d5ff390796fdf62e19e43cc62cc8d00458d3887098b40f413f56b87fbf"
    $a9="1a0171ec046b5d5f7997e50a84ea78da4f1ce97ba57ec4c0e9983e21ac00941a"
    $a10="1d9d8b9a458754c6f38ef1659a4b869ffd939dd25474b0c1677b36ace49dd37a"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6908462fb4e2ce1d26de530bf014805f3f08d109f390066c635e4d0"
    $a1="d27dec486e62fc697846ad373340f254a852a270db58a0e60e812a2d"
    $a2="89e5ca9d7cb2b3597642cd2be279676935d45af50c26dac5340930e3"
    $a3="d27dec486e62fc697846ad373340f254a852a270db58a0e60e812a2d"
    $a4="3195faf8dac1265a29b31a6ca528f343b8209cf36b065e031b75b652"
    $a5="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a6="ba6134b813bf09cf0479742c3113f52fee1e6824feb200122c6aae95"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="cf963f34f33cf23074fa3a37d94c2455cf7b0d49be88d26d93280539"
    $a9="d27dec486e62fc697846ad373340f254a852a270db58a0e60e812a2d"
    $a10="a6908462fb4e2ce1d26de530bf014805f3f08d109f390066c635e4d0"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe2c6648c75468d6f4cc5fa16ce33e43f7aefe8754f92a09eee2362b71851b85"
    $a1="c62ac717afa32b3362505f0cc2a1391838ecbb84a67b6b62be8bdca46195decc"
    $a2="01d84a0e148f75e15230702ed415ffbbf9f0e05dd65c708683e4e9ed3c6fbe59"
    $a3="c62ac717afa32b3362505f0cc2a1391838ecbb84a67b6b62be8bdca46195decc"
    $a4="fc1cccc1b9f433a6095e1b515300161ced511ee8880692f9fece2f7b9db81de4"
    $a5="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a6="a65290535b8f2e82433a5b23f67b8087b135b38473a4a541ad5bf36bf0dd1804"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="2ed55ef7eead2dd7377ded21e7a3928ac7be2995b3e804ec86e2fd4c84bfc7f6"
    $a9="c62ac717afa32b3362505f0cc2a1391838ecbb84a67b6b62be8bdca46195decc"
    $a10="fe2c6648c75468d6f4cc5fa16ce33e43f7aefe8754f92a09eee2362b71851b85"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a02addf854b2f81b447883ab29038c6458fcd0e6a191360584ee8708f55c4598932177e6427004dd0272cfacce17094"
    $a1="02ecd93594f2a0925be878e2c015a211e659ffd2ab94542c2dfab1176e332b2ccd53ca1a945a4abc8edb03a0b4a5b897"
    $a2="d1506f7938bae235ae44b42b10718f3039e9f2f0a2e11df31455fa85ded512c792c5ad66bbf7cc40512f35c336199954"
    $a3="02ecd93594f2a0925be878e2c015a211e659ffd2ab94542c2dfab1176e332b2ccd53ca1a945a4abc8edb03a0b4a5b897"
    $a4="e9c39d4b15f14239a96991d9628368bfb7fab6ba2a9506574ce22070fc12ab814952fd239e7abf522777460acdc1a8ef"
    $a5="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a6="14e14ff32e7fa536d894bc4926bbcabca700d98b0c743c1ff845dc5e1cd700698b6d559a5895145628bb7bcb95eacf56"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="d5d3a83a2710dfda618f51e0ea1b486218c37ba994054a2297d5b1e31f1d271a42a4238e2dc54c2b20c087ee32599067"
    $a9="02ecd93594f2a0925be878e2c015a211e659ffd2ab94542c2dfab1176e332b2ccd53ca1a945a4abc8edb03a0b4a5b897"
    $a10="5a02addf854b2f81b447883ab29038c6458fcd0e6a191360584ee8708f55c4598932177e6427004dd0272cfacce17094"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0fe220a126aeb06ab687b5cf73175abbd6194f57b593059f33186d72066a283af765cbbea04cae0bce0ce793116a4ac99424c28ea7fded4e88a18cfc51513cd4"
    $a1="4f6b6d857af55d36973103520182a3f1aac2361408cb404e6b283b66b626a674671d47c352fb90206a188304843da991d7df8d2c98a9743d5aebcb307f8a5e88"
    $a2="8b60ce07a45624f930298d133aacb304924320cd4829c352a1dc38514299d633e37ecc5ecb90987d01273ac9709e4fe9bd496577dd2337f37526f1c5ad872591"
    $a3="4f6b6d857af55d36973103520182a3f1aac2361408cb404e6b283b66b626a674671d47c352fb90206a188304843da991d7df8d2c98a9743d5aebcb307f8a5e88"
    $a4="ce997a8d374571ab2f8c2ac59af15841a1518dbbecb473dd04a73c3a2ba3631aa5274026b136362e694ee211ea27dec883cd2610638127cb7ca5f77e2fab2c29"
    $a5="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a6="a1c449c96bd5a44824f19a7131ee2545b218541a49f10a5708addab3f6adbe66569a7741f310da4161997edfb1c7314bd2f2b81f5eff0ebd8c57faade572943d"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="a04c522832688f86f66bb9811bc69084dc7c918044c72bbdf6b87953d0cddc2952948b46c6aadce9ef8bcb62f250a837e7a7825f3468fc9415f22896dd42d6d0"
    $a9="4f6b6d857af55d36973103520182a3f1aac2361408cb404e6b283b66b626a674671d47c352fb90206a188304843da991d7df8d2c98a9743d5aebcb307f8a5e88"
    $a10="0fe220a126aeb06ab687b5cf73175abbd6194f57b593059f33186d72066a283af765cbbea04cae0bce0ce793116a4ac99424c28ea7fded4e88a18cfc51513cd4"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="UG9seWNvbQ=="
    $a1="NDU2"
    $a2="UG9seWNvbQ=="
    $a3="U3BJcA=="
    $a4="YWRtaW5pc3RyYXRvcg=="
    $a5="KiAqICM="
    $a6="YWRtaW4="
    $a7="YWRtaW4J"
    $a8="UG9seWNvbQ=="
    $a9="NDU2CQ=="
    $a10="YWRtaW4="
    $a11="NDU2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

