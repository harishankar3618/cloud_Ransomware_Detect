/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_huawei
{
    meta:
        id = "f5dN3hkRDXwGvRzzbsHtB"
        fingerprint = "ab3be9e451258f2a787acbdf95e10e06a985ff3f7852ed381f552a2fb0bd0c54"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="30994df9e2969f59cf3ea1ab3284fa6a"
    $a2="79c6899ea65d358ede499b529712a650"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="0d729832a1e9143086308e70cbc8037d"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="209c6174da490caeb422f3fa5a7ae634"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="4b0b41a2380a3a8d77e548a0256eae35"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="2f86c1a2ce778c4f5c97938e392e043f"
    $a11="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="0d4eee4271ec016d"
    $a3="43e9a4ab75570f5b"
    $a4="2b9b085368cb6279"
    $a5="43e9a4ab75570f5b"
    $a6="43e9a4ab75570f5b"
    $a7="43e9a4ab75570f5b"
    $a8="2b7cbeff40c935d0"
    $a9="43e9a4ab75570f5b"
    $a10="6ba6d4922026041c"
    $a11="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*EA487CFEF2588AF7F128B663FC8ED55BB0843949"
    $a2="*1BECA913B056B4E447CBE80FB2865A528AC0D08B"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*842A5FFFFC99A29068344CA80E52DA3B96DC2191"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*A77C2051D40C29B6480019478BB218E8E2FCB67B"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a10="*A7DC6E2DF3C1866E2DF6AB7392537CDC7086A1A5"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}NSEj9wfXb5bHYdEy8dxE8A=="
    $a2="{MD5}ngKrB1Gy0xAGK8JQFr3Bzw=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}f0R81lYOvZxd8o50XdNtsg=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}ZjUFon96hivgzq6wWD/otw=="
    $a9="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a10="{MD5}5lbUgT5aSnz3zGPPk+gE6Q=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}P5OOjMqr8ZWyRTjK/KtOdrzjvYk="
    $a2="{SHA}ScW5ZMDQlSfzSeE+q7tWJU7My1I="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}M7Nb3svEdzCrEgDRyEOfaed+mBM="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}3f3JV7MUXAFMe4VhxREYKiX/vSQ="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}44/hgmuUFp3e5wbIDikFZufjEPA="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="352123f707d76f96c761d132f1dc44f0"
    $a2="9e02ab0751b2d310062bc25016bdc1cf"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="7f447cd6560ebd9c5df28e745dd36db2"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="663505a27f7a862be0ceaeb0583fe8b7"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="e656d4813e5a4a7cf7cc63cf93e804e9"
    $a11="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="3f938e8ccaabf195b24538cafcab4e76bce3bd89"
    $a2="49c5b964c0d09527f349e13eabbb56254ecccb52"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="33b35bdecbc47730ab1200d1c8439f69e77e9813"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="ddfdc957b3145c014c7b8561c511182a25ffbd24"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="e38fe1826b94169ddee706c80e290566e7e310f0"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="93aef574a161426c27724d03ff6a81afb85d967540d0493fd2ce41fc7f48b708de86d2204e54954f9c35431e7271de21"
    $a2="eddadc3902d5fd1c3dafc411879a44e87fa920f2c7753bb0b6692ca2d8d9239830718cb45bb889284ee2081c41e49b62"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="c8e0793398104c1fb2085e0ff91704693d88000304c63e07863170bb4626385db74ac108cd26fa52800a1cba01dcaafb"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="0b9fba247e98ae155e2955ca964b0fc1a2df802b23606badc622835ec0433c0768b774017e00a325d00330675ed6dd2c"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a10="bc9d9ea38cd9de83726c9a08229c53679eee947750794cd2070fd560ec80761f085d969d413e5367fc904b5cd63d0bf2"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="feaf85e98cf8f66e500a3c6f07674241c117f308385713e9d4153a6d"
    $a2="1b969ab290ab0293f0f94eb17fdad45a073e75543007d95b4f8af043"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="61b65c0a8ba7b527e1fce22eac3d9695e2a6f0b4ae85135b24624b0f"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="3a4ec58aebdaa474539712ad4f323d840e893b9828a980ad665f4204"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="0e1126457e8746930c11e4ac24e483b04028e407417d315b6eea1c8e"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="b938b0634d6ff85ef174049ee46c77249c7f73b639b81a5ade062ab8d12e7e6438705d986cb8c80aa3f9935e1cdf2b895f79818c58e8bb64549a50e06e8b271c"
    $a2="1812bf8840e9fbbae06bef58c510f4bff23534655e3fd60e9a62119648027938045fa320d452f46bde45225441670fc3c2bf248baf9f80d253af8833cd6136dd"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="6092d8873082c0cbb4dbe8ba42e596b8c4f11afdbef413947b6cc387c4caed1a5e0e054a4e8e27a656bf6ef7b2d17bd314c03eb4e7686518e5046f05577798ce"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="4a0bb8ffefa17bca8acc4d131a358bfbe26e74a737ba0448b85c015855990cfdc2f1a09283d2d721b03b5d087c6b25a925733178ab986f0751b41110df8027b8"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a10="7857ccdd456ef829f337a81127a7f42fe3fa7dbe2ee5aad419e66d7f54f029db3569eab3b3e98c07e99f1bcc78a051234970febaf9e33fe8af406fe76adcd23d"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="6956f4af11a5ea9c50966eea41ba294ae307cdd018d4c447cbe1f482d52511af"
    $a2="f704116abc3db6bf73f0872cab3a0e9e18f0b35f1d4b84a3b3fe37052f0c01ee"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="a1dee62f6a7fb82d24528371ea3d8479a351288320e1464220a2e563de3e94be"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="f0bd270e93971cd1c35c97d2316df5bc538db42eb9d9ea9310963f949c1510a3"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="42971fa38528f78c9c389e095c0faf38b1a2d3d7a3c3f6ba27d06c11f94e0b5f"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="90df9ae70c38c54cdf686b7ae247e2fc22729473673c1fca54785a897d5cb0c70b70d06afcc40c0ddae5824bb91ef78cc44a33f2515b7b48629be3976f3ee320"
    $a2="6303fd543d062b7691d9ce11959ebca6ef2f401c6929e0d6e0525ec7c3bcf1f9c73ecaaf9793c6a520ac2d7438217fc428395afce8e13fc93710cda2d22fab4a"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="896cb089fb0516c2c300b755ec16e53994e7c27d4ab1cbb051362cc43b88f0fca62a7ef8052f32d4af8c713844426a5fceec9434bf5d611503e7ef4a6f99f934"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a8="464006f8826289f72faec5943252b661f702261a65fc5af835190221780a967f220fdeb0672b4fff07828863866577ae785595617e4e72770a869d4536981264"
    $a9="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a10="54ff4cbdf63661b2f0cc15d2375be44c6bc2e7b409514aaf916d7b802819010c120fd367874b077680194c6160c5044d1999449475017d12d60937968ca93446"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="53f9d8883449375bfbc22803c9a3303337204ce5b7990d3a9d4b9b289fecc665"
    $a2="4adb2daa95ec923f74fa0f1a0675e1603a4de2896f5d2ce947b2ac97e26c31ab"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="4a63c075656d834a6e9597c0243d75e5cf14a2b38bd35790ff9bf55079b16508"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="4cabf48405f5b818344b40eda830a8b3423458d6b63d2edf86699731348cffa9"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a10="af987008f22acc1accc5b5a4faf592a10130eaa857dc14df430d7e8f364f1bab"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="e8b4719f911a47cd8d94e29e98e3e982a88e645e28517896e063b563"
    $a2="0c8d6b6730a3251b39edd49edb49265cf3b29ecfaa99a32aa022a492"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="a5446a1a57b93d4621a413167c53e057d5784c2d4d1473311833db0c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="f12ab392f34399e0f44cd45e07adf1aa726eb67aa8284e14dfcfd130"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="b54f1da960a2a897a4b3f0d780be55994512d4c4451d71ee4175df3c"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="affb825dd1a04fc5b4ad54b460ea44c89a5eb6486abbb116ba90f2f2452c75ff"
    $a2="428ffc84a399c56f3972e2f774c48cdc7d24a9a4a0844c4b58d4abf80608b8a4"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="9729a6935dd0de85c082b59faccfaa9221e66f6d51ded5a34fbe4c7c763592d5"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="401a3e555492b13e213df69707e37f84694c91fae8fe09c263549954bec0d519"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a10="a9cbf09d0d04321ccaea7a07728435e38d9c7d4134cce945ecdba74cc5d5138e"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="7b6d72fb010c3e99c1dc32115deb6c79b97b40b1789a5132e120f3a071a4e650f421f76aa94f279f377d8711af6f6996"
    $a2="5a6cbf0814fedc757f00b948d8960eb18d7c701723942a7197f864efe447be84b1c65cf0af70d40b8d1acf6c4bfee781"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="32123b7c281aa342835b48291b995f39131ac6223c056443c26e8747eff562395c648ec7960cca3f3850274ab06f6c22"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="a90b2b44915d8ffcab82e21ecc4a7bc911c3693815803bafae2941c9705400968ed2c432ddae854a5a205ea49890041d"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a10="53b7f6cf057d3100b523614d0b66b3bdf10edbd7636d4ab5dcd9ed52742d07d1956bb21f2ea805fd4250cc59d69bcade"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="8b6d1aa2a62446c7b9e24b6caee8e1df84282b79a4ea2330fe6778e4a534dfb26a23aa77aa558f880728428e7e451c54acb6e1667e070ff59cee5f5807f3eb10"
    $a2="01453a3d181c85cf81f5c5b79303234fbd8541902e3225cd4b010d3fcc979f71ec3aec7f234841e67ccdfc8b2538be563243baca5091509049d5398c76ca9872"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="29b9423956a3316c847c2cebaf27feb60b2ec7c3f2e967343775d4852abfd2141795b5d529a97addddda541dbd4f1aab45ec3eee1c3cfa2f48ab07cd90418f12"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="512c45c5271405fa75225a2b8d2b2b2fd20863d9a0d9f4e42c0c53f0952fa1b7edfd05fe7683fbbbe5a734ef3cf693484f3874238194de58ed31e3962c0c04f6"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="7891e4bb64d7b0c9cea1a051300fdb921acae2bf2f1bf18b4f8fd3f94c0fdb5fae3728cf6e49f0fcc9ff9abc24641835780f63b7eae7a7c2eb7aa71533f295f5"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="IGFkbWlu"
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="QWRtaW5AaHVhd2Vp"
    $a4="YWRtaW4="
    $a5="YWRtaW5AaHVhd2VpLmNvbQ=="
    $a6="YWRtaW4="
    $a7="YWRtaW4="
    $a8="YWRtaW4="
    $a9="QEh1YXdlaUhndw=="
    $a10="YWRtaW4="
    $a11="c3VwZXJvbmxpbmU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

