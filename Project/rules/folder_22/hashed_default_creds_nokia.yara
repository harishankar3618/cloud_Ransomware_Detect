/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_nokia
{
    meta:
        id = "6let6Rxplm5DbpjXwAgqec"
        fingerprint = "0221e855cc08215991099d0e18670ab72eb61a72052e6ab3c8fed5e67847be5b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="102019b0a021e7bf80a02f07167b8a74"
    $a1="102019b0a021e7bf80a02f07167b8a74"
    $a2="1c72ec33dcd8413a552d6563d7bb6452"
    $a3="1c72ec33dcd8413a552d6563d7bb6452"
    $a4="09e55a127f3d4e4957c77de30000502a"
    $a5="09e55a127f3d4e4957c77de30000502a"
    $a6="7a21990fcd3d759941e45c490f143d5f"
    $a7="42b1e57dca4ca18b8b08ec58344b38e3"
    $a8="2d033d5762adff596255b36b4be98227"
    $a9="42b1e57dca4ca18b8b08ec58344b38e3"
    $a10="dfa00d30923c6a547d53c92da85850c5"
    $a11="329153f560eb329c0e1deea55e88a1e9"
    $a12="43a4477335c84ba91f310bde197cdbbe"
    $a13="329153f560eb329c0e1deea55e88a1e9"
    $a14="7a21990fcd3d759941e45c490f143d5f"
    $a15="34686ea587a2c288b00bc7a2c3c67c3e"
    $a16="1cf0700926b37a30c826c8edf64339d9"
    $a17="1cf0700926b37a30c826c8edf64339d9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql323_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73b2e35d17b2d4b3"
    $a1="73b2e35d17b2d4b3"
    $a2="2a551c033eebc604"
    $a3="2a551c033eebc604"
    $a4="51d64c393625fc9a"
    $a5="51d64c393625fc9a"
    $a6="2e782c85379a326e"
    $a7="7a296cc326fc2b04"
    $a8="565497b904012c27"
    $a9="7a296cc326fc2b04"
    $a10="10a781a847b74e82"
    $a11="67457e226a1a15bd"
    $a12="19b522a4743bf12c"
    $a13="67457e226a1a15bd"
    $a14="2e782c85379a326e"
    $a15="21641f392e3dcadd"
    $a16="3d7d6f637a0e2b84"
    $a17="3d7d6f637a0e2b84"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule mysql41_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*DDAE4474D45824760B618F2FB8EBA1B7F74AD813"
    $a1="*DDAE4474D45824760B618F2FB8EBA1B7F74AD813"
    $a2="*F7F3E8FE07A91C0D4A82490530C8F6F95EE5C9E9"
    $a3="*F7F3E8FE07A91C0D4A82490530C8F6F95EE5C9E9"
    $a4="*459DEC76B4BAF7C0DCE265EDCA7EB68442C45E78"
    $a5="*459DEC76B4BAF7C0DCE265EDCA7EB68442C45E78"
    $a6="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a7="*925845C9C64B72F38E419FFBF18D7B226A7B8F4B"
    $a8="*F2F313DF7509271404F34B83B519FDF0863AEC8D"
    $a9="*925845C9C64B72F38E419FFBF18D7B226A7B8F4B"
    $a10="*BFDF7BC8F1D4DC3C02079CCE6D0E507554319409"
    $a11="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a12="*FAAA67924961263057D0546413F1F88CE1793236"
    $a13="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a14="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a15="*D3A47E0C03C5F3CAD8F8F0BBF571FFE274C8CC66"
    $a16="*4B90CAD22308225EAF6A07A7ED75928D5C1B2C6B"
    $a17="*4B90CAD22308225EAF6A07A7ED75928D5C1B2C6B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_md5_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}3SaL2CbZlHyh/rXphRqWPQ=="
    $a1="{MD5}3SaL2CbZlHyh/rXphRqWPQ=="
    $a2="{MD5}Kec5a2t+i4qyDaq83hx3Mg=="
    $a3="{MD5}Kec5a2t+i4qyDaq83hx3Mg=="
    $a4="{MD5}YmCOCK3Cmo1tvJdU5lnxJQ=="
    $a5="{MD5}YmCOCK3Cmo1tvJdU5lnxJQ=="
    $a6="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a7="{MD5}pXHZachmH7A0Kv0I5XHfoA=="
    $a8="{MD5}Jo4nBWo+Us83VdGTy+sFlA=="
    $a9="{MD5}pXHZachmH7A0Kv0I5XHfoA=="
    $a10="{MD5}DCOovymhkfGK7oFHN+Km7A=="
    $a11="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a12="{MD5}lsqdL5S4ceaTO1GADiTpFw=="
    $a13="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a14="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a15="{MD5}ExY3kJbIXkiuPIQm4VNu1A=="
    $a16="{MD5}6puzqpUHI/rOc0I4AmJQdA=="
    $a17="{MD5}6puzqpUHI/rOc0I4AmJQdA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule ldap_sha1_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}23CiD0A9rUOsvNwCkIYgedcwD34="
    $a1="{SHA}23CiD0A9rUOsvNwCkIYgedcwD34="
    $a2="{SHA}u/DgDc5CQElDP1rsHZMBPbNpgwM="
    $a3="{SHA}u/DgDc5CQElDP1rsHZMBPbNpgwM="
    $a4="{SHA}0qBNcTAaiRUhfdX6+B0Sz/1s2Vg="
    $a5="{SHA}0qBNcTAaiRUhfdX6+B0Sz/1s2Vg="
    $a6="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a7="{SHA}4ycjY/flnd7jxr4oEfYdTo+z8AI="
    $a8="{SHA}AeuE8FK6hX1hCiaBVijVM5OGyOk="
    $a9="{SHA}4ycjY/flnd7jxr4oEfYdTo+z8AI="
    $a10="{SHA}1h24NjXl9yBDPveKMPPLJp3wwNo="
    $a11="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a12="{SHA}wfRsgFIA2ACgwBhbMzNLJj00x+0="
    $a13="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a14="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a15="{SHA}/Tz8AoNIWLaEehi81ujowUX61Ic="
    $a16="{SHA}+bqYoGlK3gdAAX7yb3nvsQJgnHw="
    $a17="{SHA}+bqYoGlK3gdAAX7yb3nvsQJgnHw="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule md5_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd268bd826d9947ca1feb5e9851a963d"
    $a1="dd268bd826d9947ca1feb5e9851a963d"
    $a2="29e7396b6b7e8b8ab20daabcde1c7732"
    $a3="29e7396b6b7e8b8ab20daabcde1c7732"
    $a4="62608e08adc29a8d6dbc9754e659f125"
    $a5="62608e08adc29a8d6dbc9754e659f125"
    $a6="827ccb0eea8a706c4c34a16891f84e7b"
    $a7="a571d969c8661fb0342afd08e571dfa0"
    $a8="268e27056a3e52cf3755d193cbeb0594"
    $a9="a571d969c8661fb0342afd08e571dfa0"
    $a10="0c23a8bf29a191f18aee814737e2a6ec"
    $a11="63a9f0ea7bb98050796b649e85481845"
    $a12="96ca9d2f94b871e6933b51800e24e917"
    $a13="63a9f0ea7bb98050796b649e85481845"
    $a14="827ccb0eea8a706c4c34a16891f84e7b"
    $a15="1316379096c85e48ae3c8426e1536ed4"
    $a16="ea9bb3aa950723face73423802625074"
    $a17="ea9bb3aa950723face73423802625074"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha1_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db70a20f403dad43acbcdc0290862079d7300f7e"
    $a1="db70a20f403dad43acbcdc0290862079d7300f7e"
    $a2="bbf0e00dce424049433f5aec1d93013db3698303"
    $a3="bbf0e00dce424049433f5aec1d93013db3698303"
    $a4="d2a04d71301a8915217dd5faf81d12cffd6cd958"
    $a5="d2a04d71301a8915217dd5faf81d12cffd6cd958"
    $a6="8cb2237d0679ca88db6464eac60da96345513964"
    $a7="e3272363f7e59ddee3c6be2811f61d4e8fb3f002"
    $a8="01eb84f052ba857d610a26815628d5339386c8e9"
    $a9="e3272363f7e59ddee3c6be2811f61d4e8fb3f002"
    $a10="d61db83635e5f720433ef78a30f3cb269df0c0da"
    $a11="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a12="c1f46c805200d800a0c0185b33334b263d34c7ed"
    $a13="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a14="8cb2237d0679ca88db6464eac60da96345513964"
    $a15="fd3cfc02834858b6847a18bcd6e8e8c145fad487"
    $a16="f9ba98a0694ade0740017ef26f79efb102609c7c"
    $a17="f9ba98a0694ade0740017ef26f79efb102609c7c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha384_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fde45e7a0492240962f1c83ac2e27af3023758079177620e47d83669c955aa4a1b535b7128f810b46eb7fc2cead3e6c6"
    $a1="fde45e7a0492240962f1c83ac2e27af3023758079177620e47d83669c955aa4a1b535b7128f810b46eb7fc2cead3e6c6"
    $a2="defd7b8c342efc74c397228ba9c2090c7565453d472cad2434cd4ac29e16d28655015c65f1e224e378e5887f71a8ddbb"
    $a3="defd7b8c342efc74c397228ba9c2090c7565453d472cad2434cd4ac29e16d28655015c65f1e224e378e5887f71a8ddbb"
    $a4="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
    $a5="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
    $a6="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a7="ff05f65a7ba581f9cc95d243128fa47f3fa3c34c8d4efe6761c62a8a4f083e90081722a2fab656b335887a24535b1550"
    $a8="2bc130303bb7c1ed0c32351d922e0759add2cb648f7e25ea0b1fb3aa48403117f7f5e1d8faa5c7fd1aae93b56038b647"
    $a9="ff05f65a7ba581f9cc95d243128fa47f3fa3c34c8d4efe6761c62a8a4f083e90081722a2fab656b335887a24535b1550"
    $a10="82cd45637b6e37ef02482a4d769c1bc1caabc0201a9236f739c285053549ca80d0ef2d554abf072558330627d36b44b4"
    $a11="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a12="e1df526616174e93218657e00cf11841173920b8bb984ab531b2a0c5ec111e342e1bce34a95a905b80c93916f9fc0da2"
    $a13="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a14="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a15="873574cfb5ba53f2cad1e4673f59b6764d52bf83a2b3a4f81a7aabbc5c3a2671640731ae078d1aad2c3838b055b23ab5"
    $a16="118cafcc919f7e0212f0ce0bd057a0f5452f501ae2f8c5663c60164286dcad1c87723293e4314f644d9ee53a7d437119"
    $a17="118cafcc919f7e0212f0ce0bd057a0f5452f501ae2f8c5663c60164286dcad1c87723293e4314f644d9ee53a7d437119"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha224_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="704878b930e6c0a1bf9c2534c9271d6d09c85956f5532aa21b23ac30"
    $a1="704878b930e6c0a1bf9c2534c9271d6d09c85956f5532aa21b23ac30"
    $a2="c573581f23014a220ce810c6eed001ce74cf7b82c76f37a7a6bbb855"
    $a3="c573581f23014a220ce810c6eed001ce74cf7b82c76f37a7a6bbb855"
    $a4="192a06d20b1a067cc25d4916200752c0903521fdd342bef03961284a"
    $a5="192a06d20b1a067cc25d4916200752c0903521fdd342bef03961284a"
    $a6="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a7="a976fa8a05671043deadbfc0d50a15e9adf48d47361991e7b0452a0b"
    $a8="bc4c7b249289acdc09f7cd84537311182f71a4c4b8a391a870d55929"
    $a9="a976fa8a05671043deadbfc0d50a15e9adf48d47361991e7b0452a0b"
    $a10="557f89c384f7385be18c3d14c893f72029f8abab7ccd0663f4b49474"
    $a11="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a12="0af5f61619a226b4a59dbab983fb0027d12dbe9fb438e89835539982"
    $a13="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a14="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a15="9b32cc942b73c884c90a739a20aa5c379c6fa6a7832ea521d5ffeaa7"
    $a16="b573f6c18a1ec9e54b18f686bc8e143978cf67f317facf0296d9620d"
    $a17="b573f6c18a1ec9e54b18f686bc8e143978cf67f317facf0296d9620d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha512_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd7760f88605a4e3ec091c627d8210c8eb78756585aaf10125b55f8f5ed0b8707a32388777919145d0094859c62617f34285c8f6ceb858b32521ab49c77e42ce"
    $a1="fd7760f88605a4e3ec091c627d8210c8eb78756585aaf10125b55f8f5ed0b8707a32388777919145d0094859c62617f34285c8f6ceb858b32521ab49c77e42ce"
    $a2="b7ab73d40be6cec19c6d4e3fdd5a61be97fda1d9322578462bf0cd7c921877f9178f3c8df0d0491763ff2b78baf3ca7ce2b48b29e895632332ab54b4ae71223d"
    $a3="b7ab73d40be6cec19c6d4e3fdd5a61be97fda1d9322578462bf0cd7c921877f9178f3c8df0d0491763ff2b78baf3ca7ce2b48b29e895632332ab54b4ae71223d"
    $a4="85d7741af27f18cbefc7fdc96d4465f63d4e8da2126a196f87c4f7e1f65298855a0e4a4a8986936eae95e2b899e837c48ae39d8048f907ebd0095c87c49fb0af"
    $a5="85d7741af27f18cbefc7fdc96d4465f63d4e8da2126a196f87c4f7e1f65298855a0e4a4a8986936eae95e2b899e837c48ae39d8048f907ebd0095c87c49fb0af"
    $a6="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a7="acced7d843aa1133b618794a27ade5254e53a6b682cad5edb249494d5f0d76b9262b179dc125af2cf5ddd6bd570cd5513146139d61f46ee7fa3efa1b06a82a92"
    $a8="2637e59347980f0bae0e2817fe650c05be6faf161f957a32feec1d6b2d460a678d0a12c603e459abb43a36ddbe47b38f34841959c426c3d835e18b1b2d2939fb"
    $a9="acced7d843aa1133b618794a27ade5254e53a6b682cad5edb249494d5f0d76b9262b179dc125af2cf5ddd6bd570cd5513146139d61f46ee7fa3efa1b06a82a92"
    $a10="3f83728a555227c63232e874177bfe70616e8879472b016bebcdd776f6c2ecfd5621db4717faea02c1e5875ba90c2b2160b93efea4918df05ac1992631359bee"
    $a11="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a12="4b96c64ca2ddac7d50fd33bc75028c9462dfbea446f51e192b39011d984bc8809218e3907d48ffc2ddd2cce2a90a877a0e446f028926a828a5d47d72510eebc0"
    $a13="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a14="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a15="7f412151c47f07236c426eaa9a5e9510f006b421f7330527f4a42845b7a3f4927c742e812cbfec9f6e62a5dca586a0aeacb553190f53ff7ceb39245eb001dbb2"
    $a16="8ef2e7406d35e5d72f34a9fe3e33fdd37cf3c49747f3b6bf9fb179c1234b5bc73a1095e47f718115bdb044469670a64066c5b65fc043f408098d1d3492d39d54"
    $a17="8ef2e7406d35e5d72f34a9fe3e33fdd37cf3c49747f3b6bf9fb179c1234b5bc73a1095e47f718115bdb044469670a64066c5b65fc043f408098d1d3492d39d54"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha256_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29a0ae2eec6a90eb8100d0bcbf063c7081e60277dfba2a9db821074776bc44bb"
    $a1="29a0ae2eec6a90eb8100d0bcbf063c7081e60277dfba2a9db821074776bc44bb"
    $a2="c06f6073897e5e857e12be420e89d62163e5b0e73317d0a6c34dd34dec57c1d7"
    $a3="c06f6073897e5e857e12be420e89d62163e5b0e73317d0a6c34dd34dec57c1d7"
    $a4="948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d"
    $a5="948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d"
    $a6="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a7="2b8fbda969a8aaa908e763c57e6b22a1697b7c0c5f95fc35b95d492fcc54d082"
    $a8="12d27e106af46b4b9ca8772d97f1855329a420d873ca738b7b11c68d285ca71d"
    $a9="2b8fbda969a8aaa908e763c57e6b22a1697b7c0c5f95fc35b95d492fcc54d082"
    $a10="2ab6d53e717a0e0d773ccfdb8b0e84ac494729c6b567c72d256b883a9db17ea8"
    $a11="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a12="746ff992cd97391b15891f93dd1ce02908c33947c60f1a95fc134d40874e5ac0"
    $a13="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a14="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a15="73170a99e6da9a0d8b381209436bacd8cfef30ade921a2ca1276880611000138"
    $a16="d7c1f771f6f06139d6f4ada46a6c6f50b0e3fcfb6b4b2bce3721aa07c11a4096"
    $a17="d7c1f771f6f06139d6f4ada46a6c6f50b0e3fcfb6b4b2bce3721aa07c11a4096"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2b_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5781eab2a830933f68c9925214cd498e51ec9ab5f292f831aacb9bcc1e75e22a8d709f812529b075baa7bd1559bc4cb38785e6367b092f169c596209fee88dcb"
    $a1="5781eab2a830933f68c9925214cd498e51ec9ab5f292f831aacb9bcc1e75e22a8d709f812529b075baa7bd1559bc4cb38785e6367b092f169c596209fee88dcb"
    $a2="52e9f4483b441699b16276094af78f1cea6670bc9e359ca4fb984d69a0dd767a5acc9290515ea597639f629f76b25e198a3d121c1c7e82b553fb429e893e3973"
    $a3="52e9f4483b441699b16276094af78f1cea6670bc9e359ca4fb984d69a0dd767a5acc9290515ea597639f629f76b25e198a3d121c1c7e82b553fb429e893e3973"
    $a4="d6dc44ef4c274486bf10ad45b9b97537746443c665b875817010b6398aba76b321064857dd86568a6610e4de9ab520e57bbf64b11da6c1402873f4372d230414"
    $a5="d6dc44ef4c274486bf10ad45b9b97537746443c665b875817010b6398aba76b321064857dd86568a6610e4de9ab520e57bbf64b11da6c1402873f4372d230414"
    $a6="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a7="d3e9afd16eda3c4629fd94e48e5bab9dc9da5dbd3b07cf9ea5663ad9d154c91c5390f6997a3ce46cd7fd56c612d9de0831263a017576baf7069d3cee30633cd1"
    $a8="342d752a9dc0dfffe297aeafeac198365be1d50f3b21cbca820743e86f2dac2adf0c28e44106ab95575610ddd16ab149d681e63c1df2bd926635ccecfa259e4d"
    $a9="d3e9afd16eda3c4629fd94e48e5bab9dc9da5dbd3b07cf9ea5663ad9d154c91c5390f6997a3ce46cd7fd56c612d9de0831263a017576baf7069d3cee30633cd1"
    $a10="5a49aa49a7751ae9c0f3044663a776313a2c47130a948ea3fc038549dac4482559f6ec51fccd57987c765b2f79dbb88216df4103772432fba8d150e449e88d6f"
    $a11="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a12="046fe9d2fac4b0c0376da117d98abbc0f5cfe3acc91ff6085908b3f13d10bd4e6c0151d4fb0ab312c322380f5dc3258bbbb6ab27fe8c51f659d33a32ffd146a1"
    $a13="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a14="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a15="0df3481e3baf81644af9a215dbc64af11b61a08bc42ab45fc72d93147ac02eaf32c076defe258658710a2a7742d58ebdbca1feb04ae5ebd8b938604d18544132"
    $a16="7b817910a46064762097c3a6119ca5584bd0822e1d3821c2daab55135b2732ea2f9976fbc75aee3923b5ebf18338cf206386559ec611c39ee6c8072c28543e24"
    $a17="7b817910a46064762097c3a6119ca5584bd0822e1d3821c2daab55135b2732ea2f9976fbc75aee3923b5ebf18338cf206386559ec611c39ee6c8072c28543e24"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule blake2s_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80c86cf3a5c01a69b8a7ff71e0494169e29091fbdcc74deb27b0424b063da631"
    $a1="80c86cf3a5c01a69b8a7ff71e0494169e29091fbdcc74deb27b0424b063da631"
    $a2="fec1c25022e096836f4a607ce3f6c200abea8775cbb8bf8a7ca78dbd867c0e0c"
    $a3="fec1c25022e096836f4a607ce3f6c200abea8775cbb8bf8a7ca78dbd867c0e0c"
    $a4="ff95b804efe8412a293bdff3bfe9bffa0251ea7327f243a195bc6e1f68f16142"
    $a5="ff95b804efe8412a293bdff3bfe9bffa0251ea7327f243a195bc6e1f68f16142"
    $a6="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a7="47677dd17a17a8bc5b12a38ebc591c4dbb68499e929807a83244e372f639a32a"
    $a8="27ca50c9efe17c2d0871a3a5b07058eee51e0fec449450a463badc34be9cfb72"
    $a9="47677dd17a17a8bc5b12a38ebc591c4dbb68499e929807a83244e372f639a32a"
    $a10="309d4021807c32d3135c512b63aa35eaa712ecd016557c758650e38444b54f1b"
    $a11="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a12="c7867568fc4b7b2650b83f24a57e6d028f3c40e2b232f5ccbe8e1e99544a3833"
    $a13="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a14="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a15="94a80f8591a0d6bdfa8cc2126602a3852d92708079bad3ca3a814619898e7067"
    $a16="cf4f5c761da7a1c4166595e3b77976fe3135e6de6adea29f47c863bc4cfeef32"
    $a17="cf4f5c761da7a1c4166595e3b77976fe3135e6de6adea29f47c863bc4cfeef32"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_224_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e08ddc7460d3a0339638ff6a250888b2fdd5279ff8a13c1a8f84bc6a"
    $a1="e08ddc7460d3a0339638ff6a250888b2fdd5279ff8a13c1a8f84bc6a"
    $a2="d20652273bc03d450977787afeeb7b83cb394d78eb3fb1c2237f8e06"
    $a3="d20652273bc03d450977787afeeb7b83cb394d78eb3fb1c2237f8e06"
    $a4="e4edba7fad7cb671e5fd65394c56bb10d40a3fa809b44f7fdd3725ba"
    $a5="e4edba7fad7cb671e5fd65394c56bb10d40a3fa809b44f7fdd3725ba"
    $a6="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a7="37788067fed012db40ecbaff604c112684f0685d131bae1649b7ae76"
    $a8="dacf4055fd6f8f8b4af04ba59f7da52b72ae3ac620f8c6bf985e847c"
    $a9="37788067fed012db40ecbaff604c112684f0685d131bae1649b7ae76"
    $a10="55511238d0d82eba3d5e323fe3d0f4c6dbae811f3ba28e136ce6063a"
    $a11="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a12="30026b68fe664d44c650bc4445adb5806fcfe8129a77b32112cab8d0"
    $a13="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a14="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a15="ad89019dde61894842a61f2f2272182a68e1b5000ba353aa9e3e9205"
    $a16="20048b1f2fe61f29a4e1b33f4ffcf2fe777005ef616ac5a0e48e110b"
    $a17="20048b1f2fe61f29a4e1b33f4ffcf2fe777005ef616ac5a0e48e110b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_256_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bdaf93e1d2634a74791d37c11904211325d89d7dcf2c6231960f8ae15d1c3401"
    $a1="bdaf93e1d2634a74791d37c11904211325d89d7dcf2c6231960f8ae15d1c3401"
    $a2="86cbdabeba46c2f05e460f7183d20a09cb01c354fcb81d29ab54773e4c7cd490"
    $a3="86cbdabeba46c2f05e460f7183d20a09cb01c354fcb81d29ab54773e4c7cd490"
    $a4="b0c487aac068df482bf0a6ca161ac7dde146730324ac52c23dc429975a64fc6e"
    $a5="b0c487aac068df482bf0a6ca161ac7dde146730324ac52c23dc429975a64fc6e"
    $a6="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a7="f51812338f1d3993ea2fc873e24a049420606a22e8d24f2a9f2aa4687d98f0a3"
    $a8="7f2ca0d7e8d2e1e283fc1bb42b26da97da44ac170909d2fd831eeb1e0c5fa49f"
    $a9="f51812338f1d3993ea2fc873e24a049420606a22e8d24f2a9f2aa4687d98f0a3"
    $a10="eb03687b75749f50dc368946860642f928e14e00aa80ff438ed0105f3a608bcd"
    $a11="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a12="50ae02b46526f6ce0bedcd33b475840f27e148b312e8089dc2dfbc10ddca960b"
    $a13="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a14="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a15="be2f847879f73004a0da3c8dec8efd24d8671a15d4f67d51a9782f8c4394abd7"
    $a16="4e0e9f5fa7bb1a8778118cdc604dd98c00f29f34be0c54227e7c26e814152f32"
    $a17="4e0e9f5fa7bb1a8778118cdc604dd98c00f29f34be0c54227e7c26e814152f32"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_384_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18116244f5df2ae4f2650679c451d9a31aa03b9b4c66db3045e88afa9acb9a2f7782c85b82ff10ee3f76727af52ffb8d"
    $a1="18116244f5df2ae4f2650679c451d9a31aa03b9b4c66db3045e88afa9acb9a2f7782c85b82ff10ee3f76727af52ffb8d"
    $a2="16ecf09833cfef4d951cef07cb9f6808c2486aed0fdf70fa1422db442ef8abfe0f36a5677afb555f695291e3804eaed5"
    $a3="16ecf09833cfef4d951cef07cb9f6808c2486aed0fdf70fa1422db442ef8abfe0f36a5677afb555f695291e3804eaed5"
    $a4="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
    $a5="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
    $a6="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a7="ee45e3ab25285f3457a73f9cd40362598a53ff5e11aa929ea92eddca1df8f96f129dab5e0dc10bf91a8f1584caf046f3"
    $a8="88bcc6999eb878c6f2f8c6b4e4d53c16cef8b404a2e2a535184f613516821f6582f2b2047becefda5dbf1d578607b824"
    $a9="ee45e3ab25285f3457a73f9cd40362598a53ff5e11aa929ea92eddca1df8f96f129dab5e0dc10bf91a8f1584caf046f3"
    $a10="5b6ec279e869c119bb09329a67bc3008bf193b9d08cc125760576e557ab01985cf3dd9d949e4e3b859ad8d68abd48d04"
    $a11="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a12="859f4acd5845ee70358ee2c50f345047e4c52cdbf7940dc7e5585d7008af14ee6a4a5d88aa12dff4c50eecf6c5c42e1b"
    $a13="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a14="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a15="a7a88afadf5e6559987e2a7e031337a99ef1085074cbdf43ad046e40156897de70d34663a97c3427756090b3782cb92c"
    $a16="2c53361516b9069b5d11f3f70dc2b8ee39e5487145d52f4cf7b026bb8e3a6227670243749beb93475d66ce8ab0ddcb44"
    $a17="2c53361516b9069b5d11f3f70dc2b8ee39e5487145d52f4cf7b026bb8e3a6227670243749beb93475d66ce8ab0ddcb44"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule sha3_512_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc7b8225e921d98472b1fdc77a00ca8b2ae02cb6578a3b9e9e6bace00252311c1e3264df33426b3aa36dafc03d973bc5fdb38f1ce5de9283393d8c51a4183804"
    $a1="cc7b8225e921d98472b1fdc77a00ca8b2ae02cb6578a3b9e9e6bace00252311c1e3264df33426b3aa36dafc03d973bc5fdb38f1ce5de9283393d8c51a4183804"
    $a2="099fd622c3a5797b980360ab230600ad42ec392d25d68b715827211eca3e2971c9f445e8161ec80dd3c0e4a55d1bb82a5d0da8164b1f8816cbec43cdab8d4e59"
    $a3="099fd622c3a5797b980360ab230600ad42ec392d25d68b715827211eca3e2971c9f445e8161ec80dd3c0e4a55d1bb82a5d0da8164b1f8816cbec43cdab8d4e59"
    $a4="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
    $a5="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
    $a6="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a7="e53ad98cf3081f292dfaff1c5c9a2532dd4cf87c023d45ddfe3bbfecafdd60317f30d88d990cf02101a33dbefe4c29f0634ebd53b962bd91e9d4937f0f006c5e"
    $a8="29bdf6e37475a3019d6aaf797d7c015403b0596ebd26a307a6d9d2e02b2843d541853a00a77e7c43dd214682abe2f1c89ffd0a3b5a2622c4746bce84ce1a71b2"
    $a9="e53ad98cf3081f292dfaff1c5c9a2532dd4cf87c023d45ddfe3bbfecafdd60317f30d88d990cf02101a33dbefe4c29f0634ebd53b962bd91e9d4937f0f006c5e"
    $a10="f376c5f7052c441759b1667c4d80c125c7f5e377f6f0fbb9cc055cef1e0d237c8bc596fdb3d1ef696259b8c91fdb58406659e9eeb08cba614ddf77700891a741"
    $a11="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a12="ebb1f467a01dad7841e4db3a8495461a51d64d5b986f218dedaaa3e3c20a82e9f29ae0d3d4c2653d580d6e5062589a523f04912fe0cc3d760bbd029b78e5dad2"
    $a13="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a14="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a15="efe4903d927ec614d4591348e0266bea1f74e798eba058dd8fa7ca685726c1d6d9575e450d5650a8610313f06c2835abdf73555abb3807789c5df8d913fe1107"
    $a16="1c5dd0861a3e1d7368bd1c4e01eaa6624c30a4b1baa0abf5d033b424e5ec7b8a36fd98c12c1b4bb2dfba18228c3a56dc18d583ff34ac599bd26d682980f8429f"
    $a17="1c5dd0861a3e1d7368bd1c4e01eaa6624c30a4b1baa0abf5d033b424e5ec7b8a36fd98c12c1b4bb2dfba18228c3a56dc18d583ff34ac599bd26d682980f8429f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

rule base64_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bTExMjI="
    $a1="bTExMjI="
    $a2="dGVsZWNvbQ=="
    $a3="dGVsZWNvbQ=="
    $a4="Y2xpZW50"
    $a5="Y2xpZW50"
    $a6="bm9w"
    $a7="MTIzNDU="
    $a8="bm9w"
    $a9="MTIzNDU0"
    $a10="cm9vdA=="
    $a11="bm9raWE="
    $a12="cm9vdA=="
    $a13="cm9vdG1l"
    $a14="U2VjdXJpdHkgQ29kZQ=="
    $a15="MTIzNDU="
    $a16="VGVsZWNvbQ=="
    $a17="VGVsZWNvbQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}

