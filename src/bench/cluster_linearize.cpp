// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <cluster_linearize.h>
#include <util/bitset.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <vector>
#include <streams.h>
#include <test/util/cluster_linearize.h>

using namespace cluster_linearize;

namespace {

std::vector<std::string> slow_clusters = {
/*89, 700515*/ "b16a85cd3400b20b85d15a01b06385e03802b34485e96203af6685ad3804b16d85de6005b15185d43206b16885f24807b06085cc0a086e80db720808834882c76c09088010e4200a088035ec6c0b08864983bc5c0c088061f3440d0881178085680e0871b3400f08719c7210086e80dc761007832781c5161107803edb0412078051e40213078124808b6c14078010c41415078010c17616076fa67417078052c65818078063c34419076ef30c1908803ee73a1a086fb77e1b088035bc7c1c088050bf6c1d08884585a20c1e086e80e25a1e0871ce0e1f08817380fe6020088010d60021088010d81c22088010c82c230871b54024086fb44425086eb406260871b5202708800dc12428088051d35c29088134985a2a086e80d3662a078054ff262b078052da1c2c0771a2282d076e80dc1a2d08805f8084002e086fbf3e2f088051b31031076e80db223008830881af263108805ef53c32088032c07c33086ef51c33086fc56634086fc56635088035ea2e36086fb62a37088118c8763808800ea41839086e80d76e3908800edd4a3a088040eb003b0871bc323c0880109a784401800e9a3842048153a5024601800ec7464305800ec3183442c07b90c97448002f8010e1122644811880a41e4902208051b876214b8010da24204d8034b3044905118010a2581749815b80bd284a040b8078c7424a05068454ef6e500202926d85ef58098000d8559b87685000011d8051c62c0c42198051af72004c0b00",
/*90, 700511*/ "b16a85cd3400b20b85d15a01b06385e03802b34485e96203af6685ad3804b16d85de6005b15185d43206b16885f24807b06085cc0a086e80db720808834882c76c09088010e4200a088035ec6c0b08864983bc5c0c088061f3440d0881178085680e0871b3400f08719c7210086e80dc761007832781c5161107803edb0412078051e40213078124808b6c14078010c41415078010c17616076fa67417078052c65818078063c34419076ef30c1908803ee73a1a086fb77e1b088035bc7c1c088050bf6c1d08884585a20c1e086e80e25a1e0871ce0e1f08817380fe6020088010d60021088010d81c22088010c82c230871b54024086fb44425086eb406260871b5202708800dc12428088051d35c29088134985a2a086e80d3662a078054ff262b078052da1c2c0771a2282d076e80dc1a2d08805f8084002e086fbf3e2f088051b3103107800ec74631086e80db223108830881af263208805ef53c33088032c07c34086ef51c34086fc56635086fc56636088035ea2e37086fb62a38088118c8763908800ea4183a086e80d76e3a08800edd4a3b088040eb003c0871bc323d0880109a784501800e9a3843048153a5024701800ec3183442c07b90c97448002f8010e1122644811880a41e4902208051b876214b8010da24204d8034b3044905108010a2581649815b80bd284a040a8078c7424a05058454ef6e500201926d85ef58098000d8559b87685000011c8051c62c0c42188051af72004c0a800ea000005200",
/*91, 674669*/ "b16a85cd3400b20b85d15a01b06385e03802b34485e96203af6685ad3804b16d85de6005b15185d43206b16885f24807b06085cc0a086e80db720808834882c76c09088010e4200a088035ec6c0b08864983bc5c0c088061f3440d0881178085680e0871b3400f08719c7210086e80dc761007832781c5161107803edb0412078051e40213078124808b6c14078010c41415078010c17616076fa67417078052c65818078063c34419076ef30c1908803ee73a1a086fb77e1b088035bc7c1c088050bf6c1d08884585a20c1e086e80e25a1e0871ce0e1f08817380fe6020088010d60021088010d81c22088010c82c230871b54024086fb44425086eb406260871b5202708800dc12428088051d35c29088134985a2a086e80d3662a078054ff262b078052da1c2c0771a2282d076e80dc1a2d08805f8084002e086fbf3e2f088051b3103107800ec74631086e80db223108830881af263208805ef53c33088032c07c34086ef51c34086fc56635086fc56636088035ea2e37086fb62a38088118c8763908800ea4183a086e80d76e3a08800edd4a3b088040eb003c0871bc323d0880109a784501800e9a3843048153a502470180419cb76c4207800ec3183543c07b90c9744900308010e1122745811880a41e4a02218051b876224c8010da24214e8034b3044a05118010a258174a815b80bd284b040b8078c7424b05068454ef6e510202926d85ef58098002d8559b87685100011d8051c62c0c43198051af72004d0b800ea000005800",
/*87, 664495*/ "b16a85cd3400b34485e96201b20b85d15a02b06385e03803af6685ad3804b16d85de6005b15185d43206b16885f24807b06085cc0a086e80db720808834882c76c09088010e4200a088035ec6c0b08864983bc5c0c088061f3440d0881178085680e0871b3400f08719c7210086e80e25a100871ce0e1108817380fe6012088010d60013088010d81c14088010c82c150871b54016086fb44417086eb406180871b5201908800dc1241a088051d35c1b088134985a1c086e80dc761c08832781c5161d08803edb041e088051e4021f088124808b6c20088010c41421088010c17622086fa67423088052c65824088063c34425086ef30c2508803ee73a26086fb77e27088035bc7c28088050bf6c29086e80d36629088054ff262a088052da1c2b0871a2282c086e80dc1a2c08805f8084002d086fbf3e2e088051b31030076e80db222f08830881af263008805ef53c31088032c07c32086ef51c32086fc56633086fc56634088035ea2e35086fb62a36088118c8763708800ea418380880109a783e03800e9a383d056e80d76e3a08800edd4a3b088040eb003c0871bc323d088153a5024402884585a20c44038010e112334e811880a41e4800398051b8762e4d8010da242d4e800ec3182a4bc07b90c9744a00228034b3044805118010a2581748815b80bd2849030f8454ef6e500002926d85ef580470d8559b87684e00001e8051c62c07451a8051af72004a0900",
/*88, 650795*/ "b16a85cd3400b20b85d15a01b06385e03802b34485e96203af6685ad3804b16d85de6005b15185d43206b16885f24807b06085cc0a086e80db720808834882c76c09088010e4200a088035ec6c0b08864983bc5c0c088061f3440d0881178085680e0871b3400f08719c7210086e80dc761007832781c5161107803edb0412078051e40213078124808b6c14078010c41415078010c17616076fa67417078052c65818078063c34419076ef30c1908803ee73a1a086fb77e1b088035bc7c1c088050bf6c1d08884585a20c1e086e80e25a1e0871ce0e1f08817380fe6020088010d60021088010d81c22088010c82c230871b54024086fb44425086eb406260871b5202708800dc12428088051d35c29088134985a2a086e80d3662a078054ff262b078052da1c2c0771a2282d076e80dc1a2d08805f8084002e086fbf3e2f088051b31031076e80db223008830881af263108805ef53c32088032c07c33086ef51c33086fc56634086fc56635088035ea2e36086fb62a37088118c8763808800ea418390880109a784002800e9a383e056e80d76e3b08800edd4a3c088040eb003d0871bc323e088153a5024601800ec3183341c07b90c97447002e8010e1122543811880a41e48021f8051b876204a8010da241f4c8034b3044805108010a2581648815b80bd2849040a8454ef6e4e02018078c7424a0502926d85ef58097ed8559b87684f00011c8051c62c0c41188051af72004b0900",
/*94, 584769*/ "c104bae17400c55bbeab6601ae50aaa33602c040b9e15a03b10eac842604805f85931805ae2aa9c72c06af7dab817a07c61fbef926089d76a9bf7009805e81992e0a80408eb7320a096f8785320b096f86e2700c09803f8c86000d098a6fe6c3720e096e80e69f520e0a840faddd460f0a80618eb732100a80548bee6a110a814f92a204130980628a8a441409803285df6815097187da1a14087186c05c15087185893c1608805f8ad9001708800d84e74e18087183a67a19086e8081f5661a08803e92bd781a097185c76c1b096e80b3d7121c09850bb9953c1c0a803389f6261d0a6f859d621e0a6e84ff501f0a803f88d300200a6e8089ee0c210a806285931821096e85e14e210a80518abb5c220a805489e75a230a803187e338240a6e8082a60e250a7182e2342a066f87c34a260a8309a5c544270a71869118280a8054899c08290a6e8086e5082a0a801083bc102b0a6e8a83202b0a80518ccf282c0a80518996302d0a800e83f8302e0a6e80c39c482f0a8034849866380271829c6e35066e8290783a02837690f6483706807986883c3b03718298403c03815388b6583d03805384ec743e037184b53a370a6eaaec50380a7181f5683f04800582a8583b097081e02a3d08805f848f0c3e087181b91445027180eb1c47007180c37045036f80a22442077180a0504a00816f8381444b00803f80ef004309800580a4284c018267a096104d0041923d808d82164b0031803585ea40490025815c90b76649041b803584837c4e03129247dc86684a080d862184db684a060a8723c7a40a52000133835d97887806800181529ae21430203080548b8f382e282b80408e955c045a802589dc10048009801083b546027a8010848130007c00",
/*81, 582672*/ "800eb63c00af358dae5e01af5a8db93602bb5991827403800eb204048052af7205b5078f853006af578db86a07b3078eb90a08800ea218098054e47e08096fbd1409096fbb380a09805ef87a0b0971b8640c096fbb380d09837a82b4200e098076fa300f098309818e3e10096e80823c1009817580bf6c11098054e47e120971be1a130971f55c1409800dc920150971e25e160971b52017096ec15e1809803de5001909803fdc001a09803f809b201a09800ecd601b096eba721c098062f0001d096ed7161e0971e4241f09815280b36a20098008c25021098010c4142209805eeb0223098051d35c24098052e4022309803cda462308803fdc0024088061ec3c25086ebc2826088010cf2627088054ff2628086fb46a290871b8462a088010b5122b088010c4142c0871e4782d08800ec9642d098010cd0a2e0971b5402f0971b54030098060f24031098114ee6c320971b52032098035d90e33098033808f1a340971be2435098054f53436096fb444370971c5283809817df1003f03a7418a9c4a3d068051b41a42016fbb143746841b81f77038468054e47e44002f6fbb142840805f80f4002a3f6fbd0e14408062fa4c14418061de2c1244821c80c60244040771ea143517824180dd2e47000200000fb2138d9834261f0002030200",
/*76, 578559*/ "b46f93990000b263939c0801af5792832a02b26d92b77003c8249ac13004800eb83e058010b80606800da41007800d9d4c08800df01408088054808c3a09086ecc000a086fcc2c0b088035fc0a0c08810080a7000d086e81ef4c0e088060e8000f086e80926e0f05807680b87810058051e66011056fbc1412056e808c64120671d854130680548093021406817580b00416056e81e34a15078010e54e1607817481870817078032f05c1807803ef75219076ec13a1a078102f71e1b076eb5241c07811880813a1d07800dc0501e076e81d0241e088010e3301f0880538093022008800dc04221086eb90622088052e40223088051e66024088035d34025086eb17227078054db0c2b046eae582c046eb05029088052dd3e2a08800db82c2a05800db8202a06800d9d4c2908800dbc122f036faf103003937c87e70e31038173e8503104805180a74c2c38810180b650293c811480de522522a01891eb3637001171e11c1b2e800ee41617336ece121635873683af3e3900138052f42416378010c63013398010c2681339800d9d4c0f33800eb93a1929800ee4162c1697568d8004400200158050dd040c478010b6620444800db92e044371d5180149800db9300147a749928a2a18000013130f00",
/*52, 526866*/ "b13385ae2000800d991a01b31985a24402af5483fb4403b37285d63004b22885bd0605719e52050571ae2006058033d17e07056e9f420805817380d0200905805fc5500a058054c0640b05800ea3020c058101ff000d05803fe1340e05803dd4520f0571a45c0e02804080b2080f028035ca4810026ef624110271b74812028051c30c13028054c40a14026fcb1615026e80df3615037196301603800e9b4c1703800e9d5018038033b614190371aa7a1a038032b2441b038032c05c1c0371bf741d03811680960e1e036fb2481f036ea31220036fa36e2004800ece1621046fa30e220471cc7223048040c91824048060e44024058060e10025056ef82c27046ef51a2705800e95002a036ef3302e0071a214262c850d818172292a8052c0142f00039c1a87fc082d000000010200",
/*71, 521792*/ "801081a5360092239efc6201810982ab58029b6b98c86803800eed7804800ecb7e058f2f878778068030d43407853e81902a08962a81d176098010b6620a8010b2280b8010da3a0c9f069da9580d800db11e0e9d719ad37a0f967897ed5210990e99fc0e11812c81982012804685823e0f0a893982b6040a10804682c146110a6e80db5c120a8010819806130a8079858f0c140a8054829a120c12803483a1760c116f81843c0d11718189000e11800d81ac2c0f11800d81e50e10117181c77c1111822e87f2601012815983d17211127180f2121212811584a21e1312800e80d1781412813c83e81815126f80ef5016126f80ff6c16126f80f66017126e80fd541812800d81942a1912800e80dd781a12800d81f96c1b12805282e7581b127180fd721c1271a918230b805fc11a220d8118a15a2d036f80e5002011817684d8241e346f80e1181c37805082fc04260024800d81f8621734803382b354270b12805182ca2e162f800e80d52e0d32803dc360201b850e818c400b318c49808a5a290210805181d65823142a800d81a34e0850800e81fb3c0851886994fc0a280b00082c805482d208032e28805e83ba380059801081cd4a0159811884f770002e0015e17280e49024300a0000000000000031803dcb48014200",
/*70, 521581*/ "92239efc6200810982ab58019b6b98c86802800eed7803800ecb7e048f2f878778058030d43406853e81902a07962a81d176088010b662098010b2280a8010da3a0b9f069da9580c800db11e0d9d719ad37a0e967897ed520f990e99fc0e10812c81982011804685823e0f09893982b6040a0f804682c14611096e80db5c1209801081980613098079858f0c14098054829a120c11803483a1760c106f81843c0d10718189000e10800d81ac2c0f10800d81e50e10107181c77c1110822e87f2601011815983d17211117180f2121211811584a21e1311800e80d1781411813c83e81815116f80ef5016116f80ff6c16106f80f66017106e80fd541810800d81942a1910800e80dd781a10800d81f96c1b10805282e7581b117180fd721c116f80e5001d1171a918240a805fc11a230c8118a15a2e02817684d8241e336f80e1181c36805082fc04260023800d81f8621733803382b354270b11805182ca2e162e800e80d52e0d2d803dc3602019850e818c400a308c49808a5a29020e805181d658231429800d81a34e084f800e81fb3c0850886994fc0a280b0034805482d208032e27805e83ba380058801081cd4a0158811884f770002e0013e17280e49024300a0000000000000030803dcb48014000",
/*70, 519605*/ "801081a5360092239efc6201810982ab58029b6b98c86803800eed7804800ecb7e058f2f878778068030d43407853e81902a08962a81d176098010b6620a8010b2280b8010da3a0c9f069da9580d800db11e0e9d719ad37a0f990e99fc0e10967897ed5211812c81982012804685823e0f0a893982b6040a10804682c146110a6e80db5c120a8010819806130a8079858f0c140a8054829a120c12803483a1760c116f81843c0d11718189000e11800d81ac2c0f11800d81e50e10117181c77c1111822e87f2601012815983d17211127180f2121212811584a21e1312800e80d1781412813c83e81815126f80ef501612805282e75816117180fd7217116f80ff6c17126f80f66018126e80fd541912800d81942a1a12800e80dd781b1271a918220b805fc11a210d8118a15a2c03800d81f96c1f11817684d8241d336f80e1181b36805082fc04250023800d81f8621633803382b354260b11805182ca2e152e800e80d52e0a31803dc3601f1b850e818c400b308c49808a5a280210805181d658221429800d81a34e084e800e81fb3c084f886994fc0a270b00082b805482d208032d27805e83ba380057801081cd4a0157811884f770002d0015e17280e490242f0a0000000000000030803dcb48014100",
/*87, 509805*/ "805f85931800c104bae17401b10eac842602c040b9e15a03ae50aaa336049d76a9bf7005c55bbeab6606ae2aa9c72c07af7dab817a08805e81992e09806285931809096ea09b74090980408eb7320a096f8785320b096f86e2700c09803f8c86000d098a6fe6c3720e09814f92a2040f0980628a8a441009803285df681109803484986612096e82907813096e98e7381307850bb9953c1407803389f62615076ea0bd481508803e92bd7816087185c76c17086f859d621907803f88d3001a0771829c6e1b07837690f6481c077181f5681c086e978e081c097187da1a1d097186c05c1e097185893c1f097183a67a20097182e2342109805f8ad90022097184b53a22096ea393062209840faddd46230980618eb732240980548bee6a2509807986883c2609718298402709815388b6582809805384ec7429097181b9142a096e97b5262a096e85e14e2b0980518abb5c2c09805489e75a2d09803187e3382e096e98a0162e096f87c34a2f098309a5c54430097186911831098054899c083209801083bc1033097081e02a3409805f848f0c35097180eb1c3d016e80d4343a057180c3703d036f80a22439087180a0504101816f8381444201803f80ef003f05800580a4283f066ef7284402800d84e74e4304923d808d8216450028803584837c4700279247dc86684503258267a0961045041b803585ea40440012862184db6844050d835d97887805718723c7a40a4b00012b81529ae21446021c80548b8f381c321780408e955c0456802589dc10037a801083b54602668010848130006800",
/*94, 499456*/ "800e80c71200b365b3e40001b354b4bc2802b35bb19d5e03b52eb7873c04b55ab1b95405a93b88ae760671ea1e07800e80d42a07076d85d518070782638ad37208076f8193440907803f82a32a0a077180e9300b07805f82c2400c07803281e3500d07803481e4580e076f80d8460f076f80d37610077180be4e1107805481be6e1207803d819b3213076e809a5a1407806081b42e15076e84807815076f80f01216077180e52417077180e1501807805282a000190780108194681a076e809d321b07812383970a1c077180ce361d07822984e5381e077180b0501f07807681fe502007815283896a21078035818d3022077180a35023076e888d2e2307803d83ca7624077180f66e25076f80dc002607805e81bc582707801080d0562807805181990c29076e83a6182907817487af0c2a07801081b9402b077180f50c2c077180d3722d077180ce362e07801080f64c2f07803481b20030077180bd463107800d80d92e3207801080d5303307801080cd0634076e8a8e3a3407800d82ff643507807883be7a36076f80db2437077180dd203807803381981039077180a8603a07800d80d1003b077180a0783c0771809e7c3d076e8095723e076f8092683f0771808b0042056ea5c7364007805382cb3c4107803f81fd0a42077180975c43076f8092684407804080f5144507804080e8084607804080e000480671ed404806802f80a1404a056ec3244a06853380f25e4e03800e80c7124350864b8fd41c510040813c8486403656897592f92252012d7180b1442b5580548282485301246f80cb2e21548033819a6e540119807682b26854030c830883e25c540109805281b12054021900",
/*85, 495219*/ "800eb63c00af358dae5e01af5a8db93602bb5991827403800eb204048052af7205b5078f853006af578db86a07b3078eb90a08800ea218098054e47e08096fbd1409096fbb380a09805ef87a0b0971b8640c096fbb380d09837a82b4200e098076fa300f098309818e3e10096e80823c1009817580bf6c11098054e47e120971be1a130971f55c1409800dc920150971e25e160971b52017096ec15e1809803de5001909803fdc001a09803f809b201a09800ecd601b096eba721c098062f0001d096ed7161e0971e4241f09815280b36a20098008c25021098010c4142209805eeb0223098051d35c24098117eb5a25098052e4022409803cda462408803fdc0025088061ec3c26086ebc2827088010cf2628088054ff2629086fb46a2a0871b8462b088010b5122c088010c4142d0871e4782e08800ec9642e098010cd0a2f0971b540300971b54031098060f24032098114ee6c33098051d328340971b52034098035d90e35098033808f1a360971be2437098054f53438096fb444390971c5283a09817df1004103a7418a9c4a3f068051b41a44018175809e343f076fbb143a49841b81f7703b498054e47e47003271ea1432486fbb142c42805f80f4002e416fbd0e17428062fa4c17438061de2c15468010b9001547821c80c602490408824180dd2e4b000200000fb2138d983429200002030200",
/*65, 491819*/ "6ead340071a240018010a71602dd078fba6a03800d8e2604718b20058117990e0680108c3207b93a86a67008800d8a140980359b160a803598120b803595740c8010877a0d7189460e8a1780f41e0f6e828d6c0c0f800dd17e0d0f71c5280e0f8051fa1c0f0f811780971a100f815b808060110f8010c268120f820880bd56130f811680846c140f8034c438150f6fa86e160f800eb340170f718f28170f80108a14150f6d83dd26150f71cb08160f8075e208170f8010c268180f8010b770190e6fa8381a0e8060d04a1b0e8040c01a1c0e8061c9141d0e800d8764190f718b281f088305a7462008807880a34a1834850982b93a153471b8601534800d8764052a8515dc2c1e0b05861d84a7040e1e128a5684ba5826000413800d876403308078eb40013e8010a4760133800e876c0232800e876c0034800e876c00348008b57a00348010877c0134a0228b83241b001400000022803ddc000135800d8a760234800e8b00003680108b160036ac5e8fc2240a2100000001060e802c895c0136800dc470003700",
/*64, 491801*/ "71a240008010a71601dd078fba6a02800d8e2603718b20048117990e0580108c3206b93a86a67007800d8a140880359b1609803598120a803595740b8010877a0c7189460d8a1780f41e0e6e828d6c0c03800dd17e0d0371c5280e038051fa1c0f03811780971a1003815b80806011038010c2681203820880bd561303811680846c14038034c43815036fa86e1603800eb3401703718f28170480108a1415076d83dd26150871cb0816088075e20817088010c26818088010b77019086fa8381a088060d04a1b088040c01a1c088061c9141d08800d8764190d718b281f078305a7462007807880a34a1812850982b93a151671b8601517800d87640528861d84a7040d218515dc2c1f0b048a5684ba5826000406800d8764032e8078eb4001308010a4760131800e876c0231800e876c0033800e876c00338008b57a00338010877c0133a0228b83241b00140000000a803ddc000134800d8a760233800e8b00003580108b160035ac5e8fc2240a2100000001060d802c895c0135800dc470003600",
/*36, 479231*/ "8031c130008031c41201a1598fa05c01019048879c6001018031c67403008019c65c02048019c65c03048019c65c04048019c65c05048019c65c06048019c65c07048019c65c08048019c65c09048019c65c0a048019c65c0b048019c65c0c048019c65c0d048019c65c0d038019c65c0e038019c65c0f038019c65c10038019c65c11038019c65c12038019c65c13038019c65c14038019c65c15038019c65c16038019c65c17038019c65c18038019c65c19038019c65c1a038019c65c1b038019c65c1c038019c65c1d038019c65c1f01810ceb701e020100",
/*95, 478226*/ "c55bbeab6600c040b9e15a01b10eac842602af7dab817a03805f85931804ae2aa9c72c05ae50aaa33606c61fbef92607c104bae174089d76a9bf7009805e81992e0a6e80e69f520a0a840faddd460b0a80618eb7320c0a80548bee6a0d0a803e92bd780d097185c76c0e096e80b3d7120f09850bb9953c0f0a803389f626100a6f859d62110a6e84ff50120a803f88d300130a6e8089ee0c140a6f87c34a140a8309a5c544150a71869118160a8054899c08170a6e8086e508180a806285931818096e85e14e180a80518abb5c190a805489e75a1a0a803187e3381b0a6e8082a60e1c0a7187da1a1c0a7186c05c1d0a7185893c1e0a805f8ad9001f0a800d84e74e200a7183a67a210a6e8081f566220a7182e234230a801083bc1027076e8a8320240a80518ccf28250a8051899630260a800e83f830270a6e80c39c48280a71829c6e2e05837690f6482f05807986883c320371829840330380408eb7322c0a6f8785322d0a6f86e2702e0a803f8c86002f0a8a6fe6c372300a814f92a204310a80628a8a44320a803285df68330a8034849866340a6e829078350a815388b6583e02805384ec743f027184b53a370a6eaaec50380a7181f5684102800582a8583c087081e02a4104805f848f0c42047181b91446017180eb1c3f087180c37047016f80a22446037180a0504208816f8381444308803f80ef004309800580a4284d006e80b4cc3e4608923d808d82164d0041803585ea404b0135815c90b7664a05238267a096104a0713803584837c4b05159247dc86684b0016862184db684b0809835d97887806801481529ae2143a173b8723c7a40a5001041780548b8f3839171d80408e955c045c802589dc10026d801083b546026e8010848130007000",
/*86, 477638*/ "805f85931800c104bae17401b10eac842602c040b9e15a03ae50aaa336049d76a9bf7005c55bbeab6606ae2aa9c72c07af7dab817a08805e81992e09806285931809096ea09b74090980408eb7320a096f8785320b096f86e2700c09803f8c86000d098a6fe6c3720e09814f92a2040f0980628a8a441009803285df681109803484986612096e82907813096e98e7381308850bb9953c1408803389f62615086ea0bd481509803e92bd7816097185c76c17096f859d621908803f88d3001a0871829c6e1b08837690f6481c087181f5681c096e978e081c097187da1a1d097186c05c1e097185893c1f097183a67a20097182e23421097184b53a21096ea393062109840faddd46220980618eb732230980548bee6a2409807986883c2509718298402609815388b6582709805384ec7428097181b91429096e97b52629096e85e14e2a0980518abb5c2b09805489e75a2c09803187e3382d096e98a0162d096f87c34a2e098309a5c5442f097186911830098054899c083109801083bc1032097081e02a3309805f848f0c34097180eb1c3c016e80d43439057180c3703c036f80a22438087180a0504001816f8381444101803f80ef003e05800580a4283e066ef7284302805f8ad9004204923d808d821644002f803584837c46002e9247dc86684403258267a0961044041b803585ea40430012862184db6843050d835d97887805778723c7a40a4a00012b81529ae21445021c80548b8f381c311780408e955c0455802589dc100379801083b54602658010848130006700",
};

/** Construct a linear graph. These are pessimal for AncestorCandidateFinder, as they maximize
 *  the number of ancestor set feerate updates. The best ancestor set is always the topmost
 *  remaining transaction, whose removal requires updating all remaining transactions' ancestor
 *  set feerates. */
    template<typename SetType>
DepGraph<SetType> MakeLinearGraph(ClusterIndex ntx)
{
    DepGraph<SetType> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        depgraph.AddTransaction({-int32_t(i), 1});
        if (i > 0) depgraph.AddDependency(i - 1, i);
    }
    return depgraph;
}

/** Construct a wide graph (one root, with N-1 children that are otherwise unrelated, with
 *  increasing feerates). These graphs are pessimal for the LIMO step in Linearize, because
 *  rechunking is needed after every candidate (the last transaction gets picked every time).
 */
template<typename SetType>
DepGraph<SetType> MakeWideGraph(ClusterIndex ntx)
{
    DepGraph<SetType> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        depgraph.AddTransaction({int32_t(i) + 1, 1});
        if (i > 0) depgraph.AddDependency(0, i);
    }
    return depgraph;
}

// Construct a difficult graph. These need at least sqrt(2^(n-1)) iterations in the implemented
// algorithm (purely empirically determined).
template<typename SetType>
DepGraph<SetType> MakeHardGraph(ClusterIndex ntx)
{
    DepGraph<SetType> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        if (ntx & 1) {
            // Odd cluster size.
            //
            // Mermaid diagram code for the resulting cluster for 11 transactions:
            // ```mermaid
            // graph BT
            // T0["T0: 1/2"];T1["T1: 14/2"];T2["T2: 6/1"];T3["T3: 5/1"];T4["T4: 7/1"];
            // T5["T5: 5/1"];T6["T6: 7/1"];T7["T7: 5/1"];T8["T8: 7/1"];T9["T9: 5/1"];
            // T10["T10: 7/1"];
            // T1-->T0;T1-->T2;T3-->T2;T4-->T3;T4-->T5;T6-->T5;T4-->T7;T8-->T7;T4-->T9;T10-->T9;
            // ```
            if (i == 0) {
                depgraph.AddTransaction({1, 2});
            } else if (i == 1) {
                depgraph.AddTransaction({14, 2});
                depgraph.AddDependency(0, 1);
            } else if (i == 2) {
                depgraph.AddTransaction({6, 1});
                depgraph.AddDependency(2, 1);
            } else if (i == 3) {
                depgraph.AddTransaction({5, 1});
                depgraph.AddDependency(2, 3);
            } else if ((i & 1) == 0) {
                depgraph.AddTransaction({7, 1});
                depgraph.AddDependency(i - 1, i);
            } else {
                depgraph.AddTransaction({5, 1});
                depgraph.AddDependency(i, 4);
            }
        } else {
            // Even cluster size.
            //
            // Mermaid diagram code for the resulting cluster for 10 transactions:
            // ```mermaid
            // graph BT
            // T0["T0: 1"];T1["T1: 3"];T2["T2: 1"];T3["T3: 4"];T4["T4: 0"];T5["T5: 4"];T6["T6: 0"];
            // T7["T7: 4"];T8["T8: 0"];T9["T9: 4"];
            // T1-->T0;T2-->T0;T3-->T2;T3-->T4;T5-->T4;T3-->T6;T7-->T6;T3-->T8;T9-->T8;
            // ```
            if (i == 0) {
                depgraph.AddTransaction({1, 1});
            } else if (i == 1) {
                depgraph.AddTransaction({3, 1});
                depgraph.AddDependency(0, 1);
            } else if (i == 2) {
                depgraph.AddTransaction({1, 1});
                depgraph.AddDependency(0, 2);
            } else if (i & 1) {
                depgraph.AddTransaction({4, 1});
                depgraph.AddDependency(i - 1, i);
            } else {
                depgraph.AddTransaction({0, 1});
                depgraph.AddDependency(i, 3);
            }
        }
    }
    return depgraph;
}

/** Benchmark that does search-based candidate finding with a specified number of iterations.
 *
 * Its goal is measuring how much time every additional search iteration in linearization costs,
 * by running with a low and a high count, subtracting the results, and divided by the number
 * iterations difference.
 */
template<typename SetType>
void BenchLinearizeWorstCase(ClusterIndex ntx, benchmark::Bench& bench, uint64_t iter_limit)
{
    const auto depgraph = MakeHardGraph<SetType>(ntx);
    uint64_t rng_seed = 0;
    bench.run([&] {
        SearchCandidateFinder finder(depgraph, rng_seed++);
        auto [candidate, iters_performed] = finder.FindCandidateSet(iter_limit, {});
        assert(iters_performed == iter_limit);
    });
}

/** Benchmark for linearization improvement of a trivial linear graph using just ancestor sort.
 *
 * Its goal is measuring how much time linearization may take without any search iterations.
 *
 * If P is the benchmarked per-iteration count (obtained by running BenchLinearizeWorstCase for a
 * high and a low iteration count, subtracting them, and dividing by the difference in count), and
 * N is the resulting time of BenchLinearizeNoItersWorstCase*, then an invocation of Linearize with
 * max_iterations=m should take no more than roughly N+m*P time. This may however be an
 * overestimate, as the worst cases do not coincide (the ones that are worst for linearization
 * without any search happen to be ones that do not need many search iterations).
 *
 * This benchmark exercises a worst case for AncestorCandidateFinder, but for which improvement is
 * cheap.
 */
template<typename SetType>
void BenchLinearizeNoItersWorstCaseAnc(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeLinearGraph<SetType>(ntx);
    uint64_t rng_seed = 0;
    std::vector<ClusterIndex> old_lin(ntx);
    for (ClusterIndex i = 0; i < ntx; ++i) old_lin[i] = i;
    bench.run([&] {
        Linearize(depgraph, /*max_iterations=*/0, rng_seed++, old_lin);
    });
}

/** Benchmark for linearization improvement of a trivial wide graph using just ancestor sort.
 *
 * Its goal is measuring how much time improving a linearization may take without any search
 * iterations, similar to the previous function.
 *
 * This benchmark exercises a worst case for improving an existing linearization, but for which
 * AncestorCandidateFinder is cheap.
 */
template<typename SetType>
void BenchLinearizeNoItersWorstCaseLIMO(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeWideGraph<SetType>(ntx);
    uint64_t rng_seed = 0;
    std::vector<ClusterIndex> old_lin(ntx);
    for (ClusterIndex i = 0; i < ntx; ++i) old_lin[i] = i;
    bench.run([&] {
        Linearize(depgraph, /*max_iterations=*/0, rng_seed++, old_lin);
    });
}

template<typename SetType>
void BenchPostLinearizeWorstCase(ClusterIndex ntx, benchmark::Bench& bench)
{
    DepGraph<SetType> depgraph = MakeWideGraph<SetType>(ntx);
    std::vector<ClusterIndex> lin(ntx);
    bench.run([&] {
        for (ClusterIndex i = 0; i < ntx; ++i) lin[i] = i;
        PostLinearize(depgraph, lin);
    });
}

template<typename SetType>
void BenchMergeLinearizationsWorstCase(ClusterIndex ntx, benchmark::Bench& bench)
{
    DepGraph<SetType> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        depgraph.AddTransaction({i, 1});
        if (i) depgraph.AddDependency(0, i);
    }
    std::vector<ClusterIndex> lin1;
    std::vector<ClusterIndex> lin2;
    lin1.push_back(0);
    lin2.push_back(0);
    for (ClusterIndex i = 1; i < ntx; ++i) {
        lin1.push_back(i);
        lin2.push_back(ntx - i);
    }
    bench.run([&] {
        MergeLinearizations(depgraph, lin1, lin2);
    });
}

template<typename SetType>
void BenchSerializedCluster(const std::string& hexenc, benchmark::Bench& bench)
{
    std::optional<std::vector<uint8_t>> encoding = TryParseHex<uint8_t>(hexenc);
    SpanReader reader(*encoding);
    DepGraph<SetType> depgraph_read;
    reader >> Using<DepGraphFormatter>(depgraph_read);
    uint64_t rng_seed = 0;
    std::vector<ClusterIndex> orig_lin;
    SetType all{SetType::Fill(depgraph_read.TxCount())};
    depgraph_read.AppendTopo(orig_lin, all);
    bench.run([&] {
        auto res = Linearize(depgraph_read, /*max_iterations=*/1000000, rng_seed++);
        //assert(res.second);
    });
}

} // namespace

static void Linearize16TxWorstCase20Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<16>>(16, bench, 20); }
static void Linearize16TxWorstCase120Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<16>>(16, bench, 120); }
static void Linearize32TxWorstCase5000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<32>>(32, bench, 5000); }
static void Linearize32TxWorstCase15000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<32>>(32, bench, 15000); }
static void Linearize48TxWorstCase5000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<48>>(48, bench, 5000); }
static void Linearize48TxWorstCase15000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<48>>(48, bench, 15000); }
static void Linearize64TxWorstCase5000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<64>>(64, bench, 5000); }
static void Linearize64TxWorstCase15000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<64>>(64, bench, 15000); }
static void Linearize75TxWorstCase5000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<75>>(75, bench, 5000); }
static void Linearize75TxWorstCase15000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<75>>(75, bench, 15000); }
static void Linearize99TxWorstCase5000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<99>>(99, bench, 5000); }
static void Linearize99TxWorstCase15000Iters(benchmark::Bench& bench) { BenchLinearizeWorstCase<BitSet<99>>(99, bench, 15000); }

static void LinearizeSerializedCluster0(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[0], bench); }
static void LinearizeSerializedCluster1(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[1], bench); }
static void LinearizeSerializedCluster2(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[2], bench); }
static void LinearizeSerializedCluster3(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[3], bench); }
static void LinearizeSerializedCluster4(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[4], bench); }
static void LinearizeSerializedCluster5(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[5], bench); }
static void LinearizeSerializedCluster6(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[6], bench); }
static void LinearizeSerializedCluster7(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[7], bench); }
static void LinearizeSerializedCluster8(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<64>>(slow_clusters[8], bench); }
static void LinearizeSerializedCluster9(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[9], bench); }
static void LinearizeSerializedCluster10(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[10], bench); }
static void LinearizeSerializedCluster11(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[11], bench); }
static void LinearizeSerializedCluster12(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[12], bench); }
static void LinearizeSerializedCluster13(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[13], bench); }
static void LinearizeSerializedCluster14(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[14], bench); }
static void LinearizeSerializedCluster15(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[15], bench); }
static void LinearizeSerializedCluster16(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<64>>(slow_clusters[16], bench); }
static void LinearizeSerializedCluster17(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<36>>(slow_clusters[17], bench); }
static void LinearizeSerializedCluster18(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[18], bench); }
static void LinearizeSerializedCluster19(benchmark::Bench& bench) { BenchSerializedCluster<BitSet<99>>(slow_clusters[19], bench); }

static void LinearizeNoIters16TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<16>>(16, bench); }
static void LinearizeNoIters32TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<32>>(32, bench); }
static void LinearizeNoIters48TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<48>>(48, bench); }
static void LinearizeNoIters64TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<64>>(64, bench); }
static void LinearizeNoIters75TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<75>>(75, bench); }
static void LinearizeNoIters99TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<99>>(99, bench); }

static void LinearizeNoIters16TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<16>>(16, bench); }
static void LinearizeNoIters32TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<32>>(32, bench); }
static void LinearizeNoIters48TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<48>>(48, bench); }
static void LinearizeNoIters64TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<64>>(64, bench); }
static void LinearizeNoIters75TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<75>>(75, bench); }
static void LinearizeNoIters99TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<99>>(99, bench); }

static void PostLinearize16TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<16>>(16, bench); }
static void PostLinearize32TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<32>>(32, bench); }
static void PostLinearize48TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<48>>(48, bench); }
static void PostLinearize64TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<64>>(64, bench); }
static void PostLinearize75TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<75>>(75, bench); }
static void PostLinearize99TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<99>>(99, bench); }

static void MergeLinearizations16TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<16>>(16, bench); }
static void MergeLinearizations32TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<32>>(32, bench); }
static void MergeLinearizations48TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<48>>(48, bench); }
static void MergeLinearizations64TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<64>>(64, bench); }
static void MergeLinearizations75TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<75>>(75, bench); }
static void MergeLinearizations99TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<99>>(99, bench); }

BENCHMARK(Linearize16TxWorstCase20Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize16TxWorstCase120Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize32TxWorstCase5000Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize32TxWorstCase15000Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize48TxWorstCase5000Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize48TxWorstCase15000Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize64TxWorstCase5000Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize64TxWorstCase15000Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize75TxWorstCase5000Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize75TxWorstCase15000Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize99TxWorstCase5000Iters, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize99TxWorstCase15000Iters, benchmark::PriorityLevel::HIGH);

BENCHMARK(LinearizeSerializedCluster0, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster1, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster2, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster3, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster4, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster5, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster6, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster7, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster8, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster9, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster10, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster11, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster12, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster13, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster14, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster15, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster16, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster17, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster18, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeSerializedCluster19, benchmark::PriorityLevel::HIGH);

BENCHMARK(LinearizeNoIters16TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters32TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters48TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters64TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters75TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters99TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);

BENCHMARK(LinearizeNoIters16TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters32TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters48TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters64TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters75TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters99TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);

BENCHMARK(PostLinearize16TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize32TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize48TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize64TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize75TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize99TxWorstCase, benchmark::PriorityLevel::HIGH);

BENCHMARK(MergeLinearizations16TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations32TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations48TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations64TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations75TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations99TxWorstCase, benchmark::PriorityLevel::HIGH);
