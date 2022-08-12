using System;
using bls;
using bls.NativeImport;
using Xunit;

namespace bls.Test
{
    public class NativeTest
    {
        [Fact]
        public void TestId()
        {
            Id id1;
            id1.SetDecStr("255");
            Assert.Equal("255", id1.GetDecStr());
            Assert.Equal("ff", id1.GetHexStr());
            Id id2;
            id2.SetInt(255);
            Assert.True(id1.IsEqual(id2));
        }

        [Fact]
        public void TestSecretKey()
        {
            SecretKey sec;
            sec.SetHexStr("ff");
            Assert.Equal("ff", sec.GetHexStr());

            SecretKey sec2;
            sec.SetHexStr("321");
            sec2.SetHexStr("4000");

            sec.Add(sec2);
            Assert.Equal("4321", sec.GetHexStr());
            sec.Sub(sec2);
            Assert.Equal("321", sec.GetHexStr());

            sec.SetByCSPRNG();
            Assert.NotEmpty(sec.GetHexStr());

            sec.SetHexStr("321");
            sec2 = sec;
            sec.Neg();
            // TODO: Get Negate fixture value.

            sec.Add(sec2);
            Assert.Equal("0", sec.GetHexStr());
            Assert.True(sec.IsZero());

            sec2 = new SecretKey();
            byte[] buf = sec.Serialize();
            Assert.Throws<ArgumentException>(()=> sec2.Deserialize(buf));

            sec2 = new SecretKey();
            sec.SetHexStr("0x11");
            sec2.SetHexStr("0x23");
            sec.Mul(sec2);
            Assert.Equal("253", sec.GetHexStr());
        }

        [Fact]
        public void TestPublicKey()
        {
            SecretKey sec;
            sec.SetByCSPRNG();
            PublicKey pub = sec.GetPublicKey();
            string s = pub.GetHexStr();

            PublicKey pub2;
            pub2.SetStr(s);
            Assert.True(pub.IsEqual(pub2));

            byte[] buf = pub.Serialize();
            pub2.Deserialize(buf);
            Assert.True(pub2.IsEqual(pub));

            pub2 = pub;
            pub.Neg();
            pub.Add(pub2);
            Assert.Equal("0", pub.GetHexStr());

            pub2 = pub;
            for (int i = 0; i < 5; i++)
            {
                pub2.Add(pub);
            }

            PublicKey pub3 = pub;
            SecretKey t;
            t.SetHexStr("5");
            pub3.Mul(t);
            Assert.True(pub2.IsEqual(pub3));
        }

        [Fact]
        public void TestSign()
        {
            SecretKey sec;
            sec.SetByCSPRNG();
            PublicKey pub = sec.GetPublicKey();

            string m = "abc";
            Signature sig = sec.Sign(m);

            Assert.True(pub.Verify(sig, m));
            Assert.False(pub.Verify(sig, m + "a"));

            Signature sig2;
            byte[] buf = sig.Serialize();
            sig2.Deserialize(buf);
            Assert.True(sig2.IsEqual(sig));

            sig2 = sig;
            sig.Neg();
            sig.Add(sig2);
            Assert.True(sig.IsZero());


            sig2 = sig;
            for (int i = 0; i < 5; i++)
            {
                sig2.Add(sig);
            }

            Signature sig3 = sig;
            SecretKey t;
            t.SetHexStr("5");
            sig3.Mul(t);
            Assert.True(sig2.IsEqual(sig3));
        }

        [Fact]
        public void TestSharing()
        {
            int k = 5;
            SecretKey[] msk = new SecretKey[k];
            PublicKey[] mpk = new PublicKey[k];

            // make master secretkey
            for (int i = 0; i < k; i++)
            {
                msk[i].SetByCSPRNG();
                mpk[i] = msk[i].GetPublicKey();
            }

            int n = 30;
            Id[] ids = new Id[n];
            SecretKey[] secs = new SecretKey[n];
            PublicKey[] pubs = new PublicKey[n];
            for (int i = 0; i < n; i++)
            {
                ids[i].SetInt(i * i + 123);
                secs[i] = SecretKey.ShareSecretKey(msk, ids[i]);
                pubs[i] = PublicKey.SharePublicKey(mpk, ids[i]);
                Assert.True(secs[i].GetPublicKey().IsEqual(pubs[i]));
            }

            string m = "doremi";
            Signature signature;
            for (int i = 0; i < n; i++)
            {
                signature = secs[i].Sign(m);
                Assert.True(pubs[i].Verify(signature, m));
            }

            int[] idxTbl = { 0, 2, 5, 8, 10 };
            Assert.Equal(k, idxTbl.Length);

            Id[] subIds = new Id[k];
            SecretKey[] subSecs = new SecretKey[k];
            PublicKey[] subPubs = new PublicKey[k];
            Signature[] subSigns = new Signature[k];

            for (int i = 0; i < k; i++)
            {
                int idx = idxTbl[i];
                subIds[i] = ids[idx];
                subSecs[i] = secs[idx];
                subPubs[i] = pubs[idx];
                subSigns[i] = secs[idx].Sign(m);
            }

            SecretKey sec = SecretKey.RecoverSecretKey(subSecs, subIds);
            PublicKey pub = PublicKey.RecoverPublicKey(subPubs, subIds);
            Assert.True(pub.IsEqual(sec.GetPublicKey()));
            signature = Signature.RecoverSign(subSigns, subIds);
            Assert.True(pub.Verify(signature, m));
        }

        [Fact]
        public void TestAggregate()
        {
            const int n = 10;
            const string m = "abc";

            SecretKey[] secVec = new SecretKey[n];
            PublicKey[] pubVec = new PublicKey[n];
            Signature[] popVec = new Signature[n];
            Signature[] sigVec = new Signature[n];

            for (int i = 0; i < n; i++)
            {
                secVec[i].SetByCSPRNG();
                pubVec[i] = secVec[i].GetPublicKey();
                popVec[i] = secVec[i].GetPop();
                sigVec[i] = secVec[i].Sign(m);
            }

            SecretKey secAgg;
            PublicKey pubAgg;
            Signature sigAgg;

            for (int i = 0; i < n; i++)
            {
                secAgg.Add(secVec[i]);
                Assert.True(pubVec[i].VerifyPop(popVec[i]));
                pubAgg.Add(pubVec[i]);
                sigAgg.Add(sigVec[i]);
            }

            Assert.True(secAgg.Sign(m).IsEqual(sigAgg));
            Assert.True(pubAgg.Verify(sigAgg, m));

            // sub
            secAgg = secVec[0];
            secAgg.Add(secVec[1]);
            secAgg.Sub(secVec[1]);
            Assert.True(secAgg.IsEqual(secVec[0]));

            pubAgg = pubVec[0];
            pubAgg.Add(pubVec[1]);
            pubAgg.Sub(pubVec[1]);
            Assert.True(secAgg.IsEqual(secVec[0]));

            sigAgg = sigVec[0];
            sigAgg.Add(sigVec[1]);
            sigAgg.Sub(sigVec[1]);
            Assert.True(secAgg.IsEqual(secVec[0]));
        }

        [Fact]
        public void TestMulVec()
        {
            int n = 10;
            const string m = "abc";
            SecretKey[] secVec = new SecretKey[n];
            PublicKey[] pubVec = new PublicKey[n];
            Signature[] sigVec = new Signature[n];
            SecretKey[] frVec = new SecretKey[n];

            for (int i = 0; i < n; i++)
            {
                secVec[i].SetByCSPRNG();
                pubVec[i] = secVec[i].GetPublicKey();
                sigVec[i] = secVec[i].Sign(m);
                frVec[i].SetByCSPRNG();
            }

            PublicKey aggPub = PublicKey.MulVec(pubVec, frVec);
            Signature aggSig = Signature.MulVec(sigVec, frVec);
            Assert.True(aggPub.Verify(aggSig, m));
        }

        [Fact]
        static void TestFastAggregateVerify()
        {
            var tbl = new[] {
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
                    },
                    msg = "abababababababababababababababababababababababababababababababab",
                    sig = "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfcffffffff",
                    expected = false,
                },
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                    },
                    msg = "0000000000000000000000000000000000000000000000000000000000000000",
                    sig = "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
                    expected = true,
                },
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                    },
                    msg = "5656565656565656565656565656565656565656565656565656565656565656",
                    sig = "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1",
                    expected = true,
                },
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
                    },
                    msg = "abababababababababababababababababababababababababababababababab",
                    sig = "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930",
                    expected = true,
                },
            };

            foreach (var v in tbl)
            {
                int n = v.pubVec.Length;
                PublicKey[] pubVec = new PublicKey[n];
                bool result = false;
                try
                {
                    for (int i = 0; i < n; i++)
                    {
                        pubVec[i].Deserialize(v.pubVec[i].ToBytes());
                    }
                    var msg = v.msg.ToBytes();

                    Signature sig = new Signature();
                    sig.Deserialize(v.sig.ToBytes());
                    result = sig.FastAggregateVerify(pubVec, msg);
                }
                catch (Exception) {
                    // pass through
                }

                Assert.Equal(v.expected, result);
            }
        }

        [Fact]
        public void TestAggregateVerify()
        {
            var tbl = new[] {
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
                    },
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "5656565656565656565656565656565656565656565656565656565656565656",
                        "abababababababababababababababababababababababababababababababab",
                    },
                    sig = "9104e74bffffffff",
                    expected = false,
                },
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
                    },
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "5656565656565656565656565656565656565656565656565656565656565656",
                        "abababababababababababababababababababababababababababababababab",
                    },
                    sig = "9104e74b9dfd3ad502f25d6a5ef57db0ed7d9a0e00f3500586d8ce44231212542fcfaf87840539b398bf07626705cf1105d246ca1062c6c2e1a53029a0f790ed5e3cb1f52f8234dc5144c45fc847c0cd37a92d68e7c5ba7c648a8a339f171244",
                    expected = true,
                },
            };
            foreach (var v in tbl)
            {
                int n = v.pubVec.Length;
                PublicKey[] pubVec = new PublicKey[n];
                bool result = false;
                try {
                    for (int i = 0; i < n; i++) {
                        pubVec[i].Deserialize(v.pubVec[i].ToBytes());
                    }
                    Msg[] msgVec = new Msg[n];
                    for (int i = 0; i < n; i++) {
                        msgVec[i].Set(v.msgVec[i].ToBytes());
                    }
                    Signature sig = new Signature();
                    sig.Deserialize(v.sig.ToBytes());
                    result = sig.AggregateVerify(pubVec, msgVec);
                }
                catch (Exception)
                {
                    // pass through
                }

                Assert.Equal(v.expected, result);
            }
        }


        static void TestAreAllMsgDifferent()
        {
            Console.WriteLine("TestAreAllMsgDifferent");
            var tbl = new[] {
                new {
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000001",
                        "0000000000000000000000000000000000000000000000000000000000000002",
                    },
                    expected = true,
                },
                new {
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000001",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    },
                    expected = false,
                },
            };

            foreach (var t in tbl)
            {
                int n = t.msgVec.Length;
                var msgVec = new Msg[n];

                for (int i = 0; i < n; i++)
                {
                    msgVec[i].Set(t.msgVec[i].ToBytes());
                }
                Assert.Equal(t.expected, Msg.AreAllMsgDifferent(msgVec));
            }
        }

        [Fact]
        static void TestMultiVerify()
        {
            var tbl = new[] {
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
                    },
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "5656565656565656565656565656565656565656565656565656565656565656",
                        "abababababababababababababababababababababababababababababababab",
                    },
                    sigVec = new[]
                    {
                        "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
                        "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
                        "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
                    },
                    expected = true,
                },
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                    },
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "5656565656565656565656565656565656565656565656565656565656565656",
                    },
                    sigVec = new[]
                    {
                        "a70f1f1b4bd97d182ebb55d08be3f90b1dc232bb50b44e259381a642ef0bad3629ad3542f3e8ff6a84e451fc0b595e090fc4f0e860cfc5584715ef1b6cd717b9994378f7a51b815bbf5a0d95bc3402583ad2e95a229731e539906249a5e4355c",
                        "b758eb7e15c101f53be2214d2a6b65e8fe7053146dbe3c73c9fe9b5efecdf63ca06a4d5d938dbf18fe6600529c0011a7013f45ae012b02904d5c7c33316e935a0e084abead4f43f84383c52cd3b3f14024437e251a2a7c0d5147954022873a58",
                    },
                    expected = false,
                },
            };

            foreach (var v in tbl)
            {
                int n = v.pubVec.Length;
                PublicKey[] pubVec = new PublicKey[n];
                bool result = false;

                try
                {
                    for (int i = 0; i < n; i++)
                    {
                        pubVec[i].Deserialize(v.pubVec[i].ToBytes());
                    }

                    Msg[] msgVec = new Msg[n];
                    for (int i = 0; i < n; i++)
                    {
                        msgVec[i].Set(v.msgVec[i].ToBytes());
                    }

                    Signature[] sigVec = new Signature[n];
                    for (int i = 0; i < n; i++)
                    {
                        sigVec[i].Deserialize(v.sigVec[i].ToBytes());
                    }
                    result = BLS.MultiVerify(sigVec, pubVec, msgVec);
                }
                catch (Exception)
                {
                    // pass through
                }

                Assert.Equal(v.expected, result);
            }
        }
    }
}
