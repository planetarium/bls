using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace bls
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct Msg
    {
        private fixed byte v[BLS.MSG_SIZE];

        public void Set(byte[] buf)
        {
            if (buf.Length != BLS.MSG_SIZE)
            {
                throw new ArgumentException("bad buf size");
            }

            for (int i = 0; i < BLS.MSG_SIZE; i++)
            {
                v[i] = buf[i];
            }
        }

        public byte Get(int i)
        {
            return v[i];
        }

        public override int GetHashCode()
        {
            // FNV-1a 32-bit hash
            uint v = 2166136261;
            for (int i = 0; i < BLS.MSG_SIZE; i++)
            {
                v ^= Get(i);
                v *= 16777619;
            }

            return (int)v;
        }

        public override bool Equals(object obj)
        {
            if (!(obj is Msg)) return false;
            var rhs = (Msg)obj;
            for (int i = 0; i < BLS.MSG_SIZE; i++)
            {
                if (Get(i) != rhs.Get(i)) return false;
            }

            return true;
        }

        public static bool AreAllMsgDifferent(in Msg[] msgVec)
        {
            var set = new HashSet<Msg>();
            foreach (var msg in msgVec)
            {
                if (!set.Add(msg))
                {
                    return false;
                }
            }

            return true;
        }

        public byte[] ToByteArray()
        {
            byte[] buf = new byte[BLS.MSG_SIZE];

            for(int i = 0; i < BLS.MSG_SIZE; i++)
            {
                buf[i] = v[i];
            }

            return buf;
        }
    }
}
