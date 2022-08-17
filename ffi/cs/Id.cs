using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using bls.NativeImport;

namespace bls
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct Id
    {
        private fixed ulong v[BLS.ID_UNIT_SIZE];

        public byte[] Serialize()
        {
            ulong bufSize = (ulong)Native.Instance.blsGetFrByteSize();
            byte[] buf = new byte[bufSize];

            ulong n = Native.Instance.blsIdSerialize(buf, bufSize, ref this);

            if (n != bufSize)
            {
                throw new ArithmeticException("blsIdSerialize");
            }

            return buf;
        }

        public void Deserialize(byte[] buf)
        {
            ulong bufSize = (ulong)buf.Length;
            ulong n = Native.Instance.blsIdDeserialize(ref this, buf, bufSize);

            if (n == 0 || n != bufSize)
            {
                throw new ArithmeticException("blsIdDeserialize");
            }
        }

        public bool IsEqual(in Id rhs)
        {
            fixed(Id *l = &this)
            {
                fixed(Id *r = &rhs)
                {
                    return Native.Instance.blsIdIsEqual(l, r) != 0;
                }
            }
        }

        public void SetDecStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsIdSetDecStr(ref this, arr, (ulong)arr.Length) != 0)
            {
                throw new ArgumentException($"blsIdSetDecStr: {s}");
            }
        }


        public void SetHexStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsIdSetHexStr(ref this, arr, (ulong)s.Length) != 0) {
                throw new ArgumentException("blsIdSetDecStr:" + s);
            }
        }

        public void SetInt(int x)
        {
            Native.Instance.blsIdSetInt(ref this, x);
        }

        public string GetDecStr()
        {
            byte[] arr = new byte[1024];

            ulong size = Native.Instance.blsIdGetDecStr(arr, (ulong)arr.Length, ref this);
            if (size == 0)
            {
                throw new ArgumentException("blsIdGetDecStr");
            }

            arr = arr.Take((int)size).ToArray();
            return Encoding.UTF8.GetString(arr);
        }

        public string GetHexStr()
        {
            byte[] arr = new byte[1024];

            ulong size = Native.Instance.blsIdGetHexStr(arr, (ulong)arr.Length, ref this);
            if (size == 0)
            {
                throw new ArgumentException("blsIdGetDecStr");
            }

            arr = arr.Take((int)size).ToArray();
            return Encoding.UTF8.GetString(arr);
        }
    }
}
