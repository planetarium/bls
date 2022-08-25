using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Planetarium.Cryptography.BLS12_381.NativeImport;

namespace Planetarium.Cryptography.BLS12_381
{
    /// <summary>
    /// An Identifier struct of a BLS signature.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct Id
    {
        private fixed ulong v[BLS.ID_UNIT_SIZE];

        /// <summary>
        /// Serializes the Identifier to a <see cref="byte"/> array.
        /// </summary>
        /// <returns>Returns a <see cref="byte"/> array representation of this Identifier.</returns>
        /// <exception cref="ArithmeticException">Thrown if serialization is failed.</exception>
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

        /// <summary>
        /// Deserializes the Identifier from a <see cref="byte"/> array.
        /// </summary>
        /// <param name="buf">A <see cref="byte"/> array representation of an Identifier.</param>
        /// <exception cref="ArithmeticException">Thrown if deserialization is failed.</exception>
        public void Deserialize(byte[] buf)
        {
            ulong bufSize = (ulong)buf.Length;
            ulong n = Native.Instance.blsIdDeserialize(ref this, buf, bufSize);

            if (n == 0 || n != bufSize)
            {
                throw new ArithmeticException("blsIdDeserialize");
            }
        }

        /// <summary>
        /// Checks if the Identifier is equal to another Identifier.
        /// </summary>
        /// <param name="rhs">an <see cref="Id"/> to check.</param>
        /// <returns>Returns <see langword="true"/> if both are equal, otherwise returns
        /// <see langword="false"/>.
        /// </returns>
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

        /// <summary>
        /// Sets an Identifier with an decimal value string.
        /// </summary>
        /// <param name="s">a string contains decimal value to set.</param>
        /// <exception cref="ArgumentException">Thrown if setting attempt is failed.
        /// </exception>
        public void SetDecStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsIdSetDecStr(ref this, arr, (ulong)arr.Length) != 0)
            {
                throw new ArgumentException($"blsIdSetDecStr: {s}");
            }
        }


        /// <summary>
        /// Sets an Identifier with an hex string.
        /// </summary>
        /// <param name="s">a string contains hexadecimal value to set. </param>
        /// <exception cref="ArgumentException">Thrown if setting attempt is failed.</exception>
        public void SetHexStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsIdSetHexStr(ref this, arr, (ulong)s.Length) != 0) {
                throw new ArgumentException("blsIdSetDecStr:" + s);
            }
        }

        /// <summary>
        /// Sets an Identifier with a decimal value.
        /// </summary>
        /// <param name="x">a <see cref="int"/> representation of an Identifier.</param>
        public void SetInt(int x)
        {
            Native.Instance.blsIdSetInt(ref this, x);
        }

        /// <summary>
        /// Gets an decimal value string of an Identifier.
        /// </summary>
        /// <returns>Returns a decimal value string of Identifier.</returns>
        /// <exception cref="ArgumentException">Thrown if getting decimal string is failed.
        /// </exception>
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

        /// <summary>
        /// Gets an hexadecimal value string of an Identifier.
        /// </summary>
        /// <returns>Returns a hexadecimal value string of Identifier.</returns>
        /// <exception cref="ArgumentException">Thrown if getting hexadecimal string is failed.
        /// </exception>
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
