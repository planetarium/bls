using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Planetarium.Cryptography.BLS12_381
{
    /// <summary>
    /// A message struct of BLS signature.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct Msg
    {
        private fixed byte v[BLS.MSG_SIZE];

        /// <summary>
        /// Sets a message from <see cref="byte"/> array.
        /// </summary>
        /// <param name="buf">A message to set.</param>
        /// <exception cref="ArgumentException">Thrown if given message array size is not
        /// <see cref="BLS.MSG_SIZE"/>.
        /// </exception>
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

        /// <summary>
        /// Gets a <see cref="byte"/> value in given index.
        /// </summary>
        /// <param name="i">a index to get.</param>
        /// <returns>Returns a <see cref="byte"/> value of given index.</returns>
        public byte Get(int i)
        {
            return v[i];
        }

        /// <inheritdoc cref="IEquatable{T}.GetHashCode()"/>
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

        /// <inheritdoc cref="IEquatable{T}.Equals(object)"/>
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

        /// <summary>
        /// Checks if any message is equal in message array.
        /// </summary>
        /// <param name="msgVec">A <see cref="Msg"/> array to check.</param>
        /// <returns>Returns <see langword="true"/> if given messages are unique, otherwise returns
        /// <see langword="false"/>.</returns>
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

        /// <summary>
        /// Returns a message as <see cref="byte"/> array.
        /// </summary>
        /// <returns></returns>
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
