using System;

namespace Planetarium.Cryptography.bls.NativeImport
{
    public abstract partial class Native
    {
        private const string dllName = BLS.FP_UNIT_SIZE == 6 ? "bls384_256" : "bls256";

        public static readonly Native Instance;

        static Native()
        {
            Instance = Auto.Import<Native>(dllName, "1.10", true);

            if (!BLS.isETH)
            {
                throw new PlatformNotSupportedException("BLS is not set in ethereum mode.");
            }
            if (!Environment.Is64BitProcess) {
                throw new PlatformNotSupportedException("not 64-bit system");
            }
            int err = Instance.blsInit(BLS.BLS12_381, BLS.COMPILED_TIME_VAR);
            if (err != 0)
            {
                throw new ArgumentException("blsInit");
            }
        }

        public Native()
        {
        }
    }
}
