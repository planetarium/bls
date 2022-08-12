using mcl;

// ReSharper disable InconsistentNaming

namespace bls.NativeImport
{
    public abstract partial class Native
    {
        private const string dllName = BLS.FP_UNIT_SIZE == 6 ? "bls384_256" : "bls256";

        public static readonly Native Instance;

        static Native()
        {
            Instance = Auto.Import<Native>(dllName, "1.10", true);
            Instance.blsInit(BLS.BLS12_381, BLS.COMPILED_TIME_VAR);
        }

        public Native()
        {
        }
    }
}
